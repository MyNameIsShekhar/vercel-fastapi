from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import jwt

app = FastAPI()

MONGO_URI = 'mongodb://localhost:27017/'
MONGO_DB = 'user_database'
SECRET_KEY = 'your_secret_key_here'
ALGORITHM = 'HS256'

client = AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB]

class User(BaseModel):
    user_id: str
    password: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def get_user_by_id(user_id: str):
    return await db.users.find_one({"user_id": user_id})

async def create_user(user: User):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_in_db = UserInDB(user_id=user.user_id, hashed_password=hashed_password)
    await db.users.insert_one(user_in_db.dict())
    return user_in_db

async def authenticate_user(user_id: str, password: str):
    user = await get_user_by_id(user_id)
    if user and bcrypt.checkpw(password.encode('utf-8'), user['hashed_password'].encode('utf-8')):
        return UserInDB(**user)
    return None

def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = await get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return UserInDB(**user)

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.user_id})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register", response_model=Token)
async def register(user: User):
    existing_user = await get_user_by_id(user.user_id)
    if existing_user:
        raise HTTPException(status_code=400, detail="User ID already exists")
    user_in_db = await create_user(user)
    access_token = create_access_token(data={"sub": user_in_db.user_id})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user

@app.get("/")
async def root():
    return {"message": "Hello, World!"}
