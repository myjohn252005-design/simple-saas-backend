"""
YouTube Timestamp SaaS – Production Backend
Tech Stack:
- FastAPI
- PostgreSQL (SQLAlchemy)
- JWT Auth
- API Keys
- Rate Limiting
- yt-dlp
- Whisper
- Background Queue
"""

import os
import uuid
import time
import subprocess
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError

# -------------------------
# CONFIG
# -------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/timestamp")
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

UPLOAD_DIR = "downloads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------
# APP INIT
# -------------------------
app = FastAPI(
    title="YouTube Timestamp SaaS",
    version="1.0.0",
    description="AI-powered timestamp generator for YouTube creators"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -------------------------
# DATABASE
# -------------------------
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


# -------------------------
# MODELS
# -------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    request_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String)
    key = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class RequestLog(Base):
    __tablename__ = "request_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String)
    endpoint = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# -------------------------
# SCHEMAS
# -------------------------
class SignupSchema(BaseModel):
    email: str
    password: str


class GenerateSchema(BaseModel):
    youtube_url: str
    prompt: Optional[str] = "Generate timestamps"


# -------------------------
# UTILS
# -------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)


def create_token(user_id: str):
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.id == payload["sub"]).first()
        if not user:
            raise HTTPException(status_code=401)
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------------
# RATE LIMIT
# -------------------------
MAX_REQUESTS = 10


def rate_limit(user: User, db: Session):
    if user.request_count >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    user.request_count += 1
    db.commit()


# -------------------------
# WHISPER + YT-DLP
# -------------------------
def process_video(youtube_url: str):
    filename = f"{UPLOAD_DIR}/{uuid.uuid4()}.mp3"

    subprocess.run([
        "yt-dlp",
        "-x", "--audio-format", "mp3",
        youtube_url,
        "-o", filename
    ], check=True)

    result = subprocess.run([
        "whisper",
        filename,
        "--model", "base",
        "--language", "en"
    ], capture_output=True, text=True)

    return result.stdout


# -------------------------
# ROUTES
# -------------------------
@app.get("/")
def root():
    return {"message": "Backend Live"}


@app.post("/signup")
def signup(data: SignupSchema, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email exists")

    user = User(
        email=data.email,
        password=hash_password(data.password)
    )
    db.add(user)
    db.commit()
    return {"message": "User created"}


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(user.id)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/generate")
def generate(
    data: GenerateSchema,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rate_limit(user, db)

    background_tasks.add_task(process_video, data.youtube_url)

    log = RequestLog(user_id=user.id, endpoint="/generate")
    db.add(log)
    db.commit()

    return {
        "status": "queued",
        "message": "Video queued for processing"
    }


@app.post("/create-api-key")
def create_api_key(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key = f"yt_{uuid.uuid4().hex}"
    api_key = APIKey(user_id=user.id, key=key)
    db.add(api_key)
    db.commit()
    return {"api_key": key}


@app.get("/billing/stripe")
def stripe_placeholder():
    return {"message": "Stripe integration placeholder"}
