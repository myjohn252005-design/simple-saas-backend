import os
import uuid
import subprocess
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError

# ---------------- CONFIG ----------------

# Safely load Database URL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecret123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

UPLOAD_DIR = "downloads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------- APP SETUP ----------------

app = FastAPI(
    title="YouTube Timestamp SaaS"
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

# ---------------- DATABASE MODELS ----------------

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Job(Base):
    __tablename__ = "jobs"
    id = Column(String, primary_key=True)
    status = Column(String, default="queued")
    result = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ---------------- SCHEMAS ----------------

class Signup(BaseModel):
    email: str
    password: str

class Generate(BaseModel):
    youtube_url: str

# ---------------- UTILS ----------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(p):
    return pwd_context.hash(p)

def verify(p, h):
    return pwd_context.verify(p, h)

def create_token(uid):
    return jwt.encode(
        {"sub": uid, "exp": datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_MINUTES)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

def get_user(token=Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return db.query(User).filter(User.id == data["sub"]).first()
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------------- BACKGROUND JOB ----------------

def run_job(job_id: str, youtube_url: str):
    db = SessionLocal()
    job = db.query(Job).filter(Job.id == job_id).first()
    job.status = "processing"
    db.commit()

    try:
        audio = f"{UPLOAD_DIR}/{uuid.uuid4()}.mp3"

        subprocess.run(
            ["yt-dlp", "-x", "--audio-format", "mp3", youtube_url, "-o", audio],
            check=True
        )

        subprocess.run(
            ["whisper", audio, "--model", "base", "--output_format", "txt"],
            check=True
        )

        txt_file = audio.replace(".mp3", ".txt")
        with open(txt_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        timestamps = []
        minute = 0
        for i in range(0, len(lines), 5):
            text = lines[i].strip()
            timestamps.append(f"{minute:02d}:00 {text[:60]}")
            minute += 1

        job.status = "completed"
        job.result = "\n".join(timestamps)
        db.commit()

    except Exception as e:
        job.status = "failed"
        job.result = str(e)
        db.commit()

    finally:
        db.close()

# ---------------- API ROUTES ----------------

@app.get("/")
def home():
    return {"message": "Backend Live"}

@app.post("/signup")
def signup(data: Signup, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    user = User(email=data.email, password=hash_password(data.password))
    db.add(user)
    db.commit()
    return {"message": "User created"}

@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify(form.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_token(user.id), "token_type": "bearer"}

@app.post("/generate")
def generate(
    data: Generate,
    background_tasks: BackgroundTasks,
    user=Depends(get_user),
    db: Session = Depends(get_db)
):
    job_id = str(uuid.uuid4())
    job = Job(id=job_id)
    db.add(job)
    db.commit()

    background_tasks.add_task(run_job, job_id, data.youtube_url)
    return {"status": "queued", "job_id": job_id}

@app.get("/status/{job_id}")
def check_status(job_id: str, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"status": job.status, "result": job.result}
