from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from typing import List, Optional, Any

app = FastAPI(title="ITEK VAPT Tool API", version="1.0")

# CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models[cite: 1]
class UserSignup(BaseModel):
    email: str
    username: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# In-memory storage mapping: email -> {"password": password, "username": username}[cite: 1]
users_db = {}

# Routing[cite: 1]
@app.get("/")
async def get_index():
    return {"status": "API is online"}

@app.post("/login")
async def get_login(credentials: UserLogin):
    email = credentials.email
    password = credentials.password

    user_record = users_db.get(email)
    if not user_record or user_record["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid email or password"
        )
    
    return {"message": "Login successful", "user": user_record["username"]}

@app.post("/signup")
async def get_signup(credentials: UserSignup):
    email = credentials.email
    username = credentials.username.strip().lower()
    password = credentials.password

    # Check if email exists[cite: 1]
    if email in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="An account with this email already exists"
        )
    
    # Check if username is already taken by anyone else[cite: 1]
    if any(user.get("username") == username for user in users_db.values()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This username is already taken"
        )
    
    # Save composite user dictionary[cite: 1]
    users_db[email] = {
        "password": password,
        "username": username
    }
    return {"message": "Registration successful"}

@app.get("/{username}")
async def get_user(username: str):
    pass

@app.get("/{username}/{project}")
async def get_project(username: str, project: str):
    pass

@app.get("/{username}/{project}/vault")
async def get_project_vault(username: str, project: str):
    pass

@app.get("/{username}/{project}/reports")
async def get_project_reports(username: str, project: str):
    pass

@app.get("/{username}/{project}/{scan}")
async def get_scan_settings(username: str, project: str, scan: str):
    pass