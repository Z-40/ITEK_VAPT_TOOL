from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from typing import List, Optional, Any

app = FastAPI(title="ITEK VAPT Tool API", version="1.0")

# CORS (Configured for local development talking to React) 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models[cite: 1]
class UserAuth(BaseModel):
    email: str
    password: str

# Temporary in-memory user tracking storage
users_db = {}

# Routing[cite: 1]
@app.get("/")
async def get_index():
    return {"status": "API is online"}

@app.post("/login")
async def get_login(credentials: UserAuth):
    email = credentials.email
    password = credentials.password

    # Validation check
    if email not in users_db or users_db[email] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid email or password"
        )
    
    return {"message": "Login successful", "user": email}

@app.post("/signup")
async def get_signup(credentials: UserAuth):
    email = credentials.email
    password = credentials.password

    # Check duplication
    if email in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="An account with this email already exists"
        )
    
    # Save user credentials simply
    users_db[email] = password
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