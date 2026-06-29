from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Any
from datetime import datetime
import secrets

app = FastAPI(title="ITEK VAPT Tool API", version="1.0")

# CORS setup for direct browser-to-backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------- #
# Data Schemas (Pydantic Models)
# ---------------------------------------------------------------- #

class UserSignup(BaseModel):
    email: str
    username: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# ---------------------------------------------------------------- #
# In-Memory Database Simulation
# ---------------------------------------------------------------- #
# Keyed by email -> stores profile properties and localized project lists[cite: 1].
users_db = {
    "admin@itek.io": {
        "username": "admin",
        "password": "password123",
        "company": "ITEK Offensive Security Labs",
        "role": "Administrator",
        "bio": "Offensive security team lead & core automated fuzzing engine maintainer.",
        "projects": [
            {"name": "core-api-service", "visibility": "Private", "critical": 2, "high": 5, "updated": "2 hours ago"},
            {"name": "legacy-auth-gateway", "visibility": "Private", "critical": 7, "high": 12, "updated": "Yesterday"},
            {"name": "public-documentation", "visibility": "Public", "critical": 0, "high": 0, "updated": "3 days ago"}
        ]
    }
}

# ---------------------------------------------------------------- #
# API Routing Contexts
# ---------------------------------------------------------------- #

@app.get("/")
async def get_index():
    return {"status": "API is online"}

@app.post("/signup")
async def get_signup(credentials: UserSignup):
    email = credentials.email.strip()
    username = credentials.username.strip().lower()
    
    # 1. Enforce unique emails[cite: 1]
    if email in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="An account with this email already exists"
        )
        
    # 2. Enforce unique usernames across the ecosystem[cite: 1]
    if any(u.get("username") == username for u in users_db.values()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This username is already taken"
        )
    
    # Create the user namespace profile with empty baseline lists[cite: 1]
    users_db[email] = {
        "username": username,
        "password": credentials.password,
        "company": "Independent Security Team",
        "role": "Pentester",
        "bio": "Security analyst executing target infrastructure verification assessments.",
        "projects": [
            {"name": "default-scan-target", "visibility": "Private", "critical": 0, "high": 0, "updated": "Just now"}
        ]
    }
    return {"message": "Registration successful"}

@app.post("/login")
async def get_login(credentials: UserLogin):
    user_record = users_db.get(credentials.email.strip())
    
    if not user_record or user_record["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid email or password"
        )
    
    return {"message": "Login successful", "username": user_record["username"]}

@app.get("/{username}")
async def get_user(username: str):
    target = username.strip().lower()
    
    # Scoped identification lookup loop[cite: 1]
    profile = next((u for u in users_db.values() if u["username"] == target), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User profile workspace not found")
    
    return {
        "username": profile["username"],
        "company": profile["company"],
        "role": profile["role"],
        "bio": profile["bio"],
        "projects": profile["projects"]
    }

@app.get("/{username}/{project}")
async def get_project(username: str, project: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    # Gate 1: Enforce strict user verification boundary[cite: 1]
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Workspace operator context not found")
        
    # Gate 2: Pull project strictly from within that verified container[cite: 1]
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Project profile mismatch under this user context")
        
    return {
        "project_info": proj, 
        "scope_rules": [f"*.{proj['name']}.itek.internal"], 
        "engine_status": "Idle"
    }

# Remaining functional VAPT route placeholders[cite: 1]
@app.get("/{username}/{project}/vault")
async def get_project_vault(username: str, project: str): pass

@app.get("/{username}/{project}/reports")
async def get_project_reports(username: str, project: str): pass

@app.get("/{username}/{project}/{scan}")
async def get_scan_settings(username: str, project: str, scan: str): pass