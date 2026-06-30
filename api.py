from fastapi import FastAPI, HTTPException, status, Header, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Any
from pathlib import Path
import secrets
import os

app = FastAPI(title="ITEK VAPT Tool API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base folder layer for permanent server binary isolation
STORAGE_DIR = Path("vault_storage")

# ---------------------------------------------------------------- #
# Data Schemas 
# ---------------------------------------------------------------- #

class UserSignup(BaseModel):
    email: str
    username: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# ---------------------------------------------------------------- #
# In-Memory Database Simulation (Isolated Workspace Nodes)
# ---------------------------------------------------------------- #
users_db = {
    "admin@itek.io": {
        "username": "admin",
        "password": "password123",
        "company": "ITEK Offensive Security Labs",
        "role": "Administrator",
        "bio": "Offensive security team lead & core automated fuzzing engine maintainer.",
        "projects": [
            {
                "name": "core-api-service", 
                "visibility": "Private", 
                "critical": 2, 
                "high": 5, 
                "updated": "2 hours ago",
                "vault": [
                    {"id": "v-7d2a", "name": "nmap_discovery_subnet.xml", "size": "42.8 KB", "date": "2 hours ago"},
                    {"id": "v-9c1f", "name": "prod_jwt_public_key.pem", "size": "1.6 KB", "date": "Yesterday"}
                ]
            },
            {
                "name": "legacy-auth-gateway", 
                "visibility": "Private", 
                "critical": 7, 
                "high": 12, 
                "updated": "Yesterday",
                "vault": [
                    {"id": "v-1a4b", "name": "fuzz_wordlist_backdoor.txt", "size": "1.2 MB", "date": "2 days ago"}
                ]
            },
            {
                "name": "public-documentation", 
                "visibility": "Public", 
                "critical": 0, 
                "high": 0, 
                "updated": "3 days ago",
                "vault": []
            }
        ]
    }
}

# ---------------------------------------------------------------- #
# Core Routing Framework
# ---------------------------------------------------------------- #

@app.get("/")
async def get_index():
    return {"status": "API is online"}

@app.post("/signup")
async def get_signup(credentials: UserSignup):
    email = credentials.email.strip()
    username = credentials.username.strip().lower()
    
    if email in users_db:
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    if any(u.get("username") == username for u in users_db.values()):
        raise HTTPException(status_code=400, detail="This username is already taken")
    
    users_db[email] = {
        "username": username,
        "password": credentials.password,
        "company": "Independent Security Team",
        "role": "Pentester",
        "bio": "Security analyst executing target infrastructure verification assessments.",
        "projects": [
            {
                "name": "default-scan-target", 
                "visibility": "Private", 
                "critical": 0, 
                "high": 0, 
                "updated": "Just now",
                "vault": []
            }
        ]
    }
    return {"message": "Registration successful"}

@app.post("/login")
async def get_login(credentials: UserLogin):
    user_record = users_db.get(credentials.email.strip())
    if not user_record or user_record["password"] != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"message": "Login successful", "username": user_record["username"]}

@app.get("/{username}")
async def get_user(username: str):
    target = username.strip().lower()
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
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Workspace operator context not found")
        
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Project profile mismatch under this user context")
        
    return {
        "project_info": proj, 
        "scope_rules": [f"*.{proj['name']}.itek.internal"], 
        "engine_status": "Idle",
        "vault": proj.get("vault", [])
    }

# ---------------------------------------------------------------- #
# Secure Vault Storage Operations
# ---------------------------------------------------------------- #

@app.get("/{username}/{project}/vault")
async def get_project_vault(username: str, project: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User target not found")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Project context matching error")
        
    return {"vault": proj.get("vault", [])}

@app.post("/{username}/{project}/vault/upload")
async def upload_to_vault(username: str, project: str, file: UploadFile = File(...)):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User container missing")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Target scope missing")
    
    if "vault" not in proj:
        proj["vault"] = []
        
    if any(f["name"] == file.filename for f in proj["vault"]):
        raise HTTPException(status_code=400, detail="Asset matching this filename already exists inside Vault")
        
    # Enforce automated multi-tenant folder track creation
    project_disk_path = STORAGE_DIR / target_user / target_project
    project_disk_path.mkdir(parents=True, exist_ok=True)
    
    content = await file.read()
    raw_bytes = len(content)
    if raw_bytes >= 1024 * 1024:
        size_str = f"{round(raw_bytes / (1024 * 1024), 1)} MB"
    else:
        size_str = f"{round(raw_bytes / 1024, 1)} KB" if raw_bytes > 0 else "0 KB"
        
    file_id = f"v-{secrets.token_hex(2)}"
    
    # Prefix identifier to prevent server-side path traversal and name conflicts
    safe_filename = f"{file_id}_{file.filename}"
    target_filepath = project_disk_path / safe_filename
    
    try:
        with open(target_filepath, "wb") as storage_buffer:
            storage_buffer.write(content)
    except Exception:
        raise HTTPException(status_code=500, detail="Server block write exception during file buffer synchronization")
        
    new_asset = {
        "id": file_id,
        "name": file.filename,
        "size": size_str,
        "date": "Just now"
    }
    
    proj["vault"].append(new_asset)
    return {"message": "Payload securely isolated and buffered in project vault", "asset": new_asset}

@app.get("/{username}/{project}/vault/download/{file_id}")
async def download_from_vault(username: str, project: str, file_id: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User target space error")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Project context error")
        
    file_record = next((f for f in proj.get("vault", []) if f["id"] == file_id), None)
    if not file_record:
        raise HTTPException(status_code=404, detail="Target file record identifier not located in scope")
        
    safe_filename = f"{file_id}_{file_record['name']}"
    target_filepath = STORAGE_DIR / target_user / target_project / safe_filename
    
    if not target_filepath.exists():
        raise HTTPException(status_code=404, detail="Physical binary file missing from server disk storage")
        
    # FileResponse returns original name, concealing internal trackers from browser downloads
    return FileResponse(
        path=target_filepath, 
        filename=file_record['name'], 
        media_type="application/octet-stream"
    )

@app.delete("/{username}/{project}/vault/{file_id}")
async def delete_from_vault(username: str, project: str, file_id: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User target space error")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Project context error")
        
    file_record = next((f for f in proj.get("vault", []) if f["id"] == file_id), None)
    if not file_record:
        raise HTTPException(status_code=404, detail="Target file record identifier not located in scope")
        
    safe_filename = f"{file_id}_{file_record['name']}"
    target_filepath = STORAGE_DIR / target_user / target_project / safe_filename
    
    if target_filepath.exists():
        os.remove(target_filepath)
        
    proj["vault"] = [f for f in proj.get("vault", []) if f["id"] != file_id]
    return {"message": "Asset safely purged from vault inventory mapping and disk tracking nodes"}

@app.get("/{username}/{project}/reports")
async def get_project_reports(username: str, project: str): pass

@app.get("/{username}/{project}/{scan}")
async def get_scan_settings(username: str, project: str, scan: str): pass