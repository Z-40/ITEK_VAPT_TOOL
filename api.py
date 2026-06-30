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

class DomainAdd(BaseModel):
    domain_name: str

# ---------------------------------------------------------------- #
# In-Memory Database Simulation
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
                "engine_status": "Idle",
                "domains": [
                    {"name": "api.itek.io", "swagger_file_id": None}
                ],
                "vault": [
                    {"id": "v-7d2a", "name": "nmap_discovery_subnet.xml", "size": "42.8 KB", "date": "2 hours ago"},
                    {"id": "v-9c1f", "name": "prod_jwt_public_key.pem", "size": "1.6 KB", "date": "Yesterday"}
                ]
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
                "engine_status": "Idle",
                "domains": [],
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
        "engine_status": proj.get("engine_status", "Idle"),
        "domains": proj.get("domains", []),
        "vault": proj.get("vault", [])
    }

# ---------------------------------------------------------------- #
# Scan Execution Infrastructure
# ---------------------------------------------------------------- #

@app.post("/{username}/{project}/scan")
async def launch_project_scan(username: str, project: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User namespace mismatch")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Target tracking block missing")
        
    proj["engine_status"] = "Scanning"
    return {"message": "Offensive orchestration engine pipeline active.", "engine_status": "Scanning"}

@app.post("/{username}/{project}/scan/stop")
async def stop_project_scan(username: str, project: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User namespace mismatch")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Target tracking block missing")
        
    proj["engine_status"] = "Idle"
    return {"message": "Pipeline execution cleanly severed.", "engine_status": "Idle"}

# ---------------------------------------------------------------- #
# Domain & Target Matrix Operations
# ---------------------------------------------------------------- #

@app.post("/{username}/{project}/domains")
async def add_project_domain(username: str, project: str, payload: DomainAdd):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User container missing")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Target scope missing")
        
    if "domains" not in proj:
        proj["domains"] = []
        
    domain_clean = payload.domain_name.strip().lower()
    if any(d["name"] == domain_clean for d in proj["domains"]):
        raise HTTPException(status_code=400, detail="Domain is already registered in this project.")
        
    new_domain = {"name": domain_clean, "swagger_file_id": None}
    proj["domains"].append(new_domain)
    return {"message": "Domain mapped to project scope.", "domain": new_domain}

@app.post("/{username}/{project}/domains/{domain_name}/swagger")
async def upload_domain_swagger(username: str, project: str, domain_name: str, file: UploadFile = File(...)):
    if not file.filename.lower().endswith('.json'):
        raise HTTPException(status_code=400, detail="Invalid format. Swagger/OpenAPI schemas must be JSON.")

    target_user = username.strip().lower()
    target_project = project.strip().lower()
    target_domain = domain_name.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile:
        raise HTTPException(status_code=404, detail="User container missing")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Target scope missing")
        
    domain_record = next((d for d in proj.get("domains", []) if d["name"] == target_domain), None)
    if not domain_record:
        raise HTTPException(status_code=404, detail="Domain not mapped in this project.")

    if "vault" not in proj:
        proj["vault"] = []

    custom_filename = f"{target_domain}_{file.filename}"
        
    if any(f["name"] == custom_filename for f in proj["vault"]):
        raise HTTPException(status_code=400, detail="A schema with this name already exists for this domain.")

    project_disk_path = STORAGE_DIR / target_user / target_project
    project_disk_path.mkdir(parents=True, exist_ok=True)
    
    content = await file.read()
    raw_bytes = len(content)
    size_str = f"{round(raw_bytes / (1024 * 1024), 1)} MB" if raw_bytes >= 1024 * 1024 else f"{round(raw_bytes / 1024, 1)} KB"
        
    file_id = f"v-{secrets.token_hex(2)}"
    safe_filepath = project_disk_path / f"{file_id}_{custom_filename}"
    
    try:
        with open(safe_filepath, "wb") as storage_buffer:
            storage_buffer.write(content)
    except Exception:
        raise HTTPException(status_code=500, detail="Server write block exception.")
        
    new_asset = {
        "id": file_id,
        "name": custom_filename,
        "size": size_str,
        "date": "Just now"
    }
    
    proj["vault"].append(new_asset)
    domain_record["swagger_file_id"] = file_id
    
    return {"message": "Swagger schema attached and secured in vault.", "asset": new_asset, "domain": domain_record}

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
        raise HTTPException(status_code=404, detail="Project context error")
        
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
        
    project_disk_path = STORAGE_DIR / target_user / target_project
    project_disk_path.mkdir(parents=True, exist_ok=True)
    
    content = await file.read()
    raw_bytes = len(content)
    size_str = f"{round(raw_bytes / (1024 * 1024), 1)} MB" if raw_bytes >= 1024 * 1024 else f"{round(raw_bytes / 1024, 1)} KB"
        
    file_id = f"v-{secrets.token_hex(2)}"
    target_filepath = project_disk_path / f"{file_id}_{file.filename}"
    
    try:
        with open(target_filepath, "wb") as storage_buffer:
            storage_buffer.write(content)
    except Exception:
        raise HTTPException(status_code=500, detail="Server block write exception.")
        
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
        raise HTTPException(status_code=404, detail="Physical binary file missing from disk.")
        
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
    
    if "domains" in proj:
        for d in proj["domains"]:
            if d.get("swagger_file_id") == file_id:
                d["swagger_file_id"] = None

    return {"message": "Asset safely purged from vault inventory."}