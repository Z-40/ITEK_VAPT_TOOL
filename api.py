from fastapi import FastAPI, HTTPException, status, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from pathlib import Path
import shutil
import json
import os

# --- Your Custom Pipeline Modules ---
try:
    from features.recon.enumerate import enumerate as run_enum
except ImportError:
    def run_enum(domain: str): return [f"api.{domain}", domain] # Fallback

try:
    from features.post_requests.post_requests import get_post_requests
except ImportError:
    def get_post_requests(filepath: str): return ["POST / HTTP/1.1\nHost: test"] # Fallback

app = FastAPI(title="ITEK VAPT Orchestrator", version="2.0")

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
class UserSignup(BaseModel): email: str; username: str; password: str
class UserLogin(BaseModel): email: str; password: str
class DomainAdd(BaseModel): domain: str

# ---------------------------------------------------------------- #
# In-Memory Database Simulation
# ---------------------------------------------------------------- #
users_db = {
    "admin@itek.io": {
        "username": "admin",
        "password": "password123",
        "company": "ITEK Offensive Security Labs",
        "role": "Administrator",
        "bio": "Offensive security team lead.",
        "projects": [
            {
                "name": "core-api-service", 
                "visibility": "Private", 
                "domains": [
                    {"name": "example.com"}
                ]
            }
        ]
    }
}

def find_profile_by_username(username: str):
    target = username.strip().lower()
    return next((u for u in users_db.values() if u["username"].lower() == target), None)

# ---------------------------------------------------------------- #
# Pipeline Execution Engine
# ---------------------------------------------------------------- #
def run_vapt_pipeline(username: str, project_name: str, domain: str):
    domain_dir = STORAGE_DIR / username.lower() / project_name.lower() / domain.lower()
    requests_dir = domain_dir / "parsed_requests"

    # 1. CLEANUP: Delete files from the first run (except swagger file)
    if domain_dir.exists():
        for item in domain_dir.iterdir():
            if item.name.startswith("openapi_spec"):
                continue
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
    
    domain_dir.mkdir(parents=True, exist_ok=True)
    requests_dir.mkdir(parents=True, exist_ok=True)

    # 2. ENUMERATION Phase
    try:
        subdomains = run_enum({"domain": domain})
        with open(domain_dir / "subdomains.json", "w") as f:
            json.dump({"target": domain, "subdomains": subdomains}, f, indent=4)
    except Exception as e:
        with open(domain_dir / "error_enum.log", "w") as f: f.write(str(e))

    # 3. NETWORK SCAN Phase (Placeholder)
    with open(domain_dir / "scan_metadata.json", "w") as f:
        json.dump({"status": "completed", "ports": "scanned"}, f)

    # 4. SWAGGER PARSING Phase
    swagger_files = list(domain_dir.glob("openapi_spec.*"))
    if swagger_files:
        try:
            post_requests = get_post_requests(str(swagger_files[0]))
            for i, req in enumerate(post_requests):
                with open(requests_dir / f"endpoint{i+1}_POST.txt", "w") as f:
                    f.write(req)
        except Exception as e:
            with open(domain_dir / "error_swagger.log", "w") as f: f.write(str(e))

    # 5. FINAL REPORT Phase
    with open(domain_dir / "findings_report.json", "w") as f:
        json.dump({"vulnerabilities": [], "status": "Finished"}, f, indent=4)


# ---------------------------------------------------------------- #
# Auth & Profile Routes
# ---------------------------------------------------------------- #
@app.post("/signup")
async def get_signup(credentials: UserSignup):
    email, username = credentials.email.strip(), credentials.username.strip().lower()
    if email in users_db or find_profile_by_username(username):
        raise HTTPException(status_code=400, detail="Account exists")
    users_db[email] = {
        "username": username, "password": credentials.password,
        "company": "Operator", "role": "Pentester", "bio": "",
        "projects": [{"name": "default-workspace", "visibility": "Private", "domains": []}]
    }
    return {"message": "Success"}

@app.post("/login")
async def get_login(credentials: UserLogin):
    user_record = users_db.get(credentials.email.strip())
    if not user_record or user_record["password"] != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Success", "username": user_record["username"]}

@app.get("/{username}")
async def get_user(username: str):
    profile = find_profile_by_username(username)
    if not profile: raise HTTPException(status_code=404)
    return {"username": profile["username"], "projects": profile["projects"]}

# ---------------------------------------------------------------- #
# Domain & Vault Routes
# ---------------------------------------------------------------- #
@app.post("/{username}/{project}/domains/add")
async def add_domain(username: str, project: str, payload: DomainAdd):
    profile = find_profile_by_username(username)
    proj = next((p for p in profile["projects"] if p["name"] == project), None)
    domain_name = payload.domain.lower()
    if not any(d["name"] == domain_name for d in proj["domains"]):
        proj["domains"].append({"name": domain_name})
    (STORAGE_DIR / username.lower() / project.lower() / domain_name).mkdir(parents=True, exist_ok=True)
    return {"message": "Domain added"}

@app.delete("/{username}/{project}/domains/{domain}/remove")
async def remove_domain(username: str, project: str, domain: str):
    profile = find_profile_by_username(username)
    proj = next((p for p in profile["projects"] if p["name"] == project), None)
    proj["domains"] = [d for d in proj["domains"] if d["name"] != domain]
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    if domain_dir.exists(): shutil.rmtree(domain_dir)
    return {"message": "Domain removed"}

@app.post("/{username}/{project}/{domain}/pipeline/start")
async def start_pipeline(username: str, project: str, domain: str, bg: BackgroundTasks):
    bg.add_task(run_vapt_pipeline, username, project, domain)
    return {"message": "Pipeline initiated"}

@app.get("/{username}/{project}/{domain}/vault")
async def get_vault_files(username: str, project: str, domain: str):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    files = []
    if domain_dir.exists():
        for root, _, filenames in os.walk(domain_dir):
            for fname in filenames:
                full_path = Path(root) / fname
                rel_path = full_path.relative_to(domain_dir)
                files.append({"name": str(rel_path), "size": f"{full_path.stat().st_size} bytes"})
    return {"files": files}

@app.post("/{username}/{project}/{domain}/vault/upload")
async def upload_file(username: str, project: str, domain: str, file: UploadFile = File(...)):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    domain_dir.mkdir(parents=True, exist_ok=True)
    with open(domain_dir / file.filename, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"message": "Uploaded"}

@app.get("/{username}/{project}/{domain}/vault/view/{filepath:path}")
async def view_file(username: str, project: str, domain: str, filepath: str):
    target = STORAGE_DIR / username.lower() / project.lower() / domain.lower() / filepath
    if not target.exists() or not target.is_file(): raise HTTPException(status_code=404)
    with open(target, "r", errors="ignore") as f:
        return {"content": f.read()}

@app.delete("/{username}/{project}/{domain}/vault/delete/{filepath:path}")
async def delete_file(username: str, project: str, domain: str, filepath: str):
    target = STORAGE_DIR / username.lower() / project.lower() / domain.lower() / filepath
    if target.exists(): target.unlink()
    return {"message": "Deleted"}