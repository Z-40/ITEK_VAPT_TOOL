from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import shutil
import json
import os
import db

# Custom Pipeline Modules (Stubs for Testing)
try: from features.recon.enumerate import enumerate as run_enum
except ImportError: 
    def run_enum(domain: str): return [f"api.{domain}", domain]

try: from features.recon.dns_scan import scan_dns
except ImportError: 
    def scan_dns(data: list): return {"status": "mock", "module": "dns"}

try: from features.recon.port_scan import scan_ports
except ImportError: 
    def scan_ports(data: list): return {"status": "mock", "module": "ports"}


app = FastAPI(title="ITEK VAPT Orchestrator (Pure Filesystem Mode)", version="4.0")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

STORAGE_DIR = Path("vault_storage")
STORAGE_DIR.mkdir(exist_ok=True)

class UserSignup(BaseModel): email: str; username: str; password: str
class UserLogin(BaseModel): email: str; password: str
class DomainAdd(BaseModel): domain: str

# ---------------------------------------------------------------- #
# BACKGROUND TASK (Filesystem Lock Engine)
# ---------------------------------------------------------------- #
def run_vapt_pipeline_worker(username: str, project_name: str, domain: str):
    domain_dir = STORAGE_DIR / username.lower() / project_name.lower() / domain.lower()
    lock_file = domain_dir / ".lock-pipeline"
    
    try:
        domain_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_file, "w") as lf: lf.write("running")

        # Clear historical run results (keep the lock and spec uploads)
        for item in domain_dir.iterdir():
            if item.name in [".lock-pipeline", "openapi_spec.json"]: continue
            if item.is_file(): item.unlink()
            elif item.is_dir(): shutil.rmtree(item, ignore_errors=True)

        # Simulation: Modules executing and dropping files
        with open(domain_dir / "subdomains.json", "w") as f:
            json.dump({"target": domain, "subdomains": run_enum(domain)}, f)
            
        with open(domain_dir / "findings_report.json", "w") as f:
            json.dump({"vulnerabilities": [], "status": "Filesystem Engine Success"}, f, indent=4)

    except Exception as e:
        with open(domain_dir / "execution_error.log", "w") as f: f.write(str(e))
    finally:
        if lock_file.exists(): lock_file.unlink()

# ---------------------------------------------------------------- #
# USER SPACE AND AUTH
# ---------------------------------------------------------------- #
@app.post("/signup")
async def get_signup(credentials: UserSignup):
    username_clean = credentials.username.strip().lower()
    try:
        db.create_user(credentials.email.strip(), username_clean, credentials.password)
        (STORAGE_DIR / username_clean / "default-workspace").mkdir(parents=True, exist_ok=True)
    except ValueError as e: raise HTTPException(status_code=400, detail=str(e))
    return {"message": "Success"}

@app.post("/login")
async def get_login(credentials: UserLogin):
    user = db.authenticate_user(credentials.email.strip(), credentials.password)
    if not user: raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Success", "username": user["username"]}

@app.get("/{username}")
async def get_user_profile(username: str):
    """Dynamically parses directory footprints to return active dashboard layout."""
    user_dir = STORAGE_DIR / username.lower().strip()
    if not user_dir.exists():
        user_dir.mkdir(parents=True, exist_ok=True)
        (user_dir / "default-workspace").mkdir(exist_ok=True)

    projects_list = []
    for proj_path in user_dir.iterdir():
        if proj_path.is_dir():
            domains_list = []
            for dom_path in proj_path.iterdir():
                if dom_path.is_dir(): domains_list.append({"name": dom_path.name})
            
            projects_list.append({
                "name": proj_path.name,
                "visibility": "Private",
                "domains": domains_list
            })
    return {"username": username, "projects": projects_list}

# ---------------------------------------------------------------- #
# FILESYSTEM RESOURCE MANAGEMENT
# ---------------------------------------------------------------- #
@app.post("/{username}/projects/add")
async def add_project(username: str, payload: BaseModel):
    # Added dynamic project root creation
    data = payload.dict()
    project_name = data.get("name", "").strip().lower()
    if not project_name: raise HTTPException(status_code=400)
    (STORAGE_DIR / username.lower() / project_name).mkdir(parents=True, exist_ok=True)
    return {"message": "Project space allocated"}

@app.delete("/{username}/projects/{project}/remove")
async def remove_project(username: str, project: str):
    project_dir = STORAGE_DIR / username.lower() / project.lower()
    if project_dir.exists(): shutil.rmtree(project_dir, ignore_errors=True)
    return {"message": "Project space wiped"}

@app.post("/{username}/{project}/domains/add")
async def add_domain(username: str, project: str, payload: DomainAdd):
    target_dir = STORAGE_DIR / username.lower() / project.lower() / payload.domain.lower().strip()
    target_dir.mkdir(parents=True, exist_ok=True)
    return {"message": "Domain space allocated"}

@app.delete("/{username}/{project}/domains/{domain}/remove")
async def remove_domain(username: str, project: str, domain: str, force: bool = False):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    lock_file = domain_dir / ".lock-pipeline"
    
    if lock_file.exists() and not force:
        raise HTTPException(status_code=409, detail="Pipeline actively processing. Force required.")

    if domain_dir.exists(): shutil.rmtree(domain_dir, ignore_errors=True)
    return {"message": "Wiped structural space completely"}

# ---------------------------------------------------------------- #
# PIPELINE CONTROL & ARTIFACTS
# ---------------------------------------------------------------- #
@app.post("/{username}/{project}/{domain}/pipeline/start")
async def start_pipeline(username: str, project: str, domain: str, bg: BackgroundTasks):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    if not domain_dir.exists(): raise HTTPException(status_code=404, detail="Workspace not found.")
    if (domain_dir / ".lock-pipeline").exists(): raise HTTPException(status_code=400, detail="Running.")
        
    bg.add_task(run_vapt_pipeline_worker, username, project, domain)
    return {"message": "Pipeline processing"}

@app.get("/{username}/{project}/{domain}/pipeline/status")
async def get_pipeline_status(username: str, project: str, domain: str):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    is_running = (domain_dir / ".lock-pipeline").exists()
    
    exact_state = "idle"
    if is_running: exact_state = "running"
    elif (domain_dir / "findings_report.json").exists(): exact_state = "completed"
    elif (domain_dir / "execution_error.log").exists(): exact_state = "failed"
        
    return {"running": is_running, "exact_state": exact_state}

@app.get("/{username}/{project}/{domain}/vault")
async def get_vault_files(username: str, project: str, domain: str):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    files = []
    if domain_dir.exists():
        for root, _, filenames in os.walk(domain_dir):
            for fname in filenames:
                if fname.startswith("."): continue # Skip lock files
                full_path = Path(root) / fname
                rel_path = full_path.relative_to(domain_dir)
                files.append({"name": str(rel_path).replace("\\", "/"), "size": f"{full_path.stat().st_size} bytes"})
    return {"files": files}

@app.post("/{username}/{project}/{domain}/vault/upload")
async def upload_file(username: str, project: str, domain: str, file: UploadFile = File(...)):
    domain_dir = STORAGE_DIR / username.lower() / project.lower() / domain.lower()
    domain_dir.mkdir(parents=True, exist_ok=True)
    with open(domain_dir / file.filename, "wb") as f: shutil.copyfileobj(file.file, f)
    return {"message": "Uploaded"}

@app.get("/{username}/{project}/{domain}/vault/view/{filepath:path}")
async def view_file(username: str, project: str, domain: str, filepath: str):
    target = STORAGE_DIR / username.lower() / project.lower() / domain.lower() / filepath
    if not target.exists() or not target.is_file(): raise HTTPException(status_code=404)
    with open(target, "r", errors="ignore") as f: return {"content": f.read()}

@app.delete("/{username}/{project}/{domain}/vault/delete/{filepath:path}")
async def delete_file(username: str, project: str, domain: str, filepath: str):
    target = STORAGE_DIR / username.lower() / project.lower() / domain.lower() / filepath
    if target.exists(): target.unlink()
    return {"message": "Deleted"}