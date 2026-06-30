import os
import json
import secrets
import traceback
import shutil
from pathlib import Path
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

# External parsing and recon dependencies
from features.recon.enumerate import enumerate as run_enumerate
from features.post_requests.post_requests import get_post_requests

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = Path("vault_storage")
users_db = {} 

def run_pipeline_worker(username: str, project_name: str):
    target_user = username.strip().lower()
    target_project = project_name.strip().lower()
    log_path = os.path.abspath("debug_worker.log")
    
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"\n=============================================\n")
        log.write(f"STARTING HARDENED ISOLATED PIPELINE: {target_user}/{target_project}\n")
        log.write(f"=============================================\n")
        
        profile = next((u for u in users_db.values() if u["username"] == target_user), None)
        if not profile:
            log.write("CRITICAL FAILED STATUS: User profile not matching context database.\n")
            return
            
        proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
        if not proj:
            log.write("CRITICAL FAILED STATUS: Project container missing from user scope mapping.\n")
            return
            
        project_disk_path = Path(os.path.abspath(STORAGE_DIR / target_user / target_project))
        
        try:
            project_disk_path.mkdir(parents=True, exist_ok=True)
            log.write(f"BASE VERIFIED PATH TRACK: {project_disk_path}\n")
        except Exception as directory_creation_fault:
            log.write(f"FATAL SYSTEM ERROR: Cannot build folder tracking sequence: {str(directory_creation_fault)}\n")
            log.write(traceback.format_exc())
            proj["engine_status"] = "Idle"
            return

        try:
            for domain_record in proj.get("domains", []):
                domain = domain_record["name"]
                log.write(f"\n--> ENGAGING DOMAIN PIPELINE: {domain}\n")
                
                # =================================================================
                # PHASE 1: EXECUTE RECON ENUMERATION & COMPEL PHYSICAL WRITE
                # =================================================================
                try:
                    output_data = run_enumerate({"domain": domain})
                    recon_dir_name = f"{domain}_enumeration"
                    domain_recon_dir = Path(os.path.abspath(project_disk_path / recon_dir_name))
                    domain_recon_dir.mkdir(parents=True, exist_ok=True)
                    
                    recon_file_name = f"recon_enumerate_{domain}.json"
                    recon_disk_path = os.path.abspath(domain_recon_dir / recon_file_name)
                    vault_recon_display_name = f"{recon_dir_name}/{recon_file_name}"
                    
                    log.write(f"Executing Recon File Allocation: {recon_disk_path}\n")
                    
                    with open(recon_disk_path, "w", encoding="utf-8") as f:
                        json.dump(output_data, f, indent=4)
                        
                    log.write(f"CONFIRMED DISK SAVE: {vault_recon_display_name} successfully committed to system.\n")
                    
                    if not any(v["name"] == vault_recon_display_name for v in proj["vault"]):
                        file_size = os.path.getsize(recon_disk_path)
                        size_str = f"{round(file_size / 1024, 1)} KB" if file_size >= 1024 else f"{file_size} Bytes"
                        proj["vault"].append({
                            "id": f"v-{secrets.token_hex(2)}",
                            "name": vault_recon_display_name,
                            "size": size_str,
                            "date": "Just now"
                        })
                        log.write(f"CONFIRMED ENGINE SYNC: {vault_recon_display_name} added to web table view.\n")
                        
                except Exception as enum_error:
                    log.write(f"!!! WRITE RECON ERROR ON TARGET '{domain}': {str(enum_error)}\n")
                    log.write(traceback.format_exc())

                # =================================================================
                # PHASE 2: RUN SWAGGER POST VECTOR PARSING & COMPEL DIRECT EXTRACTION
                # =================================================================
                file_id = domain_record.get("swagger_file_id")
                if file_id:
                    vault_asset = next((v for v in proj.get("vault", []) if v["id"] == file_id), None)
                    if vault_asset:
                        safe_filename = f"{file_id}_{domain}_{vault_asset['name'].split('_', 1)[-1]}" if "_" in vault_asset['name'] else f"{file_id}_{vault_asset['name']}"
                        schema_disk_path = os.path.abspath(project_disk_path / safe_filename)
                        if not os.path.exists(schema_disk_path):
                            schema_disk_path = os.path.abspath(project_disk_path / f"{file_id}_{vault_asset['name']}")
                            
                        if os.path.exists(schema_disk_path):
                            try:
                                with open(schema_disk_path, "r", encoding="utf-8") as f:
                                    schema_content = f.read()
                                target_dir_name = f"{domain}_requests"
                                domain_vault_dir = Path(os.path.abspath(project_disk_path / target_dir_name))
                                domain_vault_dir.mkdir(parents=True, exist_ok=True)
                                log.write(f"TARGET EXT EXTRACTION PATH VERIFIED: {domain_vault_dir}\n")
                                
                                input_payload = {"spec": schema_content, "output_dir": str(domain_vault_dir)}
                                execution_manifest = get_post_requests(input_payload)
                                
                                for full_file_path in execution_manifest.get("generated_files", []):
                                    abs_file_path = os.path.abspath(full_file_path)
                                    filename = os.path.basename(abs_file_path)
                                    vault_display_name = f"{target_dir_name}/{filename}"
                                    if os.path.exists(abs_file_path):
                                        if not any(v["name"] == vault_display_name for v in proj["vault"]):
                                            file_size_bytes = os.path.getsize(abs_file_path)
                                            v_size_str = f"{round(file_size_bytes / 1024, 1)} KB" if file_size_bytes >= 1024 else f"{file_size_bytes} Bytes"
                                            proj["vault"].append({
                                                "id": f"v-{secrets.token_hex(2)}",
                                                "name": vault_display_name,
                                                "size": v_size_str,
                                                "date": "Just now"
                                            })
                                            log.write(f"CONFIRMED VECTOR SYNC: Generated vector stored at {vault_display_name}\n")
                            except Exception as post_error:
                                log.write(f"!!! WRITE VECTOR ERROR ON TARGET '{domain}': {str(post_error)}\n")
                                log.write(traceback.format_exc())
                                
        except Exception as loop_fatal:
            log.write(f"FATAL RECON ENGINE PROCESS DE-RAIL: {str(loop_fatal)}\n")
            log.write(traceback.format_exc())
        finally:
            proj["engine_status"] = "Idle"
            log.write("\n=============================================\n")
            log.write("PIPELINE TASK STOPPED AND CLEANED UP NATIVELY\n")
            log.write("=============================================\n")

@app.post("/{username}/{project}/scan")
async def trigger_full_scan(username: str, project: str, background_tasks: BackgroundTasks):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile: raise HTTPException(status_code=404, detail="User not found")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj: raise HTTPException(status_code=404, detail="Project not found")
    proj["engine_status"] = "Scanning"
    background_tasks.add_task(run_pipeline_worker, target_user, target_project)
    return {"status": "success"}

@app.delete("/{username}/{project}/domains/{domain_name}")
async def delete_domain(username: str, project: str, domain_name: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    target_domain = domain_name.strip().lower()
    
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile: raise HTTPException(status_code=404, detail="User not found")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj: raise HTTPException(status_code=404, detail="Project not found")
    
    domain_record = next((d for d in proj.get("domains", []) if d["name"] == target_domain), None)
    if not domain_record: raise HTTPException(status_code=404, detail="Domain not found")

    proj["domains"].remove(domain_record)
    
    project_disk_path = Path(os.path.abspath(STORAGE_DIR / target_user / target_project))
    for folder in [f"{target_domain}_enumeration", f"{target_domain}_requests"]:
        p = project_disk_path / folder
        if p.exists() and p.is_dir():
            shutil.rmtree(p)
    
    proj["vault"] = [v for v in proj.get("vault", []) if not v["name"].startswith(f"{target_domain}_")]
    return {"status": "success", "message": "Domain and associated files purged."}

@app.get("/{username}/{project}/vault/download/{file_id}")
async def download_vault_file(username: str, project: str, file_id: str):
    target_user = username.strip().lower()
    target_project = project.strip().lower()
    profile = next((u for u in users_db.values() if u["username"] == target_user), None)
    if not profile: raise HTTPException(status_code=404, detail="User not found")
    proj = next((p for p in profile["projects"] if p["name"].lower() == target_project), None)
    if not proj: raise HTTPException(status_code=404, detail="Project not found")
        
    vault_asset = next((v for v in proj.get("vault", []) if v["id"] == file_id), None)
    if not vault_asset: raise HTTPException(status_code=404, detail="File record not found")
        
    project_disk_path = Path(os.path.abspath(STORAGE_DIR / target_user / target_project))
    file_disk_path = project_disk_path / vault_asset["name"]
    
    if not file_disk_path.exists():
        safe_filename = f"{file_id}_{vault_asset['name']}"
        fallback_path = project_disk_path / safe_filename
        if fallback_path.exists():
            file_disk_path = fallback_path
        else:
            raise HTTPException(status_code=404, detail="Physical file missing.")
            
    return FileResponse(path=str(file_disk_path), filename=os.path.basename(str(file_disk_path)), media_type="application/octet-stream")