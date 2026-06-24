from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import os
from typing import List, Optional, Any

app = FastAPI(title="ITEK VAPT Tool API", version="1.0")

# ====================== CORS (Update for Vercel) ======================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to your Vercel URL in production, e.g. ["https://your-frontend.vercel.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("outputs", exist_ok=True)

# ====================== REQUEST MODELS ======================
class TargetRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None
    concurrency: Optional[int] = 50
    timeout: Optional[float] = 2.0

class SQLiRequest(BaseModel):
    request_dir: str
    workers: Optional[int] = 4

class PostRequestScan(BaseModel):
    openapi_path: str
    target_url: Optional[str] = None

# ====================== ROOT ======================
@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "ITEK VAPT Tool Backend Running",
        "available": ["recon", "sqli", "post-requests", "cve-dast"]
    }

# ====================== RECON ENDPOINTS ======================
@app.post("/api/recon/port-scan")
async def port_scan(req: TargetRequest):
    try:
        from features.recon.port_scan import scan_ports
        return scan_ports(req.dict())
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/dns-scan")
async def dns_scan(req: TargetRequest):
    try:
        from features.recon.dns_scan import run_dns_scan
        return run_dns_scan(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/fingerprint")
async def fingerprint(req: TargetRequest):
    try:
        from features.recon.fingerprinting import run_fingerprinting
        return run_fingerprinting(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/tls-scan")
async def tls_scan(req: TargetRequest):
    try:
        from features.recon.tls_scan import run_tls_scan
        return run_tls_scan(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/web-path")
async def web_path(req: TargetRequest):
    try:
        from features.recon.web_path import run_web_path
        return run_web_path(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/rdap")
async def rdap(req: TargetRequest):
    try:
        from features.recon.rdap_scan import run_rdap
        return run_rdap(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/enumerate")
async def enumerate(req: TargetRequest):
    try:
        from features.recon.enumerate import run_enumeration
        return run_enumeration(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.post("/api/recon/aggregate")
async def aggregate(req: TargetRequest):
    try:
        from features.recon.aggregator import aggregate_results
        return aggregate_results(req.target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

# ====================== SQLi ======================
@app.post("/api/sqli/run")
async def run_sqli(req: SQLiRequest, background_tasks: BackgroundTasks):
    if not os.path.exists(req.request_dir):
        raise HTTPException(404, detail="Request directory not found")
    
    background_tasks.add_task(run_sqli_task, req.request_dir, req.workers)
    return {"status": "started", "directory": req.request_dir}

def run_sqli_task(request_dir: str, workers: int):
    try:
        subprocess.run([
            "python", "-m", "features.sqli.sqli",
            "--dir", request_dir,
            "--workers", str(workers)
        ], check=True, cwd=os.getcwd())
    except Exception as e:
        print(f"SQLi background task error: {e}")

# ====================== Post Requests ======================
@app.post("/api/post-requests/scan")
async def post_requests_scan(req: PostRequestScan):
    try:
        from features.post_requests.post_requests import run_post_requests
        return run_post_requests(req.openapi_path, req.target_url)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

# ====================== CVE / DAST ======================
@app.post("/api/cve-dast/detect")
async def cve_dast_detect(target: str):
    try:
        from cve_dast.detector import run_cve_detection
        return run_cve_detection(target)
    except Exception as e:
        raise HTTPException(500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)