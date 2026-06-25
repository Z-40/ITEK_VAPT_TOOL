from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from typing import List, Optional, Any

app = FastAPI(title="ITEK VAPT Tool API", version="1.0")

# CORS (Update for Vercel) 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Vercel URL in production, e.g. ["https://your-frontend.vercel.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
# add shit here

# Routing 
@app.get("/")
async def get_index():
    pass

@app.post("/login")
async def get_login():
    pass

@app.post("/signup")
async def get_signup():
    pass

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
