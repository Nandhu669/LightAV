"""
FastAPI backend bridge for LightAV
Serves React UI and exposes REST endpoints
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
from pathlib import Path

# LightAV backend imports
from agent.scanner import process_file
from agent.runtime_state import RUNNING
from agent.decision_types import Verdict

app = FastAPI()

# Request models
class ScanRequest(BaseModel):
    path: str

# API Endpoints
@app.get("/api/status")
def get_status():
    return {"running": RUNNING.is_set()}

@app.post("/api/log")
def log_ui_message(message: dict):
    print(f"[UI-CLIENT] {message.get('msg')}", flush=True)
    return {"status": "ok"}

@app.post("/api/toggle")
def toggle_protection():
    if RUNNING.is_set():
        RUNNING.clear()
    else:
        RUNNING.set()
    return {"running": RUNNING.is_set()}

@app.get("/api/system_stats")
def get_system_stats():
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        return {"cpu": cpu, "ram": ram}
    except:
        return {"cpu": 0, "ram": 0}

@app.post("/api/scan")
def scan_file(request: ScanRequest):
    print(f"[API] Received scan request for: {request.path}")
    try:
        verdict = process_file(request.path)
        print(f"[API] Scan result for {request.path}: {verdict}")
        return {
            "success": True,
            "verdict": "MALICIOUS" if verdict == Verdict.MALICIOUS else "CLEAN",
            "path": request.path
        }
    except Exception as e:
        print(f"[API] Error scanning {request.path}: {e}")
        return {"success": False, "error": str(e)}

@app.post("/api/scan_folder")
def scan_folder(request: ScanRequest):
    from agent.scanner import EXCLUDED_PATHS
    print(f"[API] Received folder scan request for: {request.path}")
    try:
        results = []
        if not os.path.isdir(request.path):
            return {"success": False, "error": "Not a directory"}
            
        for root, dirs, files in os.walk(request.path):
            # Skip excluded directories for performance and safety
            root_abs = os.path.abspath(root).lower()
            skip_dir = False
            for excluded in EXCLUDED_PATHS:
                if root_abs.startswith(excluded):
                    skip_dir = True
                    break
            
            if skip_dir:
                # Modifying dirs in-place prevents walk from descending into them
                dirs[:] = []
                continue

            for file in files:
                filepath = os.path.join(root, file)
                try:
                    verdict = process_file(filepath)
                    if verdict == Verdict.MALICIOUS:
                        results.append({"path": filepath, "verdict": "MALICIOUS"})
                except:
                    pass
        
        return {
            "success": True,
            "threats_found": len(results),
            "threats": results,
            "path": request.path
        }
    except Exception as e:
        print(f"[API] Error scanning folder {request.path}: {e}")
        return {"success": False, "error": str(e)}

@app.get("/api/quarantine")
def get_quarantine():
    from agent.quarantine import QUARANTINE_DIR
    import json
    from datetime import datetime
    
    files = []
    if QUARANTINE_DIR.exists():
        for file_path in QUARANTINE_DIR.glob("*"):
            if file_path.is_file() and not file_path.name.endswith('.meta'):
                meta_path = Path(str(file_path) + '.meta')
                metadata = {}
                if meta_path.exists():
                    try:
                        with open(meta_path, 'r') as f:
                            metadata = json.load(f)
                    except:
                        pass
                
                parts = file_path.name.split('_', 2)
                if len(parts) >= 3:
                    timestamp = int(parts[0])
                    original_name = parts[2]
                    date_quarantined = datetime.fromtimestamp(timestamp)
                else:
                    original_name = file_path.name
                    date_quarantined = datetime.fromtimestamp(file_path.stat().st_mtime)
                
                files.append({
                    'filename': original_name,
                    'threat_type': metadata.get('threat_type', 'Unknown'),
                    'date_quarantined': date_quarantined.strftime("%Y-%m-%d %H:%M:%S"),
                    'quarantine_path': str(file_path),
                    'original_path': metadata.get('original_path', 'Unknown')
                })
    
    return {"files": files}

@app.post("/api/restore_all")
def restore_all():
    from agent.restore import restore_file
    from agent.quarantine import QUARANTINE_DIR
    
    restored_count = 0
    if QUARANTINE_DIR.exists():
        for file_path in QUARANTINE_DIR.glob("*"):
            if file_path.is_file() and not file_path.name.endswith('.meta'):
                try:
                    parts = file_path.name.split('_', 2)
                    original_name = parts[2] if len(parts) >= 3 else file_path.name
                    desktop = Path.home() / "Desktop"
                    restore_path = str(desktop / original_name)
                    restore_file(str(file_path), restore_path)
                    
                    meta_path = Path(str(file_path) + '.meta')
                    if meta_path.exists():
                        meta_path.unlink()
                    
                    restored_count += 1
                except:
                    pass
    
    return {"restored": restored_count}

@app.post("/api/delete_all")
def delete_all():
    from agent.quarantine import QUARANTINE_DIR
    
    deleted_count = 0
    if QUARANTINE_DIR.exists():
        for file_path in QUARANTINE_DIR.glob("*"):
            if file_path.is_file():
                try:
                    file_path.unlink()
                    deleted_count += 1
                except:
                    pass
    
    return {"deleted": deleted_count}

# Static file serving
dist_path = Path(__file__).parent / "web" / "dist"
if dist_path.exists():
    app.mount("/assets", StaticFiles(directory=str(dist_path / "assets")), name="assets")
    
    @app.get("/")
    def serve_root():
        return FileResponse(str(dist_path / "index.html"))
    
    @app.get("/{full_path:path}")
    def serve_static(full_path: str):
        file_path = dist_path / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(dist_path / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
