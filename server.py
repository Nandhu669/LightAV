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
from agent.network_scan import start_network_scan
from agent.log_reader import read_last_lines
import json
from datetime import datetime

SCAN_HISTORY_FILE = Path("scan_history.json")

def add_to_history(scan_type, results, status="Completed"):
    history = []
    if SCAN_HISTORY_FILE.exists():
        try:
            with open(SCAN_HISTORY_FILE, "r") as f:
                history = json.load(f)
        except:
            pass
    
    history.insert(0, {
        "id": str(len(history) + 1),
        "type": scan_type,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "results": results
    })
    
    # Keep only last 50 entries
    history = history[:50]
    
    with open(SCAN_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

app = FastAPI()

# Request models
class ScanRequest(BaseModel):
    path: str

class RestoreFileRequest(BaseModel):
    quarantine_path: str

# API Endpoints
@app.get("/api/status")
def get_status():
    return {"running": RUNNING.is_set()}

@app.get("/api/system_logs")
def get_system_logs():
    lines = read_last_lines(50)
    logs = []
    for line in lines:
        try:
            logs.append(json.loads(line))
        except:
            continue
    return {"logs": logs}

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
        verdict_str = "MALICIOUS" if verdict == Verdict.MALICIOUS else "CLEAN"
        print(f"[API] Scan result for {request.path}: {verdict_str}")
        
        add_to_history("Quick Scan", {
            "path": request.path,
            "verdict": verdict_str
        })

        return {
            "success": True,
            "verdict": verdict_str,
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
        
        add_to_history("Folder Scan", {
            "path": request.path,
            "threats_found": len(results),
            "threats": results
        })

        return {
            "success": True,
            "threats_found": len(results),
            "threats": results,
            "path": request.path
        }
    except Exception as e:
        print(f"[API] Error scanning folder {request.path}: {e}")
        return {"success": False, "error": str(e)}

# Background job storage
scan_jobs = {}

def run_background_full_scan(job_id):
    from agent.scanner import EXCLUDED_PATHS
    from agent.scanner import Verdict
    import psutil
    import time
    
    scan_jobs[job_id]["status"] = "running"
    try:
        results = []
        scanned_paths = []
        files_count = 0
        
        # Discover all fixed drives
        drives = [p.mountpoint for p in psutil.disk_partitions() if 'fixed' in p.opts or 'cdrom' not in p.opts.lower()]
        
        for drive in drives:
            if scan_jobs[job_id]["status"] != "running":
                break
            
            scanned_paths.append(drive)
            for root, dirs, files in os.walk(drive):
                if scan_jobs[job_id]["status"] != "running":
                    break
                
                # Skip excluded directories
                root_abs = os.path.abspath(root).lower()
                skip_dir = False
                for excluded in EXCLUDED_PATHS:
                    if root_abs.startswith(excluded):
                        skip_dir = True
                        break
                
                if skip_dir:
                    dirs[:] = []
                    continue

                for file in files:
                    files_count += 1
                    scan_jobs[job_id]["files_scanned"] = files_count
                    
                    # Show more informative path (e.g., ParentFolder\filename.ext)
                    rel_path = os.path.relpath(os.path.join(root, file), drive)
                    scan_jobs[job_id]["last_file"] = rel_path
                    
                    # Check CPU usage every 50 files
                    if files_count % 50 == 0:
                        cpu_usage = psutil.cpu_percent(interval=None)
                        if cpu_usage > 60:
                            print(f"[API] CPU usage too high ({cpu_usage}%). Halting scan job {job_id}")
                            scan_jobs[job_id]["status"] = "halted"
                            scan_jobs[job_id]["message"] = f"Scan halted due to high CPU usage ({cpu_usage}%)."
                            break

                    # CPU Throttling
                    time.sleep(0.01)

                    filepath = os.path.join(root, file)
                    try:
                        verdict = process_file(filepath)
                        if verdict == Verdict.MALICIOUS:
                            results.append({"path": filepath, "verdict": "MALICIOUS"})
                            scan_jobs[job_id]["threats_found"] = len(results)
                    except:
                        pass
        
        if scan_jobs[job_id]["status"] == "running":
            scan_jobs[job_id]["status"] = "completed"
            scan_jobs[job_id]["scanned_paths"] = scanned_paths
            scan_jobs[job_id]["threats"] = results
            
            add_to_history("Full System Scan", {
                "drives": scanned_paths,
                "threats_found": len(results),
                "threats": results
            })
        elif scan_jobs[job_id]["status"] == "halted":
            add_to_history("Full System Scan", {
                "threats_found": len(results),
                "message": scan_jobs[job_id].get("message", "Halted")
            }, status="Halted")
            
    except Exception as e:
        print(f"[API] Error during background scan {job_id}: {e}")
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["message"] = str(e)
        add_to_history("Full System Scan", {"error": str(e)}, status="Failed")

@app.post("/api/full_scan")
def full_scan():
    import uuid
    import threading
    
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "status": "pending",
        "files_scanned": 0,
        "threats_found": 0,
        "last_file": "",
        "message": ""
    }
    
    thread = threading.Thread(target=run_background_full_scan, args=(job_id,))
    thread.daemon = True
    thread.start()
    
    return {"success": True, "job_id": job_id}

@app.get("/api/scan_status/{job_id}")
def get_scan_status(job_id: str):
    if job_id not in scan_jobs:
        return {"success": False, "error": "Job not found"}
    
    return {
        "success": True,
        **scan_jobs[job_id]
    }

@app.post("/api/network_scan")
def network_scan():
    print("[API] Received network scan request")
    result = start_network_scan()
    if result["success"]:
        add_to_history("Network Scan", {
            "connections_found": len(result["connections"])
        })
    return result

@app.post("/api/vulnerability_scan")
def vulnerability_scan():
    print("[API] Received vulnerability scan request")
    result = start_vulnerability_scan()
    if result["success"]:
        add_to_history("Vulnerability Scan", {
            "vulnerabilities_found": len(result["vulnerabilities"]),
            "security_score": result["score"]
        })
    return result

@app.get("/api/scan_history")
def get_scan_history():
    history = []
    if SCAN_HISTORY_FILE.exists():
        try:
            with open(SCAN_HISTORY_FILE, "r") as f:
                history = json.load(f)
        except:
            pass
    return {"history": history}

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

@app.post("/api/restore_file")
def restore_single_file(request: RestoreFileRequest):
    from agent.restore import restore_file
    import json

    quarantine_path = Path(request.quarantine_path)
    if not quarantine_path.exists():
        return {"success": False, "error": "Quarantined file not found"}

    # Try to get original path from metadata
    meta_path = Path(str(quarantine_path) + '.meta')
    original_path = None
    if meta_path.exists():
        try:
            with open(meta_path, 'r') as f:
                metadata = json.load(f)
            original_path = metadata.get('original_path')
        except:
            pass

    # Fall back to Desktop if original path is unavailable
    if not original_path:
        parts = quarantine_path.name.split('_', 2)
        original_name = parts[2] if len(parts) >= 3 else quarantine_path.name
        original_path = str(Path.home() / "Desktop" / original_name)

    try:
        restore_file(str(quarantine_path), original_path)
        # Clean up metadata file
        if meta_path.exists():
            meta_path.unlink()
        return {"success": True, "restored_to": original_path}
    except Exception as e:
        return {"success": False, "error": str(e)}

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
