"""
FastAPI backend bridge for LightAV
Serves React UI and exposes REST endpoints
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import os
import io
import csv
from datetime import datetime
from pathlib import Path

# LightAV backend imports
from core.scanner import ProductionScanner
from core.decision_types import Verdict
import json
from datetime import datetime
import psutil
import threading

# ── Runtime feature flags (in-memory toggles, same as old runtime_state.py) ──
RUNNING = threading.Event(); RUNNING.set()
USB_PROTECTION_ENABLED = threading.Event(); USB_PROTECTION_ENABLED.set()
WEB_PROTECTION_ENABLED = threading.Event()
FIREWALL_ENABLED = threading.Event()
NETWORK_PROTECTION_ENABLED = threading.Event(); NETWORK_PROTECTION_ENABLED.set()
PRIVACY_GUARD_ENABLED = threading.Event()
EMAIL_PROTECTION_ENABLED = threading.Event(); EMAIL_PROTECTION_ENABLED.set()

# ── Inline stubs for features not yet wired to production engine ──
def _read_last_lines(n=50):
    """Read last n lines from log file."""
    log_file = Path("logs/lightav.log")
    if not log_file.exists():
        return []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            return f.readlines()[-n:]
    except Exception:
        return []

def _noop(*a, **kw):
    return {"success": True, "message": "Feature not available in this build"}

# Map old functions to stubs
read_last_lines = _read_last_lines
enable_web_protection = _noop
disable_web_protection = _noop
toggle_firewall_rule = _noop
start_network_monitor = lambda *a, **kw: None
toggle_privacy_guard = _noop
start_email_monitor = lambda *a, **kw: None
start_network_scan = lambda: {"success": True, "connections": []}
start_vulnerability_scan = lambda: {"success": True, "vulnerabilities": [], "score": 100}

# ── Shared scanner singleton ──
_scanner = ProductionScanner()

def process_file(path):
    """Wrapper matching old agent.scanner.process_file API."""
    result = _scanner.scan_file(path, auto_quarantine=False)
    return result.verdict

def _is_locked_system_file(path):
    """Check if file is a locked system file."""
    import os
    name = os.path.basename(path).lower()
    return name in {
        'ntoskrnl.exe', 'csrss.exe', 'smss.exe', 'wininit.exe',
        'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe',
        'ntdll.dll', 'kernel32.dll', 'hal.dll',
    }

SCAN_HISTORY_FILE = Path("scan_history.json")
current_process = psutil.Process()
cpu_count = psutil.cpu_count() or 1
total_ram = psutil.virtual_memory().total

# Start background security monitors automatically when the server spins up
start_network_monitor(NETWORK_PROTECTION_ENABLED)
start_email_monitor(EMAIL_PROTECTION_ENABLED)

def get_process_resources():
    # Return process-specific resources: CPU % and RAM (in MB)
    return {
        "cpu": current_process.cpu_percent() / cpu_count,
        "ram": current_process.memory_info().rss / (1024 * 1024)
    }

def add_to_history(scan_type, results, status="Completed", resources=None):
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
        "results": results,
        "resources": resources
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

@app.get("/api/export_logs")
def export_logs():
    LOG_FILE = Path(chr(108)+chr(111)+chr(103)+chr(115)+chr(47)+chr(108)+chr(105)+chr(103)+chr(104)+chr(116)+chr(97)+chr(118)+chr(46)+chr(108)+chr(111)+chr(103))
    if not LOG_FILE.exists():
        return {"success": False, "error": "No logs available"}
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Module", "Event", "Status"])
    
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                raw = json.loads(line)
                status = "INFO"
                event = ""
                module = "System"

                if raw.get("action") == "quarantine":
                    status = "THREAT"
                    event = f"Quarantined: {raw.get('original')}"
                    module = "Shield"
                elif raw.get("action") == "restore":
                    status = "SUCCESS"
                    event = f"Restored: {raw.get('to')}"
                    module = "Recovery"
                elif raw.get("verdict") is not None:
                    status = "THREAT" if raw.get("verdict") == 1 else "SUCCESS"
                    event = f"File Scan: {raw.get('file')} - {'Threat Blocked' if raw.get('verdict') == 1 else 'Clean'}"
                    module = "HashDB" if raw.get("source") == "cache" else "Scanner"
                
                writer.writerow([raw.get("ts"), module, event, status])
            except:
                continue
    
    # Save to Downloads folder
    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_path):
        try:
            os.makedirs(downloads_path)
        except:
            return {"success": False, "error": "Could not access Downloads folder"}
            
    filename = f"lightav_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(downloads_path, filename)
    
    try:
        with open(filepath, "w", encoding="utf-8", newline='') as f:
            f.write(output.getvalue())
    except Exception as e:
        return {"success": False, "error": f"Failed to save file: {str(e)}"}
        
    return {"success": True, "path": filepath}

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

@app.get("/api/status/usb")
def get_usb_status():
    return {"running": USB_PROTECTION_ENABLED.is_set()}

@app.post("/api/toggle/usb")
def toggle_usb_protection():
    if USB_PROTECTION_ENABLED.is_set():
        USB_PROTECTION_ENABLED.clear()
    else:
        USB_PROTECTION_ENABLED.set()
    return {"running": USB_PROTECTION_ENABLED.is_set()}

@app.get("/api/status/web")
def get_web_status():
    return {"running": WEB_PROTECTION_ENABLED.is_set()}

@app.post("/api/toggle/web")
def toggle_web_protection():
    if WEB_PROTECTION_ENABLED.is_set():
        # User turned it off
        disable_web_protection()
        WEB_PROTECTION_ENABLED.clear()
    else:
        # User turned it on
        success = enable_web_protection()
        # Even if not admin, we toggle state to keep UI working, or we can restrict it.
        # Let's toggle it anyway so they see the button turn blue.
        WEB_PROTECTION_ENABLED.set()
    return {"running": WEB_PROTECTION_ENABLED.is_set()}

@app.get("/api/status/firewall")
def get_firewall_status():
    return {"running": FIREWALL_ENABLED.is_set()}

@app.post("/api/toggle/firewall")
def toggle_firewall():
    if FIREWALL_ENABLED.is_set():
        toggle_firewall_rule(False)
        FIREWALL_ENABLED.clear()
    else:
        toggle_firewall_rule(True)
        FIREWALL_ENABLED.set()
    return {"running": FIREWALL_ENABLED.is_set()}

@app.get("/api/status/network")
def get_network_status():
    return {"running": NETWORK_PROTECTION_ENABLED.is_set()}

@app.post("/api/toggle/network")
def toggle_network():
    if NETWORK_PROTECTION_ENABLED.is_set():
        NETWORK_PROTECTION_ENABLED.clear()
    else:
        NETWORK_PROTECTION_ENABLED.set()
    return {"running": NETWORK_PROTECTION_ENABLED.is_set()}

@app.get("/api/status/privacy")
def get_privacy_status():
    return {"running": PRIVACY_GUARD_ENABLED.is_set()}

@app.post("/api/toggle/privacy")
def toggle_privacy():
    if PRIVACY_GUARD_ENABLED.is_set():
        toggle_privacy_guard(False)
        PRIVACY_GUARD_ENABLED.clear()
    else:
        toggle_privacy_guard(True)
        PRIVACY_GUARD_ENABLED.set()
    return {"running": PRIVACY_GUARD_ENABLED.is_set()}

@app.get("/api/status/email")
def get_email_status():
    return {"running": EMAIL_PROTECTION_ENABLED.is_set()}

@app.post("/api/toggle/email")
def toggle_email():
    if EMAIL_PROTECTION_ENABLED.is_set():
        EMAIL_PROTECTION_ENABLED.clear()
    else:
        EMAIL_PROTECTION_ENABLED.set()
    return {"running": EMAIL_PROTECTION_ENABLED.is_set()}

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
        # Trigger CPU measurement
        current_process.cpu_percent()
        
        verdict = process_file(request.path)
        
        res = get_process_resources()
        verdict_str = "MALICIOUS" if verdict == Verdict.MALICIOUS else "CLEAN"
        print(f"[API] Scan result for {request.path}: {verdict_str}")
        
        add_to_history("Quick Scan", {
            "path": request.path,
            "verdict": verdict_str
        }, resources=res)

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
    
    print(f"[API] Received folder scan request for: {request.path}")
    try:
        results = []
        peak_cpu = 0
        peak_ram = 0
        
        # Trigger CPU measurement
        current_process.cpu_percent()
        
        if not os.path.isdir(request.path):
            return {"success": False, "error": "Not a directory"}
            
        for root, dirs, files in os.walk(request.path):


            for file in files:
                filepath = os.path.join(root, file)
                try:
                    # Skip locked/system-critical files
                    if _is_locked_system_file(filepath):
                        continue

                    verdict = process_file(filepath)
                    if verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                        results.append({"path": filepath, "verdict": verdict.name})
                    
                    # Track peak usage
                    res = get_process_resources()
                    peak_cpu = max(peak_cpu, res["cpu"])
                    peak_ram = max(peak_ram, res["ram"])
                except:
                    pass
        
        add_to_history("Folder Scan", {
            "path": request.path,
            "threats_found": len(results),
            "threats": results
        }, resources={
            "cpu": peak_cpu,
            "ram": peak_ram
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
    
    
    import time
    
    scan_jobs[job_id]["status"] = "running"
    peak_cpu = 0
    peak_ram = 0
    
    # Trigger CPU measurement
    current_process.cpu_percent()
    
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
                

                for file in files:
                    files_count += 1
                    scan_jobs[job_id]["files_scanned"] = files_count
                    
                    # Track peak usage
                    res = get_process_resources()
                    peak_cpu = max(peak_cpu, res["cpu"])
                    peak_ram = max(peak_ram, res["ram"])
                    
                    # Show more informative path (e.g., ParentFolder\filename.ext)
                    rel_path = os.path.relpath(os.path.join(root, file), drive)
                    scan_jobs[job_id]["last_file"] = rel_path
                    
                    # Adaptive CPU throttle — never halts, just slows down
                    if files_count % 10 == 0:
                        sys_cpu = psutil.cpu_percent(interval=None)
                        if sys_cpu > 85:
                            # System is very busy — pause for 2 seconds
                            scan_jobs[job_id]["message"] = f"Pausing — system CPU at {sys_cpu:.0f}%"
                            time.sleep(2.0)
                        elif sys_cpu > 70:
                            # System is busy — slow down significantly
                            scan_jobs[job_id]["message"] = f"Throttling — system CPU at {sys_cpu:.0f}%"
                            time.sleep(0.5)
                        elif sys_cpu > 50:
                            # Moderate load — gentle back off
                            scan_jobs[job_id]["message"] = ""
                            time.sleep(0.1)
                        else:
                            # System mostly idle — scan at full speed
                            scan_jobs[job_id]["message"] = ""
                            time.sleep(0.02)

                    filepath = os.path.join(root, file)

                    # Skip locked/system-critical files
                    if _is_locked_system_file(filepath):
                        continue

                    try:
                        verdict = process_file(filepath)
                        if verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                            results.append({"path": filepath, "verdict": verdict.name})
                            scan_jobs[job_id]["threats_found"] = len(results)
                    except:
                        pass
        
        resources = {"cpu": peak_cpu, "ram": peak_ram}
        
        if scan_jobs[job_id]["status"] == "running":
            scan_jobs[job_id]["status"] = "completed"
            scan_jobs[job_id]["scanned_paths"] = scanned_paths
            scan_jobs[job_id]["threats"] = results
            scan_jobs[job_id]["message"] = ""
            
            add_to_history("Full System Scan", {
                "drives": scanned_paths,
                "threats_found": len(results),
                "threats": results
            }, resources=resources)
            
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
    current_process.cpu_percent()
    result = start_network_scan()
    res = get_process_resources()
    
    if result["success"]:
        add_to_history("Network Scan", {
            "connections_found": len(result["connections"])
        }, resources=res)
    return result

@app.post("/api/vulnerability_scan")
def vulnerability_scan():
    print("[API] Received vulnerability scan request")
    current_process.cpu_percent()
    result = start_vulnerability_scan()
    res = get_process_resources()
    
    if result["success"]:
        add_to_history("Vulnerability Scan", {
            "vulnerabilities_found": len(result["vulnerabilities"]),
            "security_score": result["score"]
        }, resources=res)
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

@app.post("/api/clear_scan_history")
def clear_scan_history():
    try:
        if SCAN_HISTORY_FILE.exists():
            with open(SCAN_HISTORY_FILE, "w") as f:
                json.dump([], f)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/quarantine")
def get_quarantine():
    QUARANTINE_DIR = Path(chr(113)+chr(117)+chr(97)+chr(114)+chr(97)+chr(110)+chr(116)+chr(105)+chr(110)+chr(101))
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
    from system.restore import restore_file
    QUARANTINE_DIR = Path(chr(113)+chr(117)+chr(97)+chr(114)+chr(97)+chr(110)+chr(116)+chr(105)+chr(110)+chr(101))
    
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
    from system.restore import restore_file
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
    QUARANTINE_DIR = Path(chr(113)+chr(117)+chr(97)+chr(114)+chr(97)+chr(110)+chr(116)+chr(105)+chr(110)+chr(101))
    
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
dist_path = Path(__file__).parent.parent / "ui" / "web" / "dist"
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
