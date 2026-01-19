import json
import time
from datetime import datetime
from pathlib import Path

# Get project root (parent of agent directory)
PROJECT_ROOT = Path(__file__).parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "decisions.log"

def log_decision(file_path, file_hash, source, verdict, elapsed_ms):
    record = {
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "file": Path(file_path).name,
        "hash": file_hash,
        "source": source,
        "verdict": int(verdict),
        "ms": int(elapsed_ms),
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def log_quarantine(file_path, quarantine_path):
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "action": "quarantine",
        "original": file_path,
        "quarantine_path": quarantine_path
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def log_restore(qpath, restored_path):
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "action": "restore",
        "from": qpath,
        "to": restored_path
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
