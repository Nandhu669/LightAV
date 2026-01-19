import os
import shutil
import time
from pathlib import Path

QUARANTINE_DIR = Path("quarantine/files")
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

def quarantine_file(file_path, file_hash):
    timestamp = int(time.time())
    filename = Path(file_path).name
    quarantine_name = f"{timestamp}_{file_hash}_{filename}"

    dest = QUARANTINE_DIR / quarantine_name

    shutil.move(file_path, dest)

    return str(dest)
