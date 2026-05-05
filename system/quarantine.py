import os
import shutil
import time
from pathlib import Path

QUARANTINE_DIR = Path("quarantine/files")
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

def quarantine_file(file_path, file_hash):
    import json
    
    timestamp = int(time.time())
    filename = Path(file_path).name
    quarantine_name = f"{timestamp}_{file_hash}_{filename}"

    dest = QUARANTINE_DIR / quarantine_name

    # Store metadata before moving file
    metadata = {
        'original_path': str(file_path),
        'file_hash': file_hash,
        'timestamp': timestamp,
        'threat_type': 'Malicious',  # Default threat type
        'original_name': filename
    }
    
    meta_path = QUARANTINE_DIR / f"{quarantine_name}.meta"
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    shutil.move(file_path, dest)

    return str(dest)

