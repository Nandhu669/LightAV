from agent.hash_cache import (
    compute_hash,
    get_cached_verdict,
    store_verdict
)
from agent.decision_engine import decide
from agent.decision_types import Verdict
from agent.logger import log_decision, log_quarantine
from agent.quarantine import quarantine_file
from agent.timer import Timer
import os

# Executable file extensions to scan
SCANNABLE_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js'}

# Folders to skip during scanning (False Positives Prevention)
EXCLUDED_PATHS = [
    os.environ.get('SystemRoot', 'C:\\Windows').lower(),
    os.environ.get('ProgramFiles', 'C:\\Program Files').lower(),
    os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').lower(),
]

def process_file(path):
    """
    Process and scan a file for malware.
    
    Args:
        path: Path to the file to scan
        
    Returns:
        Verdict: BENIGN, MALICIOUS, or BENIGN for unsupported files
    """
    # Check if file exists
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    # Get file extension
    _, ext = os.path.splitext(path)
    ext_lower = ext.lower()
    
    # Skip non-executable files (images, documents, etc.)
    if ext_lower not in SCANNABLE_EXTENSIONS:
        # Non-executable files are considered benign by default
        return Verdict.BENIGN
    
    # Skip excluded system folders
    abs_path = os.path.abspath(path).lower()
    for excluded in EXCLUDED_PATHS:
        if abs_path.startswith(excluded):
            # System folders are skipped to avoid false positives
            return Verdict.BENIGN
    
    # Process executable files
    file_hash = compute_hash(path)
    cached = get_cached_verdict(file_hash)

    with Timer() as t:
        verdict, source = decide(path, cached)

    store_verdict(file_hash, int(verdict))
    log_decision(
        file_path=path,
        file_hash=file_hash,
        source=source,
        verdict=verdict,
        elapsed_ms=t.ms,
    )

    if verdict == Verdict.MALICIOUS:
        q_path = quarantine_file(path, file_hash)
        log_quarantine(path, q_path)

    return verdict

