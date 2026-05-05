"""
LightAV Hash Cache Module (Phase 3)

SHA-256 hashing and SQLite cache layer for file deduplication.
Avoids reprocessing files that have already been scanned.

Responsibilities:
    - Compute SHA-256 hash of file contents
    - Store scan verdicts in SQLite database
    - Retrieve cached verdicts for known files
    - Crash-safe persistence across restarts
"""

import sqlite3
import hashlib

DB_PATH = "hash_cache.db"


def init_db():
    """Initialize the SQLite database with cache table."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            hash TEXT PRIMARY KEY,
            verdict INTEGER
        )
    """)
    conn.commit()
    conn.close()


def compute_hash(path):
    """
    Compute SHA-256 hash of file contents.
    
    Args:
        path: Path to the file to hash.
        
    Returns:
        Hexadecimal SHA-256 hash string.
    """
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def get_cached_verdict(file_hash):
    """
    Retrieve cached verdict for a file hash.
    
    Args:
        file_hash: SHA-256 hash of file contents.
        
    Returns:
        Cached verdict (0=safe, 1=malicious) or None if not cached.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT verdict FROM cache WHERE hash=?", (file_hash,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def store_verdict(file_hash, verdict):
    """
    Store scan verdict in cache.
    
    Args:
        file_hash: SHA-256 hash of file contents.
        verdict: Scan result (0=safe, 1=malicious).
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO cache VALUES (?, ?)",
        (file_hash, verdict)
    )
    conn.commit()
    conn.close()
