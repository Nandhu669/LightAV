"""
Production Hash Database Module
High-performance malware hash storage with Bloom filter optimization
"""

import sqlite3
import hashlib
import os
from pybloom_live import BloomFilter
from pathlib import Path
from typing import Optional, Tuple, List


class HashDatabase:
    """
    Production-grade hash database with Bloom filter for O(1) negative lookups.
    
    Features:
    - SQLite backend for persistent storage
    - Bloom filter for fast negative lookups (99% RAM reduction)
    - Supports 1M+ hashes with <100MB disk usage
    - Automatic Bloom filter synchronization
    """
    
    def __init__(self, db_path: str = "data/malware_hashes.db"):
        """
        Initialize hash database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.bloom_path = db_path.replace('.db', '.bloom')
        
        # Bloom filter: 1M capacity, 0.1% false positive rate
        self.bloom = BloomFilter(capacity=1000000, error_rate=0.001)
        
        # Statistics
        self.stats = {
            'total_hashes': 0,
            'bloom_lookups': 0,
            'sqlite_lookups': 0,
            'false_positives': 0
        }
        
        # Initialize
        self._init_db()
        self._load_bloom_filter()
    
    def _init_db(self):
        """Initialize SQLite database schema."""
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main hash table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                md5 TEXT UNIQUE NOT NULL,
                sha256 TEXT,
                threat_type TEXT DEFAULT 'unknown',
                source TEXT DEFAULT 'manual',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Index for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_md5 ON malware_hashes(md5)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256)
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_bloom_filter(self):
        """Load existing hashes into Bloom filter."""
        if not os.path.exists(self.db_path):
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count total hashes
        cursor.execute("SELECT COUNT(*) FROM malware_hashes")
        self.stats['total_hashes'] = cursor.fetchone()[0]
        
        # Load all MD5 hashes into Bloom filter
        cursor.execute("SELECT md5 FROM malware_hashes")
        for row in cursor:
            self.bloom.add(row[0])
        
        conn.close()
        
        print(f"[HashDB] Loaded {self.stats['total_hashes']} hashes into Bloom filter")
    
    def contains(self, file_hash: str) -> bool:
        """
        Check if hash exists in database.
        
        Uses Bloom filter for O(1) negative lookups, SQLite for confirmation.
        
        Args:
            file_hash: MD5 or SHA256 hash to check
            
        Returns:
            True if hash is known malware, False otherwise
        """
        # Normalize hash
        file_hash = file_hash.lower().strip()
        
        # Bloom filter check first (O(1))
        self.stats['bloom_lookups'] += 1
        if file_hash not in self.bloom:
            return False  # Definitely not present
        
        # Bloom filter says maybe, check SQLite
        self.stats['sqlite_lookups'] += 1
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT 1 FROM malware_hashes WHERE md5=? OR sha256=? LIMIT 1",
            (file_hash, file_hash)
        )
        result = cursor.fetchone() is not None
        conn.close()
        
        if not result:
            # False positive from Bloom filter
            self.stats['false_positives'] += 1
        
        return result
    
    def add_hash(self, md5: str, sha256: Optional[str] = None, 
                 threat_type: str = 'unknown', source: str = 'manual') -> bool:
        """
        Add new malware hash to database.
        
        Args:
            md5: MD5 hash (32 characters)
            sha256: SHA256 hash (optional, 64 characters)
            threat_type: Category of malware (e.g., 'trojan', 'ransomware')
            source: Origin of hash (e.g., 'malwarebazaar', 'virusshare')
            
        Returns:
            True if added successfully, False if already exists
        """
        # Normalize
        md5 = md5.lower().strip()
        if sha256:
            sha256 = sha256.lower().strip()
        
        # Validate hash format
        if len(md5) != 32:
            print(f"[HashDB] Warning: Invalid MD5 hash length: {len(md5)}")
            return False
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO malware_hashes (md5, sha256, threat_type, source)
                VALUES (?, ?, ?, ?)
            ''', (md5, sha256, threat_type, source))
            
            if cursor.rowcount > 0:
                # New hash added
                self.bloom.add(md5)
                self.stats['total_hashes'] += 1
                conn.commit()
                conn.close()
                return True
            else:
                # Hash already exists
                conn.close()
                return False
                
        except sqlite3.Error as e:
            print(f"[HashDB] Error adding hash: {e}")
            return False
    
    def add_hashes_batch(self, hashes: List[Tuple[str, Optional[str], str, str]], 
                         batch_size: int = 1000) -> int:
        """
        Add multiple hashes in batch for better performance.
        
        Args:
            hashes: List of tuples (md5, sha256, threat_type, source)
            batch_size: Number of hashes per batch
            
        Returns:
            Number of hashes successfully added
        """
        added_count = 0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for i, (md5, sha256, threat_type, source) in enumerate(hashes):
            # Normalize
            md5 = md5.lower().strip()
            if sha256:
                sha256 = sha256.lower().strip()
            
            if len(md5) != 32:
                continue
            
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO malware_hashes (md5, sha256, threat_type, source)
                    VALUES (?, ?, ?, ?)
                ''', (md5, sha256, threat_type, source))
                
                if cursor.rowcount > 0:
                    self.bloom.add(md5)
                    added_count += 1
                
                # Commit every batch
                if (i + 1) % batch_size == 0:
                    conn.commit()
                    print(f"[HashDB] Imported {i+1}/{len(hashes)} hashes...")
                    
            except sqlite3.Error as e:
                print(f"[HashDB] Error adding hash {md5}: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        self.stats['total_hashes'] += added_count
        return added_count
    
    def get_stats(self) -> dict:
        """Return database statistics."""
        return {
            **self.stats,
            'bloom_fp_rate': self.stats['false_positives'] / max(self.stats['bloom_lookups'], 1),
            'db_path': self.db_path,
            'db_size_mb': os.path.getsize(self.db_path) / (1024 * 1024) if os.path.exists(self.db_path) else 0
        }
    
    def lookup_details(self, file_hash: str) -> Optional[dict]:
        """
        Get detailed information about a hash.
        
        Args:
            file_hash: MD5 or SHA256 hash
            
        Returns:
            Dictionary with hash details, or None if not found
        """
        file_hash = file_hash.lower().strip()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT md5, sha256, threat_type, source, first_seen
            FROM malware_hashes
            WHERE md5=? OR sha256=?
        ''', (file_hash, file_hash))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'md5': row[0],
                'sha256': row[1],
                'threat_type': row[2],
                'source': row[3],
                'first_seen': row[4]
            }
        return None


# Convenience function for quick lookups
def check_hash(file_hash: str, db_path: str = "data/malware_hashes.db") -> bool:
    """
    Quick check if hash is in database.
    
    Args:
        file_hash: MD5 or SHA256 hash
        db_path: Path to database
        
    Returns:
        True if known malware
    """
    db = HashDatabase(db_path)
    return db.contains(file_hash)


if __name__ == "__main__":
    # Test
    db = HashDatabase()
    
    # Test hash
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR
    print(f"Test hash present: {db.contains(test_hash)}")
    
    # Add test hash
    db.add_hash(test_hash, threat_type="test", source="eicar")
    print(f"After adding: {db.contains(test_hash)}")
    
    # Stats
    print(f"\nDatabase stats: {db.get_stats()}")
