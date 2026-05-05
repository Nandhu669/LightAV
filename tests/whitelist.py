"""
Whitelisting System
Reduce false positives by whitelisting known good files
"""

import sqlite3
import hashlib
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime


@dataclass
class WhitelistEntry:
    """Entry in the whitelist database."""
    file_hash: str
    file_path: str
    source: str  # 'microsoft', 'vendor', 'user', 'auto'
    confidence: float
    date_added: str
    description: str


class WhitelistDB:
    """
    Database for whitelisted (known good) files.
    
    Helps reduce false positives by maintaining a database
    of files known to be benign.
    """
    
    def __init__(self, db_path: str = "data/whitelist.db"):
        """
        Initialize whitelist database.
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self._init_db()
        self.stats = {'queries': 0, 'hits': 0}
    
    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT UNIQUE NOT NULL,
                file_path TEXT,
                source TEXT DEFAULT 'user',
                confidence REAL DEFAULT 1.0,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                hit_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_hash ON whitelist(file_hash)
        ''')
        
        conn.commit()
        conn.close()
    
    def is_whitelisted(self, file_hash: str) -> bool:
        """
        Check if file hash is in whitelist.
        
        Args:
            file_hash: SHA256 hash of file
            
        Returns:
            True if file is whitelisted
        """
        self.stats['queries'] += 1
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT 1 FROM whitelist WHERE file_hash = ?",
            (file_hash.lower(),)
        )
        result = cursor.fetchone() is not None
        
        if result:
            self.stats['hits'] += 1
            # Update hit count
            cursor.execute(
                "UPDATE whitelist SET hit_count = hit_count + 1 WHERE file_hash = ?",
                (file_hash.lower(),)
            )
            conn.commit()
        
        conn.close()
        return result
    
    def add_to_whitelist(self, file_path: str, 
                        source: str = 'user',
                        confidence: float = 1.0,
                        description: str = '') -> bool:
        """
        Add a file to the whitelist.
        
        Args:
            file_path: Path to file
            source: Source of whitelist entry ('microsoft', 'vendor', 'user', 'auto')
            confidence: Confidence that file is benign (0.0-1.0)
            description: Optional description
            
        Returns:
            True if added successfully
        """
        try:
            # Calculate hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO whitelist 
                (file_hash, file_path, source, confidence, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_hash.lower(), file_path, source, confidence, description))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"[Whitelist] Error adding file: {e}")
            return False
    
    def add_hash_to_whitelist(self, file_hash: str,
                             source: str = 'user',
                             confidence: float = 1.0,
                             description: str = '') -> bool:
        """
        Add a hash directly to the whitelist.
        
        Args:
            file_hash: SHA256 hash
            source: Source of entry
            confidence: Confidence level
            description: Description
            
        Returns:
            True if added successfully
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO whitelist 
                (file_hash, file_path, source, confidence, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_hash.lower(), '', source, confidence, description))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"[Whitelist] Error adding hash: {e}")
            return False
    
    def remove_from_whitelist(self, file_hash: str) -> bool:
        """
        Remove a file from the whitelist.
        
        Args:
            file_hash: SHA256 hash to remove
            
        Returns:
            True if removed
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "DELETE FROM whitelist WHERE file_hash = ?",
                (file_hash.lower(),)
            )
            
            removed = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return removed
            
        except Exception as e:
            print(f"[Whitelist] Error removing hash: {e}")
            return False
    
    def get_whitelist_info(self, file_hash: str) -> Optional[Dict]:
        """
        Get detailed info about a whitelisted file.
        
        Args:
            file_hash: File hash to look up
            
        Returns:
            Dictionary with info or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_hash, file_path, source, confidence, 
                   date_added, description, hit_count
            FROM whitelist WHERE file_hash = ?
        ''', (file_hash.lower(),))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'file_hash': row[0],
                'file_path': row[1],
                'source': row[2],
                'confidence': row[3],
                'date_added': row[4],
                'description': row[5],
                'hit_count': row[6]
            }
        return None
    
    def get_all_whitelisted(self, limit: int = 1000) -> List[Dict]:
        """
        Get all whitelisted entries.
        
        Args:
            limit: Maximum number of entries
            
        Returns:
            List of whitelist entries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_hash, file_path, source, confidence, 
                   date_added, description, hit_count
            FROM whitelist
            ORDER BY hit_count DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'file_hash': row[0],
                'file_path': row[1],
                'source': row[2],
                'confidence': row[3],
                'date_added': row[4],
                'description': row[5],
                'hit_count': row[6]
            })
        
        conn.close()
        return results
    
    def import_microsoft_signatures(self):
        """
        Import common Windows/Microsoft file signatures.
        This helps reduce false positives on system files.
        """
        # Common Windows system file hashes (these are examples)
        # In production, you would download the official Microsoft catalog
        microsoft_hashes = [
            # Common Windows executables
            ("a9488b9c3e9e2e1e0f5b9d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6", "notepad.exe", "microsoft"),
            ("b0598c8d3e8d1d0e0e4a8c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809", "calc.exe", "microsoft"),
            # Add more as needed
        ]
        
        added = 0
        for file_hash, filename, source in microsoft_hashes:
            if self.add_hash_to_whitelist(
                file_hash, 
                source=source,
                confidence=1.0,
                description=f"Microsoft Windows - {filename}"
            ):
                added += 1
        
        print(f"[Whitelist] Imported {added} Microsoft signatures")
    
    def get_stats(self) -> Dict:
        """Get whitelist statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM whitelist")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT source, COUNT(*) FROM whitelist GROUP BY source")
        by_source = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_entries': total,
            'by_source': by_source,
            'queries': self.stats['queries'],
            'hits': self.stats['hits'],
            'hit_rate': self.stats['hits'] / max(self.stats['queries'], 1)
        }
    
    def export_to_file(self, output_path: str):
        """Export whitelist to JSON file."""
        import json
        
        entries = self.get_all_whitelisted(limit=10000)
        
        with open(output_path, 'w') as f:
            json.dump(entries, f, indent=2)
        
        print(f"[Whitelist] Exported {len(entries)} entries to {output_path}")
    
    def import_from_file(self, input_path: str):
        """Import whitelist from JSON file."""
        import json
        
        with open(input_path, 'r') as f:
            entries = json.load(f)
        
        added = 0
        for entry in entries:
            if self.add_hash_to_whitelist(
                entry['file_hash'],
                source=entry.get('source', 'imported'),
                confidence=entry.get('confidence', 1.0),
                description=entry.get('description', '')
            ):
                added += 1
        
        print(f"[Whitelist] Imported {added} entries from {input_path}")


# Convenience function
def check_whitelist(file_hash: str, db_path: str = "data/whitelist.db") -> bool:
    """Quick check if hash is whitelisted."""
    db = WhitelistDB(db_path)
    return db.is_whitelisted(file_hash)


if __name__ == "__main__":
    print("=" * 60)
    print("Whitelist System Test")
    print("=" * 60)
    print()
    
    db = WhitelistDB()
    
    # Test adding
    print("Adding test hashes...")
    test_hashes = [
        "a" * 64,
        "b" * 64,
        "c" * 64
    ]
    
    for i, hash_val in enumerate(test_hashes):
        db.add_hash_to_whitelist(
            hash_val,
            source='test',
            description=f'Test hash {i+1}'
        )
    
    print(f"Added {len(test_hashes)} test hashes")
    print()
    
    # Test checking
    print("Checking hashes...")
    for hash_val in test_hashes:
        is_whitelisted = db.is_whitelisted(hash_val)
        print(f"  {hash_val[:16]}... : {'WHITELISTED' if is_whitelisted else 'NOT FOUND'}")
    
    # Check unknown hash
    unknown = "z" * 64
    print(f"  {unknown[:16]}... : {'WHITELISTED' if db.is_whitelisted(unknown) else 'NOT FOUND'}")
    
    print()
    print("Stats:")
    stats = db.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print()
    print("Test complete!")
