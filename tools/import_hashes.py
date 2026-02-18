"""
Hash Importer Tool
Downloads and imports malware hashes from public sources
"""

import requests
import sqlite3
import csv
import io
import time
from pathlib import Path
from tqdm import tqdm
from production.agent.hash_database import HashDatabase


class HashImporter:
    """Import malware hashes from various public sources."""
    
    def __init__(self, db_path: str = "data/malware_hashes.db"):
        self.db = HashDatabase(db_path)
        self.stats = {
            'malwarebazaar': 0,
            'virusshare': 0,
            'total_added': 0,
            'total_skipped': 0
        }
    
    def import_malwarebazaar(self, limit: int = 100000) -> int:
        """
        Download recent hashes from MalwareBazaar.
        
        Args:
            limit: Maximum number of hashes to import
            
        Returns:
            Number of hashes added
        """
        print("[Importer] Downloading MalwareBazaar hash list...")
        
        try:
            # MalwareBazaar provides a CSV export
            url = "https://bazaar.abuse.ch/export/csv/md5/recent/"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV (skip header comments)
            hashes_to_add = []
            lines = response.text.split('\n')
            
            for line in lines:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(',')
                if len(parts) >= 5:
                    first_seen = parts[0].strip('"')
                    md5 = parts[1].strip('"')
                    sha256 = parts[2].strip('"')
                    sha1 = parts[3].strip('"')
                    threat_type = parts[4].strip('"')
                    
                    # Validate MD5
                    if len(md5) == 32:
                        hashes_to_add.append((md5, sha256, threat_type, 'malwarebazaar'))
                
                if len(hashes_to_add) >= limit:
                    break
            
            print(f"[Importer] Found {len(hashes_to_add)} hashes from MalwareBazaar")
            
            # Batch import
            added = self.db.add_hashes_batch(hashes_to_add)
            self.stats['malwarebazaar'] = added
            self.stats['total_added'] += added
            
            print(f"[Importer] Added {added} new hashes from MalwareBazaar")
            return added
            
        except requests.RequestException as e:
            print(f"[Importer] Error downloading from MalwareBazaar: {e}")
            return 0
        except Exception as e:
            print(f"[Importer] Unexpected error: {e}")
            return 0
    
    def import_virusshare(self, hash_file_path: str = None, limit: int = 500000) -> int:
        """
        Import hashes from VirusShare hash lists.
        
        Note: VirusShare requires registration to download hash lists.
        This method assumes you have downloaded the hash file manually.
        
        Args:
            hash_file_path: Path to VirusShare hash list file
            limit: Maximum number of hashes to import
            
        Returns:
            Number of hashes added
        """
        if not hash_file_path or not Path(hash_file_path).exists():
            print("[Importer] VirusShare hash file not found. Skipping.")
            print("[Importer] Download from: https://virusshare.com/hashes.4n6")
            return 0
        
        print(f"[Importer] Importing from VirusShare file: {hash_file_path}")
        
        hashes_to_add = []
        
        try:
            with open(hash_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(tqdm(f, desc="Reading VirusShare hashes")):
                    if i >= limit:
                        break
                    
                    md5 = line.strip().lower()
                    if len(md5) == 32:
                        hashes_to_add.append((md5, None, 'unknown', 'virusshare'))
            
            print(f"[Importer] Found {len(hashes_to_add)} hashes from VirusShare")
            
            # Batch import
            added = self.db.add_hashes_batch(hashes_to_add)
            self.stats['virusshare'] = added
            self.stats['total_added'] += added
            
            print(f"[Importer] Added {added} new hashes from VirusShare")
            return added
            
        except Exception as e:
            print(f"[Importer] Error importing VirusShare hashes: {e}")
            return 0
    
    def import_eicar_test(self) -> int:
        """
        Add EICAR test file hash (standard antivirus test).
        
        Returns:
            1 if added, 0 if already exists
        """
        eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        
        if self.db.add_hash(eicar_md5, eicar_sha256, 'test', 'eicar'):
            print("[Importer] Added EICAR test hash")
            return 1
        else:
            print("[Importer] EICAR test hash already exists")
            return 0
    
    def import_from_file(self, file_path: str, source_name: str = 'custom') -> int:
        """
        Import hashes from a custom text file (one MD5 per line).
        
        Args:
            file_path: Path to text file
            source_name: Source identifier
            
        Returns:
            Number of hashes added
        """
        if not Path(file_path).exists():
            print(f"[Importer] File not found: {file_path}")
            return 0
        
        print(f"[Importer] Importing from {file_path}...")
        
        hashes_to_add = []
        
        with open(file_path, 'r') as f:
            for line in f:
                md5 = line.strip().lower()
                if len(md5) == 32:
                    hashes_to_add.append((md5, None, 'unknown', source_name))
        
        added = self.db.add_hashes_batch(hashes_to_add)
        self.stats['total_added'] += added
        
        print(f"[Importer] Added {added} hashes from {source_name}")
        return added
    
    def get_stats(self) -> dict:
        """Return import statistics."""
        return {
            **self.stats,
            'db_stats': self.db.get_stats()
        }


def main():
    """Main import routine."""
    print("=" * 60)
    print("LightAV Hash Database Importer")
    print("=" * 60)
    print()
    
    importer = HashImporter()
    
    # Import EICAR test hash
    print("Step 1: Adding EICAR test hash...")
    importer.import_eicar_test()
    print()
    
    # Import from MalwareBazaar
    print("Step 2: Importing from MalwareBazaar...")
    mb_added = importer.import_malwarebazaar(limit=100000)
    print()
    
    # Try VirusShare if available
    print("Step 3: Checking for VirusShare hashes...")
    # Look for common VirusShare hash file locations
    vs_paths = [
        "data/virusshare_hashes.txt",
        " VirusShare_00000.md5",
        "hashes/virusshare.md5"
    ]
    
    vs_added = 0
    for vs_path in vs_paths:
        if Path(vs_path).exists():
            vs_added = importer.import_virusshare(vs_path, limit=500000)
            break
    
    if vs_added == 0:
        print("[Importer] No VirusShare hash file found.")
        print("[Importer] To add VirusShare hashes, download from:")
        print("           https://virusshare.com/hashes.4n6")
        print("           and place in data/virusshare_hashes.txt")
    print()
    
    # Final stats
    print("=" * 60)
    print("Import Summary")
    print("=" * 60)
    stats = importer.get_stats()
    print(f"Total hashes added: {stats['total_added']}")
    print(f"  - MalwareBazaar: {stats['malwarebazaar']}")
    print(f"  - VirusShare: {stats['virusshare']}")
    print()
    print(f"Database size: {stats['db_stats']['total_hashes']} hashes")
    print(f"Database file: {stats['db_stats']['db_path']}")
    print(f"File size: {stats['db_stats']['db_size_mb']:.2f} MB")
    print()
    print("Import complete!")


if __name__ == "__main__":
    main()
