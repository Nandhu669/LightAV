"""
Generate Realistic Test Malware Hashes
Create test dataset when download is not available
"""

import hashlib
import csv
import random
from pathlib import Path
from datetime import datetime, timedelta


def generate_realistic_malware_hashes(count: int = 10000, output_file: str = "data/malwarebazaar_generated.csv"):
    """
    Generate realistic malware hashes for testing.
    
    These are random but valid-format hashes that simulate
    a real malware database for testing purposes.
    
    Args:
        count: Number of hashes to generate
        output_file: Output CSV file
    """
    print(f"[Generator] Creating {count} realistic malware hashes...")
    
    # Common malware families
    malware_types = [
        'Trojan', 'Ransomware', 'Worm', 'Spyware', 'Adware',
        'Backdoor', 'Rootkit', 'Keylogger', 'Botnet', 'Banker'
    ]
    
    entries = []
    
    # Generate hashes
    for i in range(count):
        # Create a random seed based on index
        random.seed(i * 12345)
        
        # Generate fake file content hash
        fake_content = f"malware_sample_{i}_{random.randint(1000000, 9999999)}".encode()
        
        md5 = hashlib.md5(fake_content).hexdigest()
        sha256 = hashlib.sha256(fake_content).hexdigest()
        sha1 = hashlib.sha1(fake_content).hexdigest()
        
        # Generate realistic timestamp
        days_ago = random.randint(0, 365)
        first_seen = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")
        
        # Random malware type
        threat_type = random.choice(malware_types)
        
        entries.append({
            'first_seen': first_seen,
            'md5': md5,
            'sha256': sha256,
            'sha1': sha1,
            'threat_type': threat_type
        })
        
        if (i + 1) % 1000 == 0:
            print(f"[Generator] Generated {i + 1}/{count} hashes...")
    
    # Save to CSV
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['first_seen', 'md5', 'sha256', 'sha1', 'threat_type'])
        writer.writeheader()
        writer.writerows(entries)
    
    print(f"[Generator] Created {count} hashes in {output_file}")
    return output_path


def import_to_lightav_db(csv_file: str = "data/malwarebazaar_generated.csv"):
    """Import generated hashes to LightAV database."""
    print(f"\n[Import] Importing hashes to LightAV database...")
    
    try:
        import sys
        sys.path.insert(0, '.')
        from production.agent.hash_database import HashDatabase
        
        db = HashDatabase()
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            hashes_to_add = []
            
            for row in reader:
                hashes_to_add.append((
                    row['md5'],
                    row['sha256'],
                    row['threat_type'],
                    'generated_test'
                ))
            
            # Batch import
            added = db.add_hashes_batch(hashes_to_add, batch_size=1000)
            print(f"[Import] Successfully imported {added} hashes to database")
            
            # Show stats
            stats = db.get_stats()
            print(f"[Import] Total hashes in database: {stats['total_hashes']}")
            
    except Exception as e:
        print(f"[Import] Error: {e}")


def main():
    """Generate hashes and import to database."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate test malware hashes")
    parser.add_argument('--count', type=int, default=10000,
                       help='Number of hashes to generate')
    parser.add_argument('--import-db', action='store_true',
                       help='Import to LightAV database')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Malware Hash Generator")
    print("=" * 60)
    print(f"\nGenerating {args.count} realistic malware hashes...")
    print("Note: These are test hashes for development purposes\n")
    
    # Generate hashes
    csv_file = generate_realistic_malware_hashes(args.count)
    
    # Import to database
    if args.import_db:
        import_to_lightav_db(str(csv_file))
    
    print("\n" + "=" * 60)
    print("Done! You can now use these hashes for testing.")
    print(f"File: {csv_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
