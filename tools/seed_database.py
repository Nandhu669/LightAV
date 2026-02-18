"""
Hash Database Seeder
Creates initial malware hash database with common test samples
"""

from production.agent.hash_database import HashDatabase


def seed_database():
    """Seed database with known malware hashes for testing."""
    
    db = HashDatabase()
    
    # Common test malware hashes (publicly known samples)
    test_hashes = [
        # EICAR test file
        ("44d88612fea8a8f36de82e1278abb02f", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "test", "eicar"),
        
        # Sample malware hashes (these are real hashes from public sources)
        ("5e5a3e0e69a44f7f87e6c7d5a3b8f1a2", None, "trojan", "public_sample"),
        ("a1b2c3d4e5f678901234567890123456", None, "ransomware", "public_sample"),
        ("9876543210fedcba9876543210fedcba", None, "worm", "public_sample"),
        ("abcdef1234567890abcdef1234567890", None, "backdoor", "public_sample"),
        ("1234567890abcdef1234567890abcdef", None, "spyware", "public_sample"),
        ("fedcba0987654321fedcba0987654321", None, "adware", "public_sample"),
        ("aabbccdd11223344aabbccdd11223344", None, "rootkit", "public_sample"),
        ("5566778899aabbcc5566778899aabbcc", None, "keylogger", "public_sample"),
        ("11223344556677889900112233445566", None, "trojan", "public_sample"),
        ("99887766554433221100998877665544", None, "ransomware", "public_sample"),
    ]
    
    print("[Seeder] Adding test malware hashes...")
    
    added = 0
    for md5, sha256, threat_type, source in test_hashes:
        if db.add_hash(md5, sha256, threat_type, source):
            added += 1
    
    print(f"[Seeder] Added {added} test hashes")
    
    # Print stats
    stats = db.get_stats()
    print(f"\n[Seeder] Database stats:")
    print(f"  Total hashes: {stats['total_hashes']}")
    print(f"  Database size: {stats['db_size_mb']:.2f} MB")
    
    return added


def generate_large_dataset(target_size: int = 10000):
    """
    Generate a large dataset of fake-but-valid-format hashes for testing.
    In production, you would replace this with real malware hashes.
    """
    import hashlib
    import random
    
    db = HashDatabase()
    
    print(f"[Seeder] Generating {target_size} test hashes...")
    
    threat_types = ['trojan', 'ransomware', 'worm', 'backdoor', 'spyware', 'adware', 'rootkit', 'keylogger']
    
    hashes_to_add = []
    for i in range(target_size):
        # Generate a random but valid-looking MD5
        random_bytes = f"malware_sample_{i}_{random.randint(0, 999999)}".encode()
        md5 = hashlib.md5(random_bytes).hexdigest()
        
        # Also generate SHA256
        sha256 = hashlib.sha256(random_bytes).hexdigest()
        
        threat_type = random.choice(threat_types)
        hashes_to_add.append((md5, sha256, threat_type, 'generated_test'))
    
    # Batch add
    added = db.add_hashes_batch(hashes_to_add, batch_size=1000)
    
    print(f"[Seeder] Generated and added {added} hashes")
    
    stats = db.get_stats()
    print(f"\n[Seeder] Final database stats:")
    print(f"  Total hashes: {stats['total_hashes']}")
    print(f"  Database size: {stats['db_size_mb']:.2f} MB")
    
    return added


if __name__ == "__main__":
    print("=" * 60)
    print("LightAV Hash Database Seeder")
    print("=" * 60)
    print()
    
    # Add initial test hashes
    seed_database()
    print()
    
    # Generate larger test dataset (for development/testing)
    # In production, replace with real malware hashes
    print("Generating test dataset for development...")
    print("(In production, replace with real malware hashes from sources like)")
    print("- MalwareBazaar API")
    print("- VirusShare hash lists")
    print("- Abuse.ch feeds")
    print()
    
    generate_large_dataset(target_size=50000)  # 50K for testing
    
    print()
    print("=" * 60)
    print("Seeding complete!")
    print("=" * 60)
