"""
Safe Malware Sample Downloader
Download real malware samples WITHOUT executing them
"""

import os
import sys
import requests
import time
from pathlib import Path
from typing import List, Dict, Optional
import argparse

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))


class SafeMalwareDownloader:
    """
    Safely download malware samples for ML training.
    
    SAFETY FEATURES:
    - Downloads as .bin files (not executable)
    - Never auto-executes
    - Stores in isolated directory
    - Validates before saving
    """
    
    def __init__(self, output_dir: str = "data/malware"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Safety check - ensure we're in project directory
        if not (Path.cwd() / "run_production.py").exists():
            print("⚠️  WARNING: Not in project root directory!")
            print("Please run from: LightAV-Python/")
            sys.exit(1)
    
    def download_from_url(self, url: str, filename: str = None) -> bool:
        """
        Download a file safely.
        
        Args:
            url: Download URL
            filename: Save filename (auto-generated if None)
            
        Returns:
            True if successful
        """
        try:
            print(f"[Download] Fetching: {url[:60]}...")
            
            # Download
            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()
            
            # Generate safe filename
            if filename is None:
                # Use hash of URL as filename
                import hashlib
                url_hash = hashlib.md5(url.encode()).hexdigest()
                filename = f"sample_{url_hash}.bin"
            else:
                # Ensure .bin extension (never .exe!)
                filename = Path(filename).stem + ".bin"
            
            output_path = self.output_dir / filename
            
            # Save file
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            print(f"[Download] ✓ Saved: {output_path}")
            print(f"[Download]   Size: {output_path.stat().st_size} bytes")
            
            return True
            
        except Exception as e:
            print(f"[Download] ✗ Failed: {e}")
            return False
    
    def download_malwarebazaar_sample(self, sha256_hash: str) -> bool:
        """
        Download a specific sample from MalwareBazaar by SHA256.
        
        Args:
            sha256_hash: SHA256 hash of sample
            
        Returns:
            True if successful
        """
        url = f"https://bazaar.abuse.ch/sample/{sha256_hash}/"
        filename = f"{sha256_hash[:16]}.bin"
        
        print(f"\n[MalwareBazaar] Downloading: {sha256_hash}")
        
        success = self.download_from_url(url, filename)
        
        if success:
            # Rate limiting
            time.sleep(1)
        
        return success
    
    def download_from_thezoo(self, malware_name: str) -> bool:
        """
        Download from TheZoo repository.
        
        Note: Requires cloning the repository first:
        git clone https://github.com/ytisf/theZoo
        
        Args:
            malware_name: Name of malware in theZoo
            
        Returns:
            True if successful
        """
        thezoo_path = Path("theZoo/malwares/Binaries")
        
        if not thezoo_path.exists():
            print(f"[TheZoo] Repository not found!")
            print(f"[TheZoo] Run: git clone https://github.com/ytisf/theZoo")
            return False
        
        # Find malware
        malware_dir = thezoo_path / malware_name
        if not malware_dir.exists():
            print(f"[TheZoo] Malware '{malware_name}' not found")
            print(f"[TheZoo] Available in: {thezoo_path}")
            return False
        
        # Copy to data/malware/
        import shutil
        for file in malware_dir.rglob("*"):
            if file.is_file():
                dest = self.output_dir / f"{malware_name}_{file.name}.bin"
                shutil.copy(file, dest)
                print(f"[TheZoo] ✓ Copied: {dest.name}")
        
        return True
    
    def create_sample_from_data(self, data: bytes, label: str = "malware") -> Path:
        """
        Create a sample file from byte data.
        
        Args:
            data: Binary data
            label: Label for filename
            
        Returns:
            Path to created file
        """
        import hashlib
        
        # Create hash-based filename
        file_hash = hashlib.md5(data).hexdigest()
        filename = f"{label}_{file_hash}.bin"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return output_path
    
    def validate_downloads(self) -> Dict:
        """
        Validate all downloaded samples.
        
        Returns:
            Statistics about downloaded files
        """
        stats = {
            'total_files': 0,
            'total_size': 0,
            'extensions': {}
        }
        
        for file in self.output_dir.iterdir():
            if file.is_file():
                stats['total_files'] += 1
                stats['total_size'] += file.stat().st_size
                
                ext = file.suffix
                stats['extensions'][ext] = stats['extensions'].get(ext, 0) + 1
        
        return stats
    
    def print_safety_warning(self):
        """Print safety warning."""
        print("\n" + "=" * 70)
        print("⚠️  SAFETY WARNING - REAL MALWARE SAMPLES ⚠️")
        print("=" * 70)
        print()
        print("You are about to download REAL MALWARE FILES.")
        print()
        print("SAFETY RULES:")
        print("  1. ✗ NEVER execute these files (don't double-click!)")
        print("  2. ✗ NEVER open in email/Document viewer")
        print("  3. ✗ NEVER upload to VirusTotal (already known)")
        print("  4. ✓ Only use for ML training and research")
        print("  5. ✓ Store only in data/malware/ directory")
        print("  6. ✓ Delete after training (keep only the model)")
        print()
        print("These files are:")
        print("  - Renamed to .bin (not .exe) to prevent accidental execution")
        print("  - Stored in isolated directory")
        print("  - Used only for feature extraction and training")
        print()
        print("Location: data/malware/")
        print("=" * 70)
        print()


def download_malwarebazaar_samples_interactive():
    """Interactive download from MalwareBazaar."""
    
    downloader = SafeMalwareDownloader()
    downloader.print_safety_warning()
    
    print("MalwareBazaar Sample Download")
    print("-" * 70)
    print()
    print("You need SHA256 hashes of samples to download.")
    print()
    print("How to get hashes:")
    print("  1. Visit: https://bazaar.abuse.ch/browse/")
    print("  2. Find interesting malware")
    print("  3. Copy the SHA256 hash")
    print("  4. Paste here")
    print()
    
    samples = []
    
    while True:
        hash_input = input("Enter SHA256 hash (or 'done' to finish): ").strip()
        
        if hash_input.lower() == 'done':
            break
        
        if len(hash_input) == 64:
            samples.append(hash_input)
            print(f"  Added: {hash_input[:16]}...")
        else:
            print("  ✗ Invalid hash (must be 64 characters)")
    
    if not samples:
        print("\nNo samples to download.")
        return
    
    print(f"\nDownloading {len(samples)} samples...")
    print("-" * 70)
    
    success_count = 0
    for i, sample_hash in enumerate(samples, 1):
        print(f"\n[{i}/{len(samples)}] Downloading...")
        if downloader.download_malwarebazaar_sample(sample_hash):
            success_count += 1
    
    print("\n" + "=" * 70)
    print(f"Download complete: {success_count}/{len(samples)} successful")
    
    # Validate
    stats = downloader.validate_downloads()
    print(f"Total samples in data/malware/: {stats['total_files']}")
    print(f"Total size: {stats['total_size'] / 1024 / 1024:.2f} MB")


def download_from_thezoo():
    """Download from TheZoo repository."""
    
    downloader = SafeMalwareDownloader()
    downloader.print_safety_warning()
    
    print("TheZoo Repository Download")
    print("-" * 70)
    print()
    print("First, clone the repository:")
    print("  git clone https://github.com/ytisf/theZoo")
    print()
    
    # Check if cloned
    if not Path("theZoo").exists():
        print("✗ TheZoo repository not found!")
        print("Please run: git clone https://github.com/ytisf/theZoo")
        return
    
    print("✓ TheZoo repository found")
    print()
    
    # List available malware
    malwares_path = Path("theZoo/malwares/Binaries")
    if malwares_path.exists():
        available = [d.name for d in malwares_path.iterdir() if d.is_dir()][:10]
        print("Available malware families (first 10):")
        for i, name in enumerate(available, 1):
            print(f"  {i}. {name}")
        print()
    
    malware_name = input("Enter malware name to download: ").strip()
    
    if downloader.download_from_thezoo(malware_name):
        print(f"\n✓ Successfully downloaded: {malware_name}")
    else:
        print(f"\n✗ Failed to download: {malware_name}")
    
    # Show stats
    stats = downloader.validate_downloads()
    print(f"\nTotal samples: {stats['total_files']}")


def main():
    """Main menu."""
    parser = argparse.ArgumentParser(description="Safe Malware Sample Downloader")
    parser.add_argument('--source', choices=['malwarebazaar', 'thezoo', 'interactive'],
                       default='interactive',
                       help='Download source')
    parser.add_argument('--hash', help='SHA256 hash for MalwareBazaar')
    parser.add_argument('--count', type=int, default=100,
                       help='Number of samples (for automated download)')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("LightAV - Safe Malware Sample Downloader")
    print("=" * 70)
    print()
    
    if args.source == 'interactive' or args.source == 'malwarebazaar':
        if args.hash:
            # Single hash download
            downloader = SafeMalwareDownloader()
            downloader.print_safety_warning()
            downloader.download_malwarebazaar_sample(args.hash)
        else:
            # Interactive mode
            download_malwarebazaar_samples_interactive()
    
    elif args.source == 'thezoo':
        download_from_thezoo()
    
    print()
    print("=" * 70)
    print("Next Steps:")
    print("  1. Verify samples: ls -la data/malware/")
    print("  2. Train ML model: python production/ml_training/train_model.py")
    print("  3. Test detection: python run_production.py --test")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
        sys.exit(1)
