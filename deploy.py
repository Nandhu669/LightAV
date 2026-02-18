#!/usr/bin/env python3
"""
Production Deployment Helper
Guide you through deploying LightAV with real malware detection
"""

import os
import sys
import subprocess
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_section(title):
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")

def print_success(msg):
    print(f"{Colors.GREEN}[OK] {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!] {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}[FAIL] {msg}{Colors.END}")

def check_prerequisites():
    """Check if system is ready for deployment."""
    print_section("STEP 1: Checking Prerequisites")
    
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 10):
        print_error("Python 3.10+ required")
        issues.append("Python version")
    else:
        print_success(f"Python {sys.version_info.major}.{sys.version_info.minor}")
    
    # Check if running on Windows
    if sys.platform != 'win32':
        print_warning("Not Windows - some features unavailable")
    else:
        print_success("Windows detected")
    
    # Check admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print_success("Running as Administrator")
        else:
            print_warning("Not running as Administrator (some features limited)")
    except:
        pass
    
    # Check dependencies
    try:
        import psutil
        import pefile
        import numpy
        print_success("Core dependencies installed")
    except ImportError as e:
        print_error(f"Missing dependency: {e}")
        issues.append("Dependencies")
    
    # Check data directories
    dirs_to_check = ['data', 'data/malware', 'data/benign', 'production/testing/results']
    for dir_path in dirs_to_check:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        if Path(dir_path).exists():
            print_success(f"Directory ready: {dir_path}")
        else:
            print_error(f"Cannot create: {dir_path}")
            issues.append(f"Directory: {dir_path}")
    
    if issues:
        print(f"\n{Colors.YELLOW}Please fix {len(issues)} issue(s) before continuing{Colors.END}")
        return False
    
    print(f"\n{Colors.GREEN}[OK] All prerequisites met!{Colors.END}")
    return True

def guide_malware_collection():
    """Guide user through collecting malware samples."""
    print_section("STEP 2: Collect Malware Samples")
    
    print("""
To achieve >90% detection rate, you need REAL malware samples.

Options to collect samples:

1. MalwareBazaar (Recommended - Free)
   Visit: https://bazaar.abuse.ch/
   - Download recent malware samples
   - Place in: data/malware/
   - Need: 5,000+ samples minimum

2. VirusShare (Free, requires registration)
   Visit: https://virusshare.com/
   - Download malware packages
   - Extract to: data/malware/

3. TheZoo (GitHub repository)
   git clone https://github.com/ytisf/theZoo
   - Contains malware samples for research

4. Your own malware collection
   - If you have existing samples
   - Copy to: data/malware/

IMPORTANT:
- Only download for research/educational purposes
- Keep samples isolated (don't run them!)
- Ensure you have 5,000+ unique samples
- Include various types: trojans, ransomware, worms, etc.
""")
    
    # Check current samples
    malware_dir = Path("data/malware")
    if malware_dir.exists():
        count = sum(1 for _ in malware_dir.rglob("*") if _.is_file())
        if count > 0:
            print(f"\n{Colors.GREEN}You currently have {count} samples in data/malware/{Colors.END}")
            if count < 5000:
                print(f"{Colors.YELLOW}Need {5000 - count} more samples for optimal training{Colors.END}")
        else:
            print(f"\n{Colors.RED}No samples found in data/malware/{Colors.END}")
    
    input(f"\n{Colors.BLUE}Press Enter when you have collected malware samples...{Colors.END}")

def guide_benign_collection():
    """Guide user through collecting benign samples."""
    print_section("STEP 3: Collect Benign Samples")
    
    print("""
You also need BENIGN (clean) files for training.

The system will automatically use:
- Windows system files (C:\Windows\System32)
- Program Files directories

For additional training, you can collect:
1. Installed applications
2. Known good software
3. Your own compiled programs

Place additional benign samples in: data/benign/

Note: System files are sufficient for most cases.
""")
    
    # Check Windows system files
    sys32 = Path(r"C:\Windows\System32")
    if sys32.exists():
        print(f"\n{Colors.GREEN}Windows system files available: {sys32}{Colors.END}")
    
    benign_dir = Path("data/benign")
    if benign_dir.exists():
        count = sum(1 for _ in benign_dir.rglob("*") if _.is_file())
        if count > 0:
            print(f"{Colors.GREEN}Additional benign samples: {count}{Colors.END}")

def train_model_guide():
    """Guide user through model training."""
    print_section("STEP 4: Train ML Model")
    
    malware_dir = Path("data/malware")
    benign_dir = Path("data/benign")
    
    # Count samples
    malware_count = sum(1 for _ in malware_dir.rglob("*") if _.is_file()) if malware_dir.exists() else 0
    benign_count = sum(1 for _ in benign_dir.rglob("*") if _.is_file()) if benign_dir.exists() else 0
    
    print(f"Current sample counts:")
    print(f"  Malware: {malware_count}")
    print(f"  Benign: {benign_count}")
    print()
    
    if malware_count < 100:
        print_error("Not enough malware samples (<100)")
        print("Please collect more samples before training")
        return False
    
    print("Ready to train ML model!")
    print()
    print("This will:")
    print("  1. Extract features from all samples")
    print("  2. Train LightGBM classifier")
    print("  3. Evaluate model performance")
    print("  4. Export to ONNX format")
    print()
    
    response = input(f"{Colors.BLUE}Start training now? (y/n): {Colors.END}").lower()
    
    if response == 'y':
        print("\nStarting training...")
        try:
            result = subprocess.run([
                sys.executable,
                "production/ml_training/train_model.py",
                "--malware-dir", str(malware_dir),
                "--benign-dir", str(benign_dir),
                "--limit", "5000"
            ], capture_output=False)
            
            if result.returncode == 0:
                print_success("Training completed!")
                return True
            else:
                print_error("Training failed")
                return False
        except Exception as e:
            print_error(f"Error during training: {e}")
            return False
    else:
        print("Training skipped")
        return False

def test_deployment():
    """Test the deployment."""
    print_section("STEP 5: Test Deployment")
    
    print("Running comprehensive tests...")
    print()
    
    try:
        # Test basic functionality
        result = subprocess.run([
            sys.executable,
            "run_production.py",
            "--test"
        ], capture_output=True, text=True)
        
        if "Self-test complete" in result.stdout:
            print_success("Basic functionality test passed")
        else:
            print_error("Basic test failed")
            print(result.stdout)
            print(result.stderr)
    except Exception as e:
        print_error(f"Test error: {e}")
    
    # Test scan
    test_file = r"C:\Windows\System32\notepad.exe"
    if Path(test_file).exists():
        print(f"\nTesting scan on: {test_file}")
        try:
            result = subprocess.run([
                sys.executable,
                "run_production.py",
                "--scan", test_file
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print_success("Scan test passed")
            else:
                print_error("Scan test failed")
        except Exception as e:
            print_error(f"Scan error: {e}")

def install_service_guide():
    """Guide user through service installation."""
    print_section("STEP 6: Install as Windows Service (Optional)")
    
    print("""
To run LightAV continuously in the background:

1. Install as Windows Service:
   python production/service_wrapper.py install

2. Start the service:
   python production/service_wrapper.py start

3. Check status:
   python production/service_wrapper.py status

Or use the simpler auto-start method:
   python tools/installer.py install

This will start LightAV automatically when Windows boots.
""")
    
    response = input(f"\n{Colors.BLUE}Install auto-start now? (y/n): {Colors.END}").lower()
    
    if response == 'y':
        try:
            result = subprocess.run([
                sys.executable,
                "tools/installer.py",
                "install"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print_success("Auto-start installed!")
            else:
                print_error("Installation failed")
                print(result.stderr)
        except Exception as e:
            print_error(f"Installation error: {e}")

def main():
    """Main deployment workflow."""
    print(f"""
{Colors.GREEN}
============================================================
                                                            
          LightAV Production Deployment Helper             
                                                            
============================================================
{Colors.END}
""")
    
    print("This script will guide you through deploying LightAV in production.")
    print("We'll go through 6 steps to get you up and running.")
    print()
    
    # Step 1: Prerequisites
    if not check_prerequisites():
        print_error("Please fix prerequisites and run again")
        return
    
    # Step 2: Malware Collection
    guide_malware_collection()
    
    # Step 3: Benign Collection
    guide_benign_collection()
    
    # Step 4: Train Model
    malware_count = sum(1 for _ in Path("data/malware").rglob("*") if _.is_file()) if Path("data/malware").exists() else 0
    if malware_count >= 100:
        train_model_guide()
    else:
        print_warning("Skipping model training (not enough samples)")
    
    # Step 5: Test
    test_deployment()
    
    # Step 6: Install Service
    install_service_guide()
    
    # Summary
    print_section("Deployment Summary")
    
    print(f"""
{Colors.GREEN}Deployment preparation complete!{Colors.END}

Next steps:
1. Place malware samples in: data/malware/
2. Run: python production/ml_training/train_model.py
3. Test: python run_production.py --test
4. Deploy: python tools/installer.py install

Commands for daily use:
  Scan file:     python run_production.py --scan file.exe
  Scan folder:   python run_production.py --scan "C:\\Users\\Name\\Downloads"
  Show stats:    python run_production.py --stats
  Run tests:     python production/testing/test_framework.py

For help: python run_production.py --help
""")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Interrupted by user{Colors.END}")
        sys.exit(1)
