#!/usr/bin/env python3
"""
LightAV Production Entry Point
Run the production-grade antivirus scanner

Usage:
    python run_production.py                    # Run full system scan
    python run_production.py --scan <path>      # Scan specific file or directory
    python run_production.py --test             # Run self-test
    python run_production.py --stats            # Show statistics
"""

import sys
import argparse
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from production.agent.scanner import ProductionScanner
from production.agent.decision_engine import ProductionDecisionEngine


def print_banner():
    """Print application banner."""
    print("=" * 60)
    print("  LightAV - Production Antivirus Scanner")
    print("  Phase 1: Enhanced Detection Engine")
    print("=" * 60)
    print()


def show_stats():
    """Show current database statistics."""
    print_banner()
    
    print("Loading production engine...")
    engine = ProductionDecisionEngine()
    
    print("\n" + "=" * 60)
    print("Engine Statistics")
    print("=" * 60)
    
    # Layer info
    print("\nDetection Layers:")
    for layer_id, info in engine.get_layer_info().items():
        status_icon = "OK" if info['status'] == 'active' else "NO"
        size_info = f"({info.get('size') or info.get('rules', 'N/A')})"
        print(f"  {status_icon} Layer {layer_id[-1]}: {info['name']:<20} {info['status']:<10} {size_info}")
    
    # Stats
    stats = engine.get_stats()
    print("\nDetection Stats:")
    print(f"  Total scans: {stats['total_scans']}")
    print(f"  Hash hits: {stats['hash_hits']}")
    print(f"  YARA hits: {stats['yara_hits']}")
    print(f"  Heuristic hits: {stats['heuristic_hits']}")
    print(f"  ML hits: {stats['ml_hits']}")
    print(f"  Clean files: {stats['clean']}")
    print(f"  Errors: {stats['errors']}")
    
    if stats['total_scans'] > 0:
        print(f"\nDetection rate: {stats['detection_rate']*100:.2f}%")


def scan_file(file_path: str):
    """Scan a single file."""
    print_banner()
    
    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}")
        return
    
    print(f"Initializing scanner...")
    scanner = ProductionScanner()
    
    print(f"\nScanning: {file_path}")
    print("-" * 60)
    
    start_time = time.time()
    result = scanner.scan_file(file_path, auto_quarantine=False)
    elapsed = (time.time() - start_time) * 1000
    
    print(f"\nResult:")
    print(f"  Verdict: {result.verdict.name}")
    print(f"  Source: {result.source}")
    print(f"  Confidence: {result.confidence*100:.1f}%")
    print(f"  Scan time: {elapsed:.2f}ms")
    
    if result.details:
        print(f"\nDetails:")
        for key, value in result.details.items():
            if key not in ['triggers', 'matches']:
                print(f"  {key}: {value}")


def scan_directory(directory: str, recursive: bool = True):
    """Scan a directory."""
    print_banner()
    
    if not Path(directory).is_dir():
        print(f"Error: Not a directory: {directory}")
        return
    
    print(f"Initializing scanner...")
    scanner = ProductionScanner()
    
    print(f"\nScanning directory: {directory}")
    print(f"Mode: {'Recursive' if recursive else 'Non-recursive'}")
    print("-" * 60)
    
    start_time = time.time()
    results = scanner.scan_directory(directory, recursive, auto_quarantine=False)
    elapsed = time.time() - start_time
    
    print(f"\nScan Complete!")
    print(f"  Files scanned: {results['files_scanned']}")
    print(f"  Threats found: {results['threats_found']}")
    print(f"  Time elapsed: {elapsed:.2f}s")
    
    if results['threats']:
        print(f"\nThreats Detected:")
        for threat in results['threats']:
            print(f"  [!] {threat['path']}")
            print(f"    Source: {threat['source']}, Confidence: {threat['confidence']*100:.1f}%")
    else:
        print("\n[OK] No threats detected")
    
    # Show stats
    print("\n" + "=" * 60)
    print("Scanner Statistics")
    print("=" * 60)
    stats = scanner.get_stats()
    print(f"  Total files: {stats['files_scanned']}")
    print(f"  Threats: {stats['threats_detected']}")
    print(f"  Average scan time: {stats['avg_scan_time_ms']:.2f}ms")
    print(f"  Detection rate: {stats['detection_rate']*100:.2f}%")


def run_self_test():
    """Run self-test to verify engine is working."""
    print_banner()
    
    print("Running self-test...")
    print("-" * 60)
    
    # Test 1: Hash database
    print("\n[1/5] Testing hash database...")
    from production.agent.hash_database import HashDatabase
    db = HashDatabase()
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR
    
    if db.contains(test_hash):
        print("  [OK] Hash database working (EICAR hash found)")
    else:
        print("  [FAIL] Hash database test failed")
    
    # Test 2: YARA engine
    print("\n[2/5] Testing YARA engine...")
    from production.ai_engine.yara_engine import YARAEngine
    yara = YARAEngine()
    
    if yara.rules:
        print(f"  [OK] YARA engine loaded ({len(yara.rule_files)} rule files)")
    else:
        print("  [FAIL] YARA engine failed to load")
    
    # Test 3: Heuristic engine
    print("\n[3/5] Testing heuristic engine...")
    from production.ai_engine.heuristic_engine import EnhancedHeuristicEngine
    heuristics = EnhancedHeuristicEngine()
    
    if len(heuristics.rules) >= 20:
        print(f"  [OK] Heuristic engine loaded ({len(heuristics.rules)} rules)")
    else:
        print(f"  [FAIL] Heuristic engine incomplete ({len(heuristics.rules)} rules)")
    
    # Test 4: Decision engine
    print("\n[4/5] Testing decision engine...")
    try:
        engine = ProductionDecisionEngine()
        print("  [OK] Decision engine initialized")
        print(f"    - Hash DB: {engine.hash_db.stats['total_hashes']} hashes")
        print(f"    - YARA: {len(engine.yara.rule_files)} rule files")
        print(f"    - Heuristics: {len(engine.heuristics.rules)} rules")
    except Exception as e:
        print(f"  [FAIL] Decision engine failed: {e}")
    
    # Test 5: Scanner
    print("\n[5/5] Testing scanner...")
    try:
        scanner = ProductionScanner()
        print("  [OK] Scanner initialized")
    except Exception as e:
        print(f"  [FAIL] Scanner failed: {e}")
    
    print("\n" + "=" * 60)
    print("Self-test complete!")
    print("=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="LightAV Production Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_production.py --test                    # Run self-test
  python run_production.py --stats                   # Show statistics
  python run_production.py --scan file.exe           # Scan single file
  python run_production.py --scan C:\\Users\\Name\\Downloads  # Scan directory
        """
    )
    
    parser.add_argument('--scan', metavar='PATH',
                       help='Scan a specific file or directory')
    parser.add_argument('--no-recursive', action='store_true',
                       help='Disable recursive scanning for directories')
    parser.add_argument('--test', action='store_true',
                       help='Run self-test')
    parser.add_argument('--stats', action='store_true',
                       help='Show database statistics')
    
    args = parser.parse_args()
    
    try:
        if args.test:
            run_self_test()
        elif args.stats:
            show_stats()
        elif args.scan:
            path = Path(args.scan)
            if path.is_file():
                scan_file(str(path))
            elif path.is_dir():
                scan_directory(str(path), recursive=not args.no_recursive)
            else:
                print(f"Error: Path not found: {args.scan}")
        else:
            # Default: show stats
            show_stats()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
