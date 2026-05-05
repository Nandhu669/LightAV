"""
Comprehensive Test Framework for LightAV
Test detection accuracy, performance, and false positives
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.resource_scanner import ResourceAwareScanner
from core.decision_engine import ProductionDecisionEngine
from core.decision_types import Verdict


@dataclass
class TestResult:
    """Result from a single test."""
    file_path: str
    file_hash: str
    expected_verdict: str
    actual_verdict: str
    source: str
    confidence: float
    scan_time_ms: float
    details: Dict
    timestamp: str


@dataclass
class TestSuiteResults:
    """Results from a complete test suite."""
    suite_name: str
    total_tests: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    detection_rate: float
    false_positive_rate: float
    accuracy: float
    avg_scan_time_ms: float
    total_time_seconds: float
    results: List[TestResult]


class LightAVTester:
    """
    Comprehensive testing framework for LightAV.
    
    Tests:
    - Detection rate on malware samples
    - False positive rate on benign files
    - Performance benchmarks
    - Resource usage
    """
    
    def __init__(self, scanner: Optional[ResourceAwareScanner] = None):
        """
        Initialize tester.
        
        Args:
            scanner: Scanner instance (creates new if None)
        """
        self.scanner = scanner or ResourceAwareScanner()
        self.results_dir = Path("results/tests")
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def test_malware_detection(self, malware_dir: str, 
                               limit: int = 1000) -> TestSuiteResults:
        """
        Test malware detection rate.
        
        Args:
            malware_dir: Directory containing malware samples
            limit: Maximum number of files to test
            
        Returns:
            TestSuiteResults with detection statistics
        """
        print(f"\n[Tester] Testing malware detection on: {malware_dir}")
        
        if not os.path.exists(malware_dir):
            print(f"[Tester] Warning: Directory not found: {malware_dir}")
            return self._create_empty_results("malware_detection")
        
        results = []
        start_time = time.time()
        
        # Find all executable files
        test_files = []
        for root, dirs, files in os.walk(malware_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if self.scanner.is_scannable(file_path):
                    test_files.append(file_path)
                if len(test_files) >= limit:
                    break
            if len(test_files) >= limit:
                break
        
        print(f"[Tester] Found {len(test_files)} test files")
        
        # Test each file
        for i, file_path in enumerate(test_files, 1):
            try:
                # Calculate hash
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Scan
                result = self.scanner.scan_file(file_path, auto_quarantine=False)
                
                test_result = TestResult(
                    file_path=file_path,
                    file_hash=file_hash,
                    expected_verdict="MALICIOUS",
                    actual_verdict=result.verdict.name,
                    source=result.source,
                    confidence=result.confidence,
                    scan_time_ms=result.scan_time_ms,
                    details=result.details,
                    timestamp=datetime.now().isoformat()
                )
                results.append(test_result)
                
                if i % 10 == 0:
                    print(f"[Tester] Progress: {i}/{len(test_files)} files tested")
                
            except Exception as e:
                print(f"[Tester] Error testing {file_path}: {e}")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        tp = sum(1 for r in results if r.actual_verdict == "MALICIOUS")
        fn = sum(1 for r in results if r.actual_verdict == "BENIGN")
        
        detection_rate = tp / len(results) if results else 0
        
        avg_scan_time = sum(r.scan_time_ms for r in results) / len(results) if results else 0
        
        suite_results = TestSuiteResults(
            suite_name="malware_detection",
            total_tests=len(results),
            true_positives=tp,
            true_negatives=0,
            false_positives=0,
            false_negatives=fn,
            detection_rate=detection_rate,
            false_positive_rate=0.0,
            accuracy=detection_rate,
            avg_scan_time_ms=avg_scan_time,
            total_time_seconds=total_time,
            results=results
        )
        
        return suite_results
    
    def test_false_positives(self, benign_dir: str,
                            limit: int = 1000) -> TestSuiteResults:
        """
        Test false positive rate on benign files.
        
        Args:
            benign_dir: Directory containing benign files
            limit: Maximum number of files to test
            
        Returns:
            TestSuiteResults with false positive statistics
        """
        print(f"\n[Tester] Testing false positives on: {benign_dir}")
        
        if not os.path.exists(benign_dir):
            print(f"[Tester] Warning: Directory not found: {benign_dir}")
            return self._create_empty_results("false_positive")
        
        results = []
        start_time = time.time()
        
        # Find all executable files
        test_files = []
        for root, dirs, files in os.walk(benign_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if self.scanner.is_scannable(file_path):
                    test_files.append(file_path)
                if len(test_files) >= limit:
                    break
            if len(test_files) >= limit:
                break
        
        print(f"[Tester] Found {len(test_files)} test files")
        
        # Test each file
        for i, file_path in enumerate(test_files, 1):
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                result = self.scanner.scan_file(file_path, auto_quarantine=False)
                
                test_result = TestResult(
                    file_path=file_path,
                    file_hash=file_hash,
                    expected_verdict="BENIGN",
                    actual_verdict=result.verdict.name,
                    source=result.source,
                    confidence=result.confidence,
                    scan_time_ms=result.scan_time_ms,
                    details=result.details,
                    timestamp=datetime.now().isoformat()
                )
                results.append(test_result)
                
                if i % 10 == 0:
                    print(f"[Tester] Progress: {i}/{len(test_files)} files tested")
                
            except Exception as e:
                print(f"[Tester] Error testing {file_path}: {e}")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        tn = sum(1 for r in results if r.actual_verdict == "BENIGN")
        fp = sum(1 for r in results if r.actual_verdict == "MALICIOUS")
        
        fp_rate = fp / len(results) if results else 0
        accuracy = tn / len(results) if results else 0
        
        avg_scan_time = sum(r.scan_time_ms for r in results) / len(results) if results else 0
        
        suite_results = TestSuiteResults(
            suite_name="false_positive",
            total_tests=len(results),
            true_positives=0,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=0,
            detection_rate=0.0,
            false_positive_rate=fp_rate,
            accuracy=accuracy,
            avg_scan_time_ms=avg_scan_time,
            total_time_seconds=total_time,
            results=results
        )
        
        return suite_results
    
    def test_specific_threats(self, threat_samples: List[str]) -> TestSuiteResults:
        """
        Test detection of specific threat types.
        
        Args:
            threat_samples: List of (file_path, threat_type) tuples
            
        Returns:
            TestSuiteResults
        """
        print(f"\n[Tester] Testing {len(threat_samples)} specific threat samples")
        
        results = []
        start_time = time.time()
        
        for file_path in threat_samples:
            if not os.path.exists(file_path):
                continue
            
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                result = self.scanner.scan_file(file_path, auto_quarantine=False)
                
                test_result = TestResult(
                    file_path=file_path,
                    file_hash=file_hash,
                    expected_verdict="MALICIOUS",
                    actual_verdict=result.verdict.name,
                    source=result.source,
                    confidence=result.confidence,
                    scan_time_ms=result.scan_time_ms,
                    details=result.details,
                    timestamp=datetime.now().isoformat()
                )
                results.append(test_result)
                
            except Exception as e:
                print(f"[Tester] Error testing {file_path}: {e}")
        
        total_time = time.time() - start_time
        
        tp = sum(1 for r in results if r.actual_verdict == "MALICIOUS")
        fn = sum(1 for r in results if r.actual_verdict == "BENIGN")
        
        detection_rate = tp / len(results) if results else 0
        avg_scan_time = sum(r.scan_time_ms for r in results) / len(results) if results else 0
        
        return TestSuiteResults(
            suite_name="specific_threats",
            total_tests=len(results),
            true_positives=tp,
            true_negatives=0,
            false_positives=0,
            false_negatives=fn,
            detection_rate=detection_rate,
            false_positive_rate=0.0,
            accuracy=detection_rate,
            avg_scan_time_ms=avg_scan_time,
            total_time_seconds=total_time,
            results=results
        )
    
    def save_results(self, results: TestSuiteResults, filename: Optional[str] = None):
        """
        Save test results to JSON file.
        
        Args:
            results: Test results to save
            filename: Output filename (auto-generated if None)
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"test_results_{results.suite_name}_{timestamp}.json"
        
        output_path = self.results_dir / filename
        
        # Convert to dict
        results_dict = {
            'suite_name': results.suite_name,
            'total_tests': results.total_tests,
            'true_positives': results.true_positives,
            'true_negatives': results.true_negatives,
            'false_positives': results.false_positives,
            'false_negatives': results.false_negatives,
            'detection_rate': results.detection_rate,
            'false_positive_rate': results.false_positive_rate,
            'accuracy': results.accuracy,
            'avg_scan_time_ms': results.avg_scan_time_ms,
            'total_time_seconds': results.total_time_seconds,
            'results': [asdict(r) for r in results.results]
        }
        
        with open(output_path, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        print(f"[Tester] Results saved to: {output_path}")
    
    def print_summary(self, results: TestSuiteResults):
        """Print test summary."""
        print("\n" + "=" * 60)
        print(f"TEST SUMMARY: {results.suite_name}")
        print("=" * 60)
        print(f"Total tests: {results.total_tests}")
        print(f"True Positives: {results.true_positives}")
        print(f"True Negatives: {results.true_negatives}")
        print(f"False Positives: {results.false_positives}")
        print(f"False Negatives: {results.false_negatives}")
        print()
        print(f"Detection Rate: {results.detection_rate*100:.2f}%")
        print(f"False Positive Rate: {results.false_positive_rate*100:.2f}%")
        print(f"Accuracy: {results.accuracy*100:.2f}%")
        print(f"Average Scan Time: {results.avg_scan_time_ms:.2f}ms")
        print(f"Total Time: {results.total_time_seconds:.2f}s")
        print("=" * 60)
    
    def _create_empty_results(self, suite_name: str) -> TestSuiteResults:
        """Create empty results for invalid test."""
        return TestSuiteResults(
            suite_name=suite_name,
            total_tests=0,
            true_positives=0,
            true_negatives=0,
            false_positives=0,
            false_negatives=0,
            detection_rate=0.0,
            false_positive_rate=0.0,
            accuracy=0.0,
            avg_scan_time_ms=0.0,
            total_time_seconds=0.0,
            results=[]
        )


def run_full_test_suite():
    """Run complete test suite."""
    print("=" * 60)
    print("LightAV Phase 3: Comprehensive Test Suite")
    print("=" * 60)
    
    tester = LightAVTester()
    
    # Test 1: Malware detection
    print("\n" + "-" * 60)
    print("TEST 1: Malware Detection")
    print("-" * 60)
    
    malware_dirs = [
        "data/malware",
        "data/test_samples/malware",
        "tests/samples/malware"
    ]
    
    malware_results = None
    for malware_dir in malware_dirs:
        if os.path.exists(malware_dir):
            malware_results = tester.test_malware_detection(malware_dir, limit=100)
            break
    
    if malware_results:
        tester.print_summary(malware_results)
        tester.save_results(malware_results)
        
        # Check if meets target
        if malware_results.detection_rate >= 0.90:
            print("✓ Detection rate meets target (>90%)")
        else:
            print("✗ Detection rate below target (<90%)")
    else:
        print("[!] No malware samples found. Skipping detection test.")
        print("    Add samples to: data/malware/ or data/test_samples/malware/")
    
    # Test 2: False positives
    print("\n" + "-" * 60)
    print("TEST 2: False Positive Rate")
    print("-" * 60)
    
    benign_dirs = [
        r"C:\Windows\System32",
        "data/benign",
        "data/test_samples/benign"
    ]
    
    fp_results = None
    for benign_dir in benign_dirs:
        if os.path.exists(benign_dir):
            fp_results = tester.test_false_positives(benign_dir, limit=100)
            break
    
    if fp_results:
        tester.print_summary(fp_results)
        tester.save_results(fp_results)
        
        # Check if meets target
        if fp_results.false_positive_rate <= 0.01:
            print("✓ False positive rate meets target (<1%)")
        else:
            print("✗ False positive rate above target (>1%)")
    else:
        print("[!] No benign samples found. Skipping false positive test.")
    
    # Overall summary
    print("\n" + "=" * 60)
    print("OVERALL TEST SUMMARY")
    print("=" * 60)
    
    all_passed = True
    
    if malware_results:
        print(f"Detection Rate: {malware_results.detection_rate*100:.1f}% {'✓' if malware_results.detection_rate >= 0.90 else '✗'}")
        all_passed &= (malware_results.detection_rate >= 0.90)
    
    if fp_results:
        print(f"False Positive Rate: {fp_results.false_positive_rate*100:.2f}% {'✓' if fp_results.false_positive_rate <= 0.01 else '✗'}")
        all_passed &= (fp_results.false_positive_rate <= 0.01)
    
    print("=" * 60)
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED - Production Ready!")
    else:
        print("\n✗ Some tests failed - Review results above")
    
    return all_passed


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="LightAV Test Suite")
    parser.add_argument('--malware-dir', help='Directory with malware samples')
    parser.add_argument('--benign-dir', help='Directory with benign samples')
    parser.add_argument('--limit', type=int, default=100, help='Max samples to test')
    
    args = parser.parse_args()
    
    if args.malware_dir or args.benign_dir:
        # Custom test
        tester = LightAVTester()
        
        if args.malware_dir:
            results = tester.test_malware_detection(args.malware_dir, args.limit)
            tester.print_summary(results)
            tester.save_results(results)
        
        if args.benign_dir:
            results = tester.test_false_positives(args.benign_dir, args.limit)
            tester.print_summary(results)
            tester.save_results(results)
    else:
        # Full test suite
        success = run_full_test_suite()
        sys.exit(0 if success else 1)
