"""
Production Scanner Module
File scanning with production decision engine
"""

import os
import hashlib
from pathlib import Path
from typing import Set, Optional
from core.decision_engine import ProductionDecisionEngine, DetectionResult
from core.decision_types import Verdict
from system.quarantine import quarantine_file
from system.logger import log_decision, log_quarantine


# Executable file extensions to scan
SCANNABLE_EXTENSIONS: Set[str] = {
    '.exe', '.dll', '.sys', '.scr', '.msi', 
    '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.com', '.pif', '.jar', '.wsf'
}

# Well-known system directories (used for throttling, NOT for skipping)
SYSTEM_PATHS = [
    Path(r"C:\Windows"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
    Path(r"C:\ProgramData")
]



# Files locked by OS kernel that cannot be read or quarantined
LOCKED_FILE_PATTERNS = frozenset([
    'ntoskrnl.exe', 'csrss.exe', 'smss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe',
    'ntdll.dll', 'kernel32.dll', 'hal.dll',
])


class ProductionScanner:
    """
    Production-grade file scanner with multi-layer detection.
    """
    
    def __init__(self, config: Optional[dict] = None):
        """
        Initialize production scanner.
        
        Args:
            config: Scanner configuration
        """
        self.config = config or {}
        self.decision_engine = ProductionDecisionEngine(config)
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'errors': 0,
            'scan_time_total': 0.0
        }
    
    def is_scannable(self, file_path: str) -> bool:
        """
        Check if file should be scanned.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file should be scanned
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return False
        
        # Check if it's a file (not directory)
        if not os.path.isfile(file_path):
            return False
        
        # Check extension
        ext = Path(file_path).suffix.lower()
        if ext not in SCANNABLE_EXTENSIONS:
            return False
        

        # Skip locked/system-critical files
        filename = os.path.basename(file_path).lower()
        if filename in LOCKED_FILE_PATTERNS:
            return False
        
        # Skip files that cannot be read
        try:
            with open(file_path, 'rb') as f:
                f.read(1)
        except (PermissionError, OSError):
            return False
        
        return True
    
    def is_system_path(self, file_path: str) -> bool:
        """
        Check if file is in a system directory.
        Used for throttling decisions — NOT for skipping scans.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file is in system path
        """
        try:
            path = Path(file_path).resolve()
            for sys_path in SYSTEM_PATHS:
                try:
                    path.relative_to(sys_path)
                    return True
                except ValueError:
                    continue
        except:
            pass
        return False
    
    def scan_file(self, file_path: str, auto_quarantine: bool = True) -> DetectionResult:
        """
        Scan a single file.
        
        Args:
            file_path: Path to file to scan
            auto_quarantine: Whether to quarantine threats automatically
            
        Returns:
            DetectionResult with verdict and details
        """
        # Validate file
        if not self.is_scannable(file_path):
            ext = Path(file_path).suffix.lower()
            if ext not in SCANNABLE_EXTENSIONS:
                return DetectionResult(
                    verdict=Verdict.BENIGN,
                    source="skipped",
                    confidence=1.0,
                    details={'reason': 'non_executable'},
                    scan_time_ms=0.0
                )
            return DetectionResult(
                verdict=Verdict.SUSPICIOUS,
                source="error",
                confidence=0.6,
                details={'reason': 'unreadable_executable'},
                scan_time_ms=0.0
            )
        
        try:
            # Performance throttling for system directories
            if self.is_system_path(file_path):
                import time as _time
                _time.sleep(0.01)  # 10ms throttle for system-path files

            # Calculate hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Run detection
            result = self.decision_engine.decide(file_path, file_hash)
            
            # Update statistics
            self.stats['files_scanned'] += 1
            self.stats['scan_time_total'] += result.scan_time_ms
            
            if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                self.stats['threats_detected'] += 1
                
                # Log decision
                log_decision(
                    file_path=file_path,
                    file_hash=file_hash,
                    source=result.source,
                    verdict=result.verdict,
                    elapsed_ms=result.scan_time_ms
                )
                
                # Quarantine if enabled (SUSPICIOUS files with quarantine flag too)
                should_quarantine = auto_quarantine and (
                    result.verdict == Verdict.MALICIOUS or
                    result.details.get('quarantine', False)
                )
                if should_quarantine:
                    try:
                        q_path = quarantine_file(file_path, file_hash)
                        log_quarantine(file_path, q_path)
                        self.stats['files_quarantined'] += 1
                        result.details['quarantined'] = True
                        result.details['quarantine_path'] = q_path
                    except Exception as e:
                        result.details['quarantine_error'] = str(e)
            
            return result
            
        except Exception as e:
            self.stats['errors'] += 1
            return DetectionResult(
                verdict=Verdict.SUSPICIOUS,  # Fail-CLOSED
                source="error",
                confidence=0.5,
                details={'error': str(e), 'quarantine': True},
                scan_time_ms=0.0
            )
    
    def scan_directory(self, directory: str, recursive: bool = True,
                       auto_quarantine: bool = True) -> dict:
        """
        Scan an entire directory.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            auto_quarantine: Whether to quarantine threats
            
        Returns:
            Dictionary with scan results
        """
        if not os.path.isdir(directory):
            return {'error': 'Not a directory'}
        
        results = []
        threats = []
        
        # Walk directory
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_scannable(file_path):
                        result = self.scan_file(file_path, auto_quarantine)
                        results.append({
                            'path': file_path,
                            'verdict': result.verdict.name,
                            'source': result.source,
                            'confidence': result.confidence
                        })
                        
                        if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                            threats.append({
                                'path': file_path,
                                'source': result.source,
                                'confidence': result.confidence,
                                'details': result.details
                            })
        else:
            # Non-recursive
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if self.is_scannable(file_path):
                    result = self.scan_file(file_path, auto_quarantine)
                    results.append({
                        'path': file_path,
                        'verdict': result.verdict.name,
                        'source': result.source,
                        'confidence': result.confidence
                    })
                    
                    if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                        threats.append({
                            'path': file_path,
                            'source': result.source,
                            'confidence': result.confidence,
                            'details': result.details
                        })
        
        return {
            'directory': directory,
            'files_scanned': len(results),
            'threats_found': len(threats),
            'threats': threats,
            'results': results
        }
    
    def get_stats(self) -> dict:
        """Return scanner statistics."""
        stats = {**self.stats}
        
        if self.stats['files_scanned'] > 0:
            stats['avg_scan_time_ms'] = self.stats['scan_time_total'] / self.stats['files_scanned']
            stats['detection_rate'] = self.stats['threats_detected'] / self.stats['files_scanned']
        else:
            stats['avg_scan_time_ms'] = 0
            stats['detection_rate'] = 0
        
        # Add decision engine stats
        stats['engine_stats'] = self.decision_engine.get_stats()
        
        return stats
    
    def reset_stats(self):
        """Reset all statistics."""
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'errors': 0,
            'scan_time_total': 0.0
        }
        self.decision_engine.reset_stats()


# Convenience functions
def scan_file(file_path: str, auto_quarantine: bool = True) -> DetectionResult:
    """
    Quick scan a single file.
    
    Args:
        file_path: Path to file
        auto_quarantine: Whether to quarantine threats
        
    Returns:
        DetectionResult
    """
    scanner = ProductionScanner()
    return scanner.scan_file(file_path, auto_quarantine)


def scan_directory(directory: str, recursive: bool = True) -> dict:
    """
    Quick scan a directory.
    
    Args:
        directory: Directory to scan
        recursive: Whether to scan recursively
        
    Returns:
        Dictionary with results
    """
    scanner = ProductionScanner()
    return scanner.scan_directory(directory, recursive, auto_quarantine=False)


if __name__ == "__main__":
    # Test scanner
    print("=" * 60)
    print("Production Scanner Test")
    print("=" * 60)
    print()
    
    scanner = ProductionScanner()
    
    # Test on system files
    test_files = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe"
    ]
    
    print("Scanning test files...")
    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"\nScanning: {test_file}")
            result = scanner.scan_file(test_file, auto_quarantine=False)
            print(f"  Verdict: {result.verdict.name}")
            print(f"  Source: {result.source}")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Time: {result.scan_time_ms:.2f}ms")
    
    print()
    print("Scanner Stats:")
    stats = scanner.get_stats()
    for key, value in stats.items():
        if key != 'engine_stats':
            print(f"  {key}: {value}")
    
    print()
    print("Engine Stats:")
    for key, value in stats['engine_stats'].items():
        print(f"  {key}: {value}")
