"""
Resource-Aware Production Scanner
Enhanced scanner with adaptive resource management
"""

import os
import hashlib
import time
from pathlib import Path
from typing import Set, Optional, Dict
from production.agent.decision_engine import ProductionDecisionEngine, DetectionResult
from production.agent.resource_governor import (
    ResourceGovernor, CPUThrottler, MemoryLimiter, 
    ResourceConfig, SystemState
)
from agent.decision_types import Verdict
from agent.quarantine import quarantine_file
from agent.logger import log_decision, log_quarantine


# Executable file extensions to scan
SCANNABLE_EXTENSIONS: Set[str] = {
    '.exe', '.dll', '.sys', '.scr', '.msi', 
    '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.com', '.pif', '.jar', '.wsf'
}

# System paths to scan with lighter rules
SYSTEM_PATHS = [
    Path(r"C:\Windows"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
    Path(r"C:\ProgramData")
]


class ResourceAwareScanner:
    """
    Production scanner with adaptive resource management.
    
    Features:
    - CPU throttling (max 30% in idle, 5% in gaming mode)
    - Memory limiting (max 100MB)
    - Gaming mode detection
    - Automatic pause when system is critical
    - Idle-only scanning option
    """
    
    def __init__(self, config: Optional[dict] = None):
        """
        Initialize resource-aware scanner.
        
        Args:
            config: Scanner configuration with options:
                - adaptive_throttling: Enable adaptive CPU throttling (default: True)
                - idle_only: Only scan when system is idle (default: False)
                - max_cpu_percent: Maximum CPU usage (default: 20)
                - max_memory_mb: Maximum memory usage (default: 100)
                - enable_gaming_detection: Detect gaming mode (default: True)
        """
        self.config = config or {}
        
        # Feature flags
        self.adaptive_throttling = self.config.get('adaptive_throttling', True)
        self.idle_only = self.config.get('idle_only', False)
        self.enable_gaming_detection = self.config.get('enable_gaming_detection', True)
        
        # Resource management
        self.resource_governor: Optional[ResourceGovernor] = None
        self.cpu_throttler: Optional[CPUThrottler] = None
        self.memory_limiter: Optional[MemoryLimiter] = None
        
        # Initialize resource management if enabled
        if self.adaptive_throttling:
            self._init_resource_management()
        
        # Decision engine
        self.decision_engine = ProductionDecisionEngine(config)
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'errors': 0,
            'scan_time_total': 0.0,
            'paused_scans': 0,
            'throttled_scans': 0
        }
    
    def _init_resource_management(self):
        """Initialize resource management components."""
        max_cpu = self.config.get('max_cpu_percent', 20)
        max_memory = self.config.get('max_memory_mb', 100)
        
        self.resource_governor = ResourceGovernor(check_interval=2.0)
        self.cpu_throttler = CPUThrottler(target_cpu_percent=max_cpu)
        self.memory_limiter = MemoryLimiter(max_memory_mb=max_memory)
        
        # Start monitoring
        self.resource_governor.start_monitoring()
        print(f"[ResourceAwareScanner] Resource management enabled")
        print(f"  Max CPU: {max_cpu}%")
        print(f"  Max Memory: {max_memory}MB")
    
    def is_scannable(self, file_path: str) -> bool:
        """Check if file should be scanned."""
        if not os.path.exists(file_path):
            return False
        if not os.path.isfile(file_path):
            return False
        
        ext = Path(file_path).suffix.lower()
        if ext not in SCANNABLE_EXTENSIONS:
            return False
        
        return True
    
    def should_scan_now(self) -> bool:
        """
        Check if scanning should proceed based on system state.
        
        Returns:
            True if scanning should proceed
        """
        if not self.adaptive_throttling or not self.resource_governor:
            return True
        
        # Check if system is in critical state
        if self.resource_governor.should_pause_scanning():
            self.stats['paused_scans'] += 1
            return False
        
        # Check idle-only mode
        if self.idle_only:
            current_state = self.resource_governor.current_state
            if current_state not in [SystemState.IDLE, SystemState.NORMAL]:
                return False
        
        return True
    
    def wait_for_idle(self, timeout: float = 60.0) -> bool:
        """
        Wait for system to become idle.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if system became idle, False if timeout
        """
        if not self.adaptive_throttling or not self.resource_governor:
            return True
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.should_scan_now():
                return True
            time.sleep(1.0)
        
        return False
    
    def scan_file(self, file_path: str, auto_quarantine: bool = True) -> DetectionResult:
        """
        Scan a single file with resource management.
        
        Args:
            file_path: Path to file to scan
            auto_quarantine: Whether to quarantine threats automatically
            
        Returns:
            DetectionResult with verdict and details
        """
        # Check if we should scan now
        if not self.should_scan_now():
            # Return result indicating scan was deferred
            return DetectionResult(
                verdict=Verdict.BENIGN,
                source="deferred",
                confidence=1.0,
                details={'reason': 'system_busy', 'retry_later': True},
                scan_time_ms=0.0
            )
        
        # Validate file
        if not self.is_scannable(file_path):
            return DetectionResult(
                verdict=Verdict.BENIGN,
                source="skipped",
                confidence=1.0,
                details={'reason': 'not_scannable'},
                scan_time_ms=0.0
            )
        
        # Check memory limit
        if self.memory_limiter and not self.memory_limiter.check_memory():
            print(f"[ResourceAwareScanner] Memory limit exceeded, pausing scan")
            return DetectionResult(
                verdict=Verdict.BENIGN,
                source="deferred",
                confidence=1.0,
                details={'reason': 'memory_limit'},
                scan_time_ms=0.0
            )
        
        try:
            start_time = time.time()
            
            # Calculate hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Run detection
            result = self.decision_engine.decide(file_path, file_hash)
            
            # Apply CPU throttling
            if self.cpu_throttler:
                self.cpu_throttler.throttle()
                self.stats['throttled_scans'] += 1
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # Update statistics
            self.stats['files_scanned'] += 1
            self.stats['scan_time_total'] += elapsed_ms
            
            if result.verdict == Verdict.MALICIOUS:
                self.stats['threats_detected'] += 1
                
                # Log decision
                log_decision(
                    file_path=file_path,
                    file_hash=file_hash,
                    source=result.source,
                    verdict=result.verdict,
                    elapsed_ms=elapsed_ms
                )
                
                # Quarantine if enabled
                if auto_quarantine:
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
                verdict=Verdict.BENIGN,
                source="error",
                confidence=0.0,
                details={'error': str(e)},
                scan_time_ms=0.0
            )
    
    def scan_directory(self, directory: str, recursive: bool = True,
                       auto_quarantine: bool = True) -> dict:
        """
        Scan a directory with resource management.
        
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
        deferred = []
        
        # Walk directory
        for root, dirs, files in os.walk(directory):
            if not recursive and root != directory:
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if not self.is_scannable(file_path):
                    continue
                
                # Check if we should pause
                if not self.should_scan_now():
                    deferred.append(file_path)
                    continue
                
                # Scan file
                result = self.scan_file(file_path, auto_quarantine)
                
                if result.source == 'deferred':
                    deferred.append(file_path)
                else:
                    results.append({
                        'path': file_path,
                        'verdict': result.verdict.name,
                        'source': result.source,
                        'confidence': result.confidence
                    })
                    
                    if result.verdict == Verdict.MALICIOUS:
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
            'deferred_count': len(deferred),
            'deferred_files': deferred[:10],  # First 10 deferred files
            'threats': threats,
            'results': results
        }
    
    def get_stats(self) -> dict:
        """Return scanner statistics with resource usage."""
        stats = {**self.stats}
        
        if self.stats['files_scanned'] > 0:
            stats['avg_scan_time_ms'] = self.stats['scan_time_total'] / self.stats['files_scanned']
            stats['detection_rate'] = self.stats['threats_detected'] / self.stats['files_scanned']
        else:
            stats['avg_scan_time_ms'] = 0
            stats['detection_rate'] = 0
        
        # Add decision engine stats
        stats['engine_stats'] = self.decision_engine.get_stats()
        
        # Add resource stats if available
        if self.resource_governor:
            stats['resource_governor_stats'] = self.resource_governor.get_stats()
        
        if self.cpu_throttler:
            stats['cpu_throttler_stats'] = self.cpu_throttler.get_stats()
        
        if self.memory_limiter:
            stats['memory_stats'] = self.memory_limiter.get_memory_usage()
        
        return stats
    
    def reset_stats(self):
        """Reset all statistics."""
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'errors': 0,
            'scan_time_total': 0.0,
            'paused_scans': 0,
            'throttled_scans': 0
        }
        self.decision_engine.reset_stats()
    
    def get_current_resource_config(self) -> Optional[ResourceConfig]:
        """Get current resource configuration."""
        if self.resource_governor:
            return self.resource_governor.get_current_config()
        return None
    
    def get_system_state(self) -> str:
        """Get current system state."""
        if self.resource_governor:
            return self.resource_governor.current_state.value
        return "unknown"


# Factory function
def create_resource_aware_scanner(
    adaptive_throttling: bool = True,
    idle_only: bool = False,
    max_cpu_percent: int = 20,
    max_memory_mb: int = 100
) -> ResourceAwareScanner:
    """
    Create a resource-aware scanner with specified configuration.
    
    Args:
        adaptive_throttling: Enable adaptive CPU throttling
        idle_only: Only scan when system is idle
        max_cpu_percent: Maximum CPU usage
        max_memory_mb: Maximum memory usage
        
    Returns:
        Configured ResourceAwareScanner
    """
    config = {
        'adaptive_throttling': adaptive_throttling,
        'idle_only': idle_only,
        'max_cpu_percent': max_cpu_percent,
        'max_memory_mb': max_memory_mb,
        'enable_gaming_detection': True
    }
    
    return ResourceAwareScanner(config)


# Convenience functions
def scan_file_with_throttling(file_path: str, auto_quarantine: bool = True) -> DetectionResult:
    """Scan a file with resource throttling enabled."""
    scanner = create_resource_aware_scanner()
    return scanner.scan_file(file_path, auto_quarantine)


def scan_directory_idle_only(directory: str) -> dict:
    """Scan a directory only when system is idle."""
    scanner = create_resource_aware_scanner(idle_only=True)
    return scanner.scan_directory(directory, recursive=True, auto_quarantine=False)


if __name__ == "__main__":
    # Test resource-aware scanner
    print("=" * 60)
    print("Resource-Aware Scanner Test")
    print("=" * 60)
    print()
    
    # Create scanner with throttling
    scanner = create_resource_aware_scanner(
        adaptive_throttling=True,
        max_cpu_percent=15,
        max_memory_mb=80
    )
    
    print(f"System state: {scanner.get_system_state()}")
    config = scanner.get_current_resource_config()
    if config:
        print(f"Current config: CPU {config.max_cpu_percent}%, Memory {config.max_memory_mb}MB")
    print()
    
    # Test on a system file
    test_file = r"C:\Windows\System32\notepad.exe"
    if os.path.exists(test_file):
        print(f"Scanning: {test_file}")
        result = scanner.scan_file(test_file, auto_quarantine=False)
        print(f"  Verdict: {result.verdict.name}")
        print(f"  Source: {result.source}")
        print(f"  System state: {scanner.get_system_state()}")
    
    print()
    print("Stats:")
    stats = scanner.get_stats()
    print(f"  Files scanned: {stats['files_scanned']}")
    print(f"  Throttled scans: {stats['throttled_scans']}")
    print(f"  Avg scan time: {stats['avg_scan_time_ms']:.2f}ms")
    
    if 'memory_stats' in stats:
        mem = stats['memory_stats']
        print(f"  Memory usage: {mem.get('rss_mb', 0):.1f}MB / {mem.get('max_allowed_mb', 0):.0f}MB")
    
    print()
    print("Test complete!")
