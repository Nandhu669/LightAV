"""
Resource Governor Module
Adaptive resource management for production scanner
"""

import psutil
import time
import threading
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum


class SystemState(Enum):
    """System state for adaptive scanning."""
    IDLE = "idle"           # System is idle - can use more resources
    NORMAL = "normal"       # Normal operation - balanced
    BUSY = "busy"           # System is busy - reduce impact
    GAMING = "gaming"       # Gaming/fullscreen app detected - minimal impact
    CRITICAL = "critical"   # Critical system state - pause scanning


@dataclass
class ResourceConfig:
    """Resource configuration for each system state."""
    max_cpu_percent: int
    max_memory_mb: int
    scan_delay_ms: int
    enable_deep_scan: bool
    enable_ml_layer: bool


class ResourceGovernor:
    """
    Adaptive resource governor for the production scanner.
    
    Monitors system state and adjusts scanning behavior to minimize impact.
    """
    
    def __init__(self, check_interval: float = 2.0):
        """
        Initialize resource governor.
        
        Args:
            check_interval: Seconds between system state checks
        """
        self.check_interval = check_interval
        self.current_state = SystemState.NORMAL
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # State configurations
        self.state_configs = {
            SystemState.IDLE: ResourceConfig(
                max_cpu_percent=30,
                max_memory_mb=100,
                scan_delay_ms=0,
                enable_deep_scan=True,
                enable_ml_layer=True
            ),
            SystemState.NORMAL: ResourceConfig(
                max_cpu_percent=20,
                max_memory_mb=80,
                scan_delay_ms=50,
                enable_deep_scan=True,
                enable_ml_layer=False
            ),
            SystemState.BUSY: ResourceConfig(
                max_cpu_percent=10,
                max_memory_mb=60,
                scan_delay_ms=100,
                enable_deep_scan=False,
                enable_ml_layer=False
            ),
            SystemState.GAMING: ResourceConfig(
                max_cpu_percent=5,
                max_memory_mb=50,
                scan_delay_ms=500,
                enable_deep_scan=False,
                enable_ml_layer=False
            ),
            SystemState.CRITICAL: ResourceConfig(
                max_cpu_percent=0,
                max_memory_mb=40,
                scan_delay_ms=0,
                enable_deep_scan=False,
                enable_ml_layer=False
            )
        }
        
        # Thresholds
        self.cpu_busy_threshold = 70
        self.cpu_critical_threshold = 90
        self.memory_busy_threshold = 80
        self.memory_critical_threshold = 90
        
        # Gaming detection
        self.gaming_processes = [
            'steam.exe', 'epicgameslauncher.exe', 'origin.exe',
            'battle.net.exe', 'uplay.exe', 'galaxyclient.exe',
            'csgo.exe', 'valorant.exe', 'fortnite.exe',
            'minecraft.exe', 'league of legends.exe', 'overwatch.exe',
            'callofduty.exe', 'apex.exe', 'pubg.exe'
        ]
        
        # Statistics
        self.stats = {
            'state_changes': 0,
            'time_in_idle': 0.0,
            'time_in_normal': 0.0,
            'time_in_busy': 0.0,
            'time_in_gaming': 0.0,
            'time_in_critical': 0.0,
            'throttling_events': 0
        }
        
        self._state_start_time = time.time()
        self._last_state = SystemState.NORMAL
    
    def start_monitoring(self):
        """Start the resource monitoring thread."""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("[ResourceGovernor] Started monitoring")
    
    def stop_monitoring(self):
        """Stop the resource monitoring thread."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        print("[ResourceGovernor] Stopped monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._update_system_state()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"[ResourceGovernor] Monitor error: {e}")
    
    def _update_system_state(self):
        """Update system state based on current conditions."""
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        
        # Check for gaming mode
        if self._is_gaming_mode():
            new_state = SystemState.GAMING
        # Check for critical state
        elif cpu_percent > self.cpu_critical_threshold or memory.percent > self.memory_critical_threshold:
            new_state = SystemState.CRITICAL
        # Check for busy state
        elif cpu_percent > self.cpu_busy_threshold or memory.percent > self.memory_busy_threshold:
            new_state = SystemState.BUSY
        # Check for idle state
        elif cpu_percent < 10 and memory.percent < 50:
            new_state = SystemState.IDLE
        else:
            new_state = SystemState.NORMAL
        
        # Update state if changed
        if new_state != self.current_state:
            self._update_state_stats()
            self.current_state = new_state
            self._state_start_time = time.time()
            self.stats['state_changes'] += 1
            print(f"[ResourceGovernor] State changed to: {new_state.value}")
    
    def _update_state_stats(self):
        """Update time spent in previous state."""
        elapsed = time.time() - self._state_start_time
        
        if self._last_state == SystemState.IDLE:
            self.stats['time_in_idle'] += elapsed
        elif self._last_state == SystemState.NORMAL:
            self.stats['time_in_normal'] += elapsed
        elif self._last_state == SystemState.BUSY:
            self.stats['time_in_busy'] += elapsed
        elif self._last_state == SystemState.GAMING:
            self.stats['time_in_gaming'] += elapsed
        elif self._last_state == SystemState.CRITICAL:
            self.stats['time_in_critical'] += elapsed
        
        self._last_state = self.current_state
    
    def _is_gaming_mode(self) -> bool:
        """Detect if gaming/fullscreen application is running."""
        try:
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if proc_name in self.gaming_processes:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return False
    
    def get_current_config(self) -> ResourceConfig:
        """Get resource configuration for current state."""
        return self.state_configs[self.current_state]
    
    def should_pause_scanning(self) -> bool:
        """Check if scanning should be paused."""
        return self.current_state == SystemState.CRITICAL
    
    def get_throttle_delay(self) -> float:
        """Get current throttle delay in seconds."""
        config = self.get_current_config()
        return config.scan_delay_ms / 1000.0
    
    def get_stats(self) -> Dict:
        """Get resource governor statistics."""
        # Update current state time
        self._update_state_stats()
        self._state_start_time = time.time()
        
        total_time = sum([
            self.stats['time_in_idle'],
            self.stats['time_in_normal'],
            self.stats['time_in_busy'],
            self.stats['time_in_gaming'],
            self.stats['time_in_critical']
        ])
        
        if total_time > 0:
            return {
                **self.stats,
                'current_state': self.current_state.value,
                'total_monitored_time': total_time,
                'percent_idle': (self.stats['time_in_idle'] / total_time) * 100,
                'percent_normal': (self.stats['time_in_normal'] / total_time) * 100,
                'percent_busy': (self.stats['time_in_busy'] / total_time) * 100,
                'percent_gaming': (self.stats['time_in_gaming'] / total_time) * 100,
                'percent_critical': (self.stats['time_in_critical'] / total_time) * 100
            }
        return self.stats


class CPUThrottler:
    """
    CPU usage throttler to limit scanning impact.
    """
    
    def __init__(self, target_cpu_percent: int = 20):
        """
        Initialize CPU throttler.
        
        Args:
            target_cpu_percent: Target CPU usage percentage
        """
        self.target_cpu = target_cpu_percent
        self.process = psutil.Process()
        self.start_time = time.time()
        self.scan_count = 0
        self.total_cpu_time = 0.0
    
    def throttle(self):
        """
        Apply CPU throttling.
        Call this periodically during scanning.
        """
        self.scan_count += 1
        
        # Get current CPU usage for this process
        try:
            cpu_percent = self.process.cpu_percent(interval=0.1)
            
            if cpu_percent > self.target_cpu:
                # Calculate sleep time to reduce CPU usage
                # Simple proportional control
                excess = cpu_percent - self.target_cpu
                sleep_time = (excess / 100.0) * 0.5  # Sleep up to 500ms
                sleep_time = min(sleep_time, 1.0)  # Max 1 second
                
                if sleep_time > 0.01:  # Only sleep if meaningful
                    time.sleep(sleep_time)
                    self.total_cpu_time += sleep_time
                    
        except Exception:
            pass
    
    def get_stats(self) -> Dict:
        """Get throttling statistics."""
        elapsed = time.time() - self.start_time
        return {
            'target_cpu_percent': self.target_cpu,
            'scans_throttled': self.scan_count,
            'total_sleep_time': self.total_cpu_time,
            'throttle_efficiency': (self.total_cpu_time / max(elapsed, 1)) * 100
        }


class MemoryLimiter:
    """
    Memory usage limiter to prevent excessive RAM consumption.
    """
    
    def __init__(self, max_memory_mb: int = 100):
        """
        Initialize memory limiter.
        
        Args:
            max_memory_mb: Maximum memory usage in MB
        """
        self.max_memory = max_memory_mb * 1024 * 1024  # Convert to bytes
        self.process = psutil.Process()
        self.limit_hit_count = 0
    
    def check_memory(self) -> bool:
        """
        Check if memory limit is exceeded.
        
        Returns:
            True if under limit, False if exceeded
        """
        try:
            memory_info = self.process.memory_info()
            current_memory = memory_info.rss
            
            if current_memory > self.max_memory:
                self.limit_hit_count += 1
                return False
            return True
        except Exception:
            return True
    
    def get_memory_usage(self) -> Dict:
        """Get current memory usage."""
        try:
            memory_info = self.process.memory_info()
            return {
                'rss_mb': memory_info.rss / (1024 * 1024),
                'vms_mb': memory_info.vms / (1024 * 1024),
                'max_allowed_mb': self.max_memory / (1024 * 1024),
                'limit_hit_count': self.limit_hit_count
            }
        except Exception:
            return {'error': 'Could not get memory info'}


# Convenience function
def create_resource_manager(target_cpu: int = 20, target_memory: int = 100) -> Dict:
    """
    Create a complete resource management system.
    
    Args:
        target_cpu: Target CPU percentage
        target_memory: Target memory in MB
        
    Returns:
        Dictionary with all resource management components
    """
    return {
        'governor': ResourceGovernor(),
        'throttler': CPUThrottler(target_cpu),
        'memory_limiter': MemoryLimiter(target_memory)
    }


if __name__ == "__main__":
    # Test resource governor
    print("=" * 60)
    print("Resource Governor Test")
    print("=" * 60)
    print()
    
    gov = ResourceGovernor(check_interval=1.0)
    
    print(f"Initial state: {gov.current_state.value}")
    print(f"Config: {gov.get_current_config()}")
    print()
    
    # Start monitoring
    print("Starting monitoring for 5 seconds...")
    gov.start_monitoring()
    time.sleep(5)
    
    # Show stats
    print("\nStats:")
    stats = gov.get_stats()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2f}")
        else:
            print(f"  {key}: {value}")
    
    # Stop
    gov.stop_monitoring()
    print("\nTest complete!")
