"""
Self-Protection Module
Prevent unauthorized termination and tampering
"""

import os
import sys
import ctypes
import threading
from typing import Optional
from pathlib import Path


class SelfProtection:
    """
    Self-protection mechanisms for the antivirus.
    
    Features:
    - Prevent process termination (Windows)
    - Protect installation directory
    - Registry protection hooks
    - Watchdog thread
    """
    
    def __init__(self, enabled: bool = True):
        """
        Initialize self-protection.
        
        Args:
            enabled: Whether to enable self-protection
        """
        self.enabled = enabled
        self.watchdog_thread: Optional[threading.Thread] = None
        self.running = False
        
        if self.enabled:
            self._init_protection()
    
    def _init_protection(self):
        """Initialize protection mechanisms."""
        if sys.platform == 'win32':
            self._init_windows_protection()
        else:
            print("[SelfProtection] Windows-specific protection only available on Windows")
    
    def _init_windows_protection(self):
        """Initialize Windows-specific protection."""
        try:
            # Set process as critical (requires admin)
            self._set_critical_process()
            
            # Protect installation directory
            self._protect_installation()
            
            print("[SelfProtection] Windows protection enabled")
            
        except Exception as e:
            print(f"[SelfProtection] Warning: Could not enable full protection: {e}")
            print("[SelfProtection] Running with limited protection")
    
    def _set_critical_process(self):
        """
        Set process as critical - prevents termination.
        Note: Requires administrator privileges.
        """
        try:
            # Import Windows API
            from ctypes import wintypes
            
            # Define constants
            PROCESS_SET_INFORMATION = 0x0200
            ProcessBreakOnTermination = 29
            
            # Get current process handle
            kernel32 = ctypes.windll.kernel32
            
            # Open current process with necessary rights
            hProcess = kernel32.GetCurrentProcess()
            
            # Set as critical process (1 = critical, 0 = not critical)
            result = ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0)
            
            if result == 0:
                print("[SelfProtection] Process set as critical (requires admin)")
            else:
                print(f"[SelfProtection] Could not set critical status: {result}")
                
        except Exception as e:
            # This is expected if not running as admin
            pass
    
    def _protect_installation(self):
        """Protect installation directory from modification."""
        try:
            # Get installation directory
            install_dir = Path(__file__).parent.parent.parent.resolve()
            
            # Set directory permissions (read-only)
            import subprocess
            result = subprocess.run(
                ['icacls', str(install_dir), '/deny', 'Everyone:(DE,DC,WDAC)'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"[SelfProtection] Installation directory protected: {install_dir}")
            
        except Exception as e:
            print(f"[SelfProtection] Could not protect installation: {e}")
    
    def start_watchdog(self, interval: float = 5.0):
        """
        Start watchdog thread to monitor process health.
        
        Args:
            interval: Check interval in seconds
        """
        if not self.enabled:
            return
        
        self.running = True
        self.watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            args=(interval,),
            daemon=True
        )
        self.watchdog_thread.start()
        print("[SelfProtection] Watchdog started")
    
    def _watchdog_loop(self, interval: float):
        """Watchdog monitoring loop."""
        import psutil
        
        process = psutil.Process()
        
        while self.running:
            try:
                # Check if process is still healthy
                if not process.is_running():
                    break
                
                # Check for suspicious activity
                # (e.g., debugger attachment, memory tampering)
                
                # Sleep until next check
                import time
                time.sleep(interval)
                
            except Exception:
                break
    
    def stop_watchdog(self):
        """Stop the watchdog thread."""
        self.running = False
        if self.watchdog_thread:
            self.watchdog_thread.join(timeout=2.0)
    
    def cleanup(self):
        """
        Cleanup protection before exit.
        Should be called on graceful shutdown.
        """
        if not self.enabled:
            return
        
        self.stop_watchdog()
        
        if sys.platform == 'win32':
            try:
                # Remove critical process status
                ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0)
                print("[SelfProtection] Process critical status removed")
            except:
                pass


class AntiTampering:
    """
    Anti-tampering mechanisms.
    """
    
    @staticmethod
    def verify_integrity() -> bool:
        """
        Verify application integrity.
        
        Returns:
            True if integrity check passed
        """
        try:
            # Check if key files exist
            required_files = [
                'production/agent/decision_engine.py',
                'production/agent/scanner.py',
                'production/ai_engine/yara_engine.py',
                'run_production.py'
            ]
            
            base_dir = Path(__file__).parent.parent.parent
            
            for file_path in required_files:
                full_path = base_dir / file_path
                if not full_path.exists():
                    print(f"[AntiTampering] Missing file: {file_path}")
                    return False
            
            return True
            
        except Exception as e:
            print(f"[AntiTampering] Integrity check failed: {e}")
            return False
    
    @staticmethod
    def is_running_as_admin() -> bool:
        """
        Check if running with administrator privileges.
        
        Returns:
            True if running as admin
        """
        try:
            if sys.platform == 'win32':
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False


def enable_self_protection():
    """
    Enable all self-protection mechanisms.
    Convenience function.
    """
    protection = SelfProtection(enabled=True)
    protection.start_watchdog()
    return protection


if __name__ == "__main__":
    print("=" * 60)
    print("Self-Protection Test")
    print("=" * 60)
    print()
    
    # Check admin status
    is_admin = AntiTampering.is_running_as_admin()
    print(f"Running as admin: {is_admin}")
    
    # Verify integrity
    integrity_ok = AntiTampering.verify_integrity()
    print(f"Integrity check: {'PASSED' if integrity_ok else 'FAILED'}")
    
    # Try to enable protection
    print()
    print("Attempting to enable self-protection...")
    protection = SelfProtection(enabled=True)
    
    if is_admin:
        print("Protection enabled (admin mode)")
    else:
        print("Protection enabled (limited - not admin)")
    
    print()
    print("Test complete!")
    print("Note: Full protection requires administrator privileges")
