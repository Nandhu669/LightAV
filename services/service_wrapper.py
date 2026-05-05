"""
Windows Service Wrapper for LightAV
Run as a Windows service for continuous protection
"""

import sys
import os
import time
import threading
from pathlib import Path

# Windows service imports
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    import win32timezone
    WINDOWS_SERVICE_AVAILABLE = True
except ImportError:
    WINDOWS_SERVICE_AVAILABLE = False
    print("Warning: pywin32 not installed. Windows service support unavailable.")

from core.resource_scanner import ResourceAwareScanner
from services.self_protection import SelfProtection
from services.file_monitor import start_monitor, Observer


class LightAVService(win32serviceutil.ServiceFramework if WINDOWS_SERVICE_AVAILABLE else object):
    """
    Windows Service wrapper for LightAV.
    
    Allows LightAV to run continuously in the background as a Windows service.
    """
    
    _svc_name_ = "LightAVService"
    _svc_display_name_ = "LightAV Antivirus Protection"
    _svc_description_ = "Real-time malware protection with adaptive resource management"
    
    def __init__(self, args):
        if not WINDOWS_SERVICE_AVAILABLE:
            raise RuntimeError("Windows service support not available")
        
        win32serviceutil.ServiceFramework.__init__(self, args)
        
        # Create stop event
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        
        # Service components
        self.scanner: ResourceAwareScanner = None
        self.self_protection: SelfProtection = None
        self.file_observers: list = []
        self.running = False
        self.monitor_thread: threading.Thread = None
    
    def SvcStop(self):
        """Stop the service."""
        # Report service stop pending
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        
        # Signal stop event
        win32event.SetEvent(self.hWaitStop)
        
        self.running = False
        
        # Cleanup
        if self.self_protection:
            self.self_protection.cleanup()
        
        # Stop file monitors
        for observer in self.file_observers:
            observer.stop()
            observer.join()
    
    def SvcDoRun(self):
        """Main service loop."""
        # Report service start
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        try:
            self.running = True
            self.run_service()
        except Exception as e:
            servicemanager.LogErrorMsg(f"Service error: {str(e)}")
        
        # Wait for stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        
        # Report service stop
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, '')
        )
    
    def run_service(self):
        """Run the main service logic."""
        print("=" * 60)
        print("LightAV Service Starting")
        print("=" * 60)
        
        # Initialize self-protection
        print("[Service] Enabling self-protection...")
        self.self_protection = SelfProtection(enabled=True)
        self.self_protection.start_watchdog()
        
        # Initialize resource-aware scanner
        print("[Service] Initializing scanner...")
        self.scanner = ResourceAwareScanner(config={
            'adaptive_throttling': True,
            'max_cpu_percent': 20,
            'max_memory_mb': 100,
            'enable_gaming_detection': True
        })
        
        # Start file system monitoring
        print("[Service] Starting file monitors...")
        self._start_file_monitoring()
        
        print("[Service] LightAV is now running and protecting your system")
        
        # Main loop - keep service alive
        while self.running:
            time.sleep(1)
    
    def _start_file_monitoring(self):
        """Start monitoring user directories."""
        from queue import Queue
        
        scan_queue = Queue()
        
        # Monitor key user directories
        user_dirs = [
            Path.home() / "Downloads",
            Path.home() / "Desktop",
            Path.home() / "Documents"
        ]
        
        for directory in user_dirs:
            if directory.exists():
                from services.file_monitor import start_monitor
                observer = start_monitor(str(directory), scan_queue)
                if observer:
                    self.file_observers.append(observer)
                    print(f"[Service] Monitoring: {directory}")
        
        # Start worker thread to process scanned files
        self.monitor_thread = threading.Thread(
            target=self._scan_worker,
            args=(scan_queue,),
            daemon=True
        )
        self.monitor_thread.start()
    
    def _scan_worker(self, scan_queue):
        """Worker thread to process files from queue."""
        while self.running:
            try:
                # Get file from queue (with timeout)
                import queue
                try:
                    file_path = scan_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Check if we should scan
                if self.scanner.should_scan_now():
                    result = self.scanner.scan_file(file_path, auto_quarantine=True)
                    
                    if result.verdict.name == "MALICIOUS":
                        servicemanager.LogWarningMsg(
                            f"Threat detected: {file_path} ({result.source})"
                        )
                
            except Exception as e:
                print(f"[Service] Scan worker error: {e}")


class LightAVServiceController:
    """
    Controller for managing the LightAV Windows service.
    """
    
    @staticmethod
    def install_service():
        """Install the LightAV service."""
        if not WINDOWS_SERVICE_AVAILABLE:
            print("Error: Windows service support not available")
            print("Install pywin32: pip install pywin32")
            return False
        
        try:
            # Install service
            win32serviceutil.InstallService(
                LightAVService._svc_class_,
                LightAVService._svc_name_,
                LightAVService._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START
            )
            
            print(f"[Service] Installed: {LightAVService._svc_display_name_}")
            print("[Service] The service will start automatically on boot")
            return True
            
        except Exception as e:
            print(f"[Service] Installation failed: {e}")
            print("Note: Requires administrator privileges")
            return False
    
    @staticmethod
    def remove_service():
        """Remove the LightAV service."""
        if not WINDOWS_SERVICE_AVAILABLE:
            print("Error: Windows service support not available")
            return False
        
        try:
            win32serviceutil.RemoveService(LightAVService._svc_name_)
            print(f"[Service] Removed: {LightAVService._svc_display_name_}")
            return True
            
        except Exception as e:
            print(f"[Service] Removal failed: {e}")
            return False
    
    @staticmethod
    def start_service():
        """Start the LightAV service."""
        if not WINDOWS_SERVICE_AVAILABLE:
            print("Error: Windows service support not available")
            return False
        
        try:
            win32serviceutil.StartService(LightAVService._svc_name_)
            print(f"[Service] Started: {LightAVService._svc_display_name_}")
            return True
            
        except Exception as e:
            print(f"[Service] Start failed: {e}")
            return False
    
    @staticmethod
    def stop_service():
        """Stop the LightAV service."""
        if not WINDOWS_SERVICE_AVAILABLE:
            print("Error: Windows service support not available")
            return False
        
        try:
            win32serviceutil.StopService(LightAVService._svc_name_)
            print(f"[Service] Stopped: {LightAVService._svc_display_name_}")
            return True
            
        except Exception as e:
            print(f"[Service] Stop failed: {e}")
            return False
    
    @staticmethod
    def restart_service():
        """Restart the LightAV service."""
        LightAVServiceController.stop_service()
        time.sleep(2)
        LightAVServiceController.start_service()
    
    @staticmethod
    def get_service_status():
        """Get current service status."""
        if not WINDOWS_SERVICE_AVAILABLE:
            return "Not Available"
        
        try:
            status = win32serviceutil.QueryServiceStatus(LightAVService._svc_name_)
            state = status[1]
            
            states = {
                win32service.SERVICE_STOPPED: "Stopped",
                win32service.SERVICE_START_PENDING: "Starting",
                win32service.SERVICE_STOP_PENDING: "Stopping",
                win32service.SERVICE_RUNNING: "Running",
                win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
                win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
                win32service.SERVICE_PAUSED: "Paused"
            }
            
            return states.get(state, f"Unknown ({state})")
            
        except Exception as e:
            return f"Error: {e}"


def run_service_command(command: str):
    """
    Run a service command.
    
    Args:
        command: One of: install, remove, start, stop, restart, status
    """
    controller = LightAVServiceController()
    
    commands = {
        'install': controller.install_service,
        'remove': controller.remove_service,
        'start': controller.start_service,
        'stop': controller.stop_service,
        'restart': controller.restart_service,
        'status': lambda: print(f"Service status: {controller.get_service_status()}")
    }
    
    if command in commands:
        commands[command]()
    else:
        print(f"Unknown command: {command}")
        print(f"Available commands: {', '.join(commands.keys())}")


if __name__ == "__main__":
    if WINDOWS_SERVICE_AVAILABLE and len(sys.argv) > 1:
        # Command-line service management
        command = sys.argv[1].lower()
        run_service_command(command)
    elif WINDOWS_SERVICE_AVAILABLE:
        # Run as service
        win32serviceutil.HandleCommandLine(LightAVService)
    else:
        print("Windows service support not available")
        print("Install pywin32: pip install pywin32")
        print()
        print("Service management commands:")
        print("  python service_wrapper.py install    - Install service")
        print("  python service_wrapper.py start      - Start service")
        print("  python service_wrapper.py stop       - Stop service")
        print("  python service_wrapper.py remove     - Remove service")
