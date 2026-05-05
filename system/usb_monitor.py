import win32com.client
import time
from core.scanner import scan_file as process_file
from services.runtime_state import USB_PROTECTION_ENABLED

def monitor_usb(callback_signal=None):
    """
    Monitors for USB insertion events.
    If callback_signal is provided (PyQt signal), it emits the drive name.
    """
    # Initialize WMI in the current thread
    import pythoncom
    pythoncom.CoInitialize()
    
    try:
        wmi = win32com.client.GetObject("winmgmts:")
        watcher = wmi.ExecNotificationQuery(
            "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
        )

        while True:
            # Check every second for better responsiveness to stop signals
            # nextEvent can block, so we use a shorter timeout if possible or just loop
            event = watcher.NextEvent()
            
            if not USB_PROTECTION_ENABLED.is_set():
                continue
                
            drive = event.DriveName
            if drive:
                print(f"[USB] Device detected at {drive}")
                if callback_signal:
                    callback_signal.emit(drive)
                else:
                    # Fallback for non-GUI usage if needed
                    pass
    except Exception as e:
        print(f"[USB] Monitor Error: {e}")
    finally:
        pythoncom.CoUninitialize()

def scan_usb(drive_path):
    import os
    print(f"[USB] Starting scan of {drive_path}")
    for root, _, files in os.walk(drive_path):
        for f in files:
            try:
                filepath = os.path.join(root, f)
                process_file(filepath)
            except:
                pass
    print(f"[USB] Scan of {drive_path} completed.")
