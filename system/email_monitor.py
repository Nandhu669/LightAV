import threading
import time
import os
import glob
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.scanner import scan_file as process_file
from core.decision_types import Verdict

class EmailAttachmentHandler(FileSystemEventHandler):
    def __init__(self, toggle_event):
        super().__init__()
        self.toggle_event = toggle_event

    def on_created(self, event):
        if not self.toggle_event.is_set():
            return
            
        if not event.is_directory:
            filepath = event.src_path
            # Outlook temporary files shouldn't be executed directly, scan them immediately.
            try:
                # Slight delay to ensure the file is completely written to disk
                time.sleep(1)
                verdict = process_file(filepath)
                if verdict == Verdict.MALICIOUS:
                    print(f"[EMAIL-PROTECTION] Threat blocked from email attachment folder: {filepath}")
            except Exception as e:
                pass

def start_email_monitor(toggle_event):
    """Monitors standard email client attachment caching directories."""
    print("[EMAIL-PROTECTION] Email attachment monitor starting...")
    
    # Common directories where Outlook drops attachments
    local_app_data = os.environ.get('LOCALAPPDATA', '')
    if not local_app_data:
        return
        
    outlook_cache_dir_pattern = os.path.join(local_app_data, "Microsoft", "Windows", "INetCache", "Content.Outlook", "*")
    potential_dirs = glob.glob(outlook_cache_dir_pattern)
    
    # Also monitor the standard Temp folder where generic email clients unpack zips
    temp_dir = os.environ.get('TEMP', '')
    if temp_dir:
        potential_dirs.append(temp_dir)
        
    valid_dirs = [d for d in potential_dirs if os.path.isdir(d)]
    
    if not valid_dirs:
        print("[EMAIL-PROTECTION] No known email cache directories found to monitor.")
        return
        
    observer = Observer()
    handler = EmailAttachmentHandler(toggle_event)
    
    for directory in valid_dirs:
        try:
            observer.schedule(handler, path=directory, recursive=True)
            print(f"[EMAIL-PROTECTION] Monitoring: {directory}")
        except:
            pass
            
    # Start the observer in a separate thread controlled by the toggle
    def run_observer():
        observer.start()
        try:
            while True:
                time.sleep(1)
                if not toggle_event.is_set():
                    # Stop monitoring if the user toggles it off
                    # But actually we might just keep it running but the handler 
                    # can check if toggle_event is set. To do this cleanly,
                    # we can pause processing inside the handler, but since watchdog 
                    # doesn't pause natively, we can just stop the observer and exit thread
                    # For simplicity we'll just keep it alive in background but check the toggle in the handler
                    pass
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        
    t = threading.Thread(target=run_observer, daemon=True)
    t.start()
    return observer
