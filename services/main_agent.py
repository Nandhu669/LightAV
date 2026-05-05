import os
import time
import threading
from queue import Queue
from core.resource_scanner import ResourceAwareScanner
from services.runtime_state import RUNNING
from services.file_monitor import start_monitor

scanner = ResourceAwareScanner()
scan_queue = Queue(maxsize=1000)

def worker(scan_queue):
    while True:
        if not RUNNING.is_set():
            time.sleep(0.5)
            continue

        try:
            path = scan_queue.get(timeout=1)
        except:
            continue

        print(f"[Scan] Processing: {path}")
        try:
            # ResourceAwareScanner handles should_scan_now(), throttling, etc.
            result = scanner.scan_file(path, auto_quarantine=True)
            print(f"[Scan] Result: {result.verdict.name} for {path}")
        except Exception as e:
            print(f"[Scan] Error: {e}")

        scan_queue.task_done()

def start_workers(num_workers=2):
    """Start worker threads for file processing."""
    for _ in range(num_workers):
        threading.Thread(
            target=worker,
            args=(scan_queue,),
            daemon=True
        ).start()

def start_monitors():
    """Start file system monitors for user directories."""
    user_home = os.path.expanduser("~")
    monitored_dirs = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Documents"),
    ]
    
    observers = []
    for dir_path in monitored_dirs:
        observer = start_monitor(dir_path, scan_queue)
        if observer:
            observers.append(observer)
            print(f"[Monitor] Watching: {dir_path}")
    
    return observers

def main_loop():
    """Main loop for the agent - call this from service or standalone."""
    start_workers()
    start_monitors()
    print("[LightAV] Engine started. Monitoring for files...")
    while True:
        time.sleep(5)

if __name__ == "__main__":
    main_loop()
