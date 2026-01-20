"""
Backend Controller - Bridge between GUI and LightAV Backend

This module provides thread-safe methods for the PyQt6 GUI to interact
with the LightAV scanning engine, quarantine system, and protection controls.
"""

import os
import threading
import json
from pathlib import Path
from queue import Queue
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

# Backend imports
from agent.scanner import process_file
from agent.runtime_state import RUNNING
from agent.quarantine import quarantine_file, QUARANTINE_DIR
from agent.restore import restore_file
from agent.decision_types import Verdict
from agent.hash_cache import compute_hash


class BackendController(QObject):
    """
    Controller class that bridges GUI and backend operations.
    All backend operations run in background threads to keep UI responsive.
    """
    
    # Qt Signals for thread-safe GUI updates
    scan_started = pyqtSignal(str)  # filepath
    scan_completed = pyqtSignal(str, str, float)  # filepath, result ("CLEAN" or "MALICIOUS"), elapsed_ms
    scan_error = pyqtSignal(str, str)  # filepath, error_message
    
    protection_status_changed = pyqtSignal(bool)  # is_running
    
    log_message = pyqtSignal(str, str)  # message, level ("INFO", "WARNING", "THREAT")
    
    def __init__(self):
        super().__init__()
        self.scan_queue = Queue()
        self.protection_active = False
        self.scan_workers = []
        
        # Start scan worker threads
        self._start_scan_workers(num_workers=2)
    
    def _start_scan_workers(self, num_workers=2):
        """Start background worker threads for file scanning"""
        for i in range(num_workers):
            worker = threading.Thread(
                target=self._scan_worker,
                daemon=True,
                name=f"ScanWorker-{i}"
            )
            worker.start()
            self.scan_workers.append(worker)
    
    def _scan_worker(self):
        """Worker thread that processes scan requests from the queue"""
        while True:
            try:
                filepath, callback = self.scan_queue.get(timeout=1)
            except:
                continue
            
            self._process_scan(filepath, callback)
            self.scan_queue.task_done()
    
    def _process_scan(self, filepath, callback=None):
        """
        Process a single file scan in background thread.
        Emits signals to update GUI.
        """
        import time
        
        try:
            # Emit scan started
            self.scan_started.emit(filepath)
            self.log_message.emit(f"Scanning file: {filepath}", "INFO")
            
            start_time = time.time()
            
            # Call backend scanner
            verdict = process_file(filepath)
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # Convert verdict to string
            if verdict == Verdict.MALICIOUS:
                result = "MALICIOUS"
                self.log_message.emit(f"THREAT DETECTED: {filepath}", "THREAT")
            else:
                result = "CLEAN"
                self.log_message.emit(f"File is clean: {filepath}", "INFO")
            
            # Emit completion signal
            self.scan_completed.emit(filepath, result, elapsed_ms)
            
            # Call callback if provided
            if callback:
                callback(filepath, result)
                
        except Exception as e:
            error_msg = str(e)
            self.scan_error.emit(filepath, error_msg)
            self.log_message.emit(f"Scan error for {filepath}: {error_msg}", "WARNING")
    
    def scan_single_file(self, filepath, callback=None):
        """
        Queue a single file for scanning.
        
        Args:
            filepath: Path to the file to scan
            callback: Optional callback function(filepath, result)
        """
        if not os.path.exists(filepath):
            self.scan_error.emit(filepath, "File not found")
            return
        
        # Add to scan queue
        self.scan_queue.put((filepath, callback))
    
    def start_protection(self):
        """Start real-time file monitoring and protection"""
        if self.protection_active:
            return
        
        # Set the RUNNING event to activate backend workers
        RUNNING.set()
        self.protection_active = True
        
        # Emit status change
        self.protection_status_changed.emit(True)
        self.log_message.emit("Real-time protection started", "INFO")
        
        # TODO: Start file system watchers (main_agent monitoring)
        # For now, just set the flag. Full integration would call:
        # from agent.main_agent import start_workers, start_monitors
        # start_workers()
        # start_monitors()
    
    def stop_protection(self):
        """Pause real-time file monitoring and protection"""
        if not self.protection_active:
            return
        
        # Clear the RUNNING event to pause backend workers
        RUNNING.clear()
        self.protection_active = False
        
        # Emit status change
        self.protection_status_changed.emit(False)
        self.log_message.emit("Real-time protection paused", "WARNING")
    
    def get_quarantined_files(self):
        """
        Get list of all quarantined files with metadata.
        
        Returns:
            List of dicts with keys: filename, threat_type, date_quarantined, 
            quarantine_path, original_path
        """
        quarantined = []
        
        if not QUARANTINE_DIR.exists():
            return quarantined
        
        # Iterate through quarantined files
        for file_path in QUARANTINE_DIR.glob("*"):
            if file_path.is_file() and not file_path.name.endswith('.meta'):
                # Try to load metadata - fix the path construction
                meta_path = Path(str(file_path) + '.meta')
                
                if meta_path.exists():
                    try:
                        with open(meta_path, 'r') as f:
                            metadata = json.load(f)
                    except:
                        metadata = {}
                else:
                    metadata = {}
                
                # Parse filename: timestamp_hash_originalname
                parts = file_path.name.split('_', 2)
                if len(parts) >= 3:
                    timestamp = int(parts[0])
                    file_hash = parts[1]
                    original_name = parts[2]
                    date_quarantined = datetime.fromtimestamp(timestamp)
                else:
                    original_name = file_path.name
                    date_quarantined = datetime.fromtimestamp(file_path.stat().st_mtime)
                    file_hash = "unknown"
                
                quarantined.append({
                    'filename': original_name,
                    'threat_type': metadata.get('threat_type', 'Unknown'),
                    'date_quarantined': date_quarantined.strftime("%Y-%m-%d %H:%M:%S"),
                    'quarantine_path': str(file_path),
                    'original_path': metadata.get('original_path', 'Unknown')
                })
        
        return quarantined
    
    def restore_file_from_quarantine(self, quarantine_path, original_path=None):
        """
        Restore a file from quarantine.
        
        Args:
            quarantine_path: Path to the quarantined file
            original_path: Optional path to restore to (if None, uses metadata)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            quarantine_path = Path(quarantine_path)
            
            # Load metadata to get original path if not provided
            if original_path is None:
                # Construct metadata path correctly
                meta_path = Path(str(quarantine_path) + '.meta')
                if meta_path.exists():
                    with open(meta_path, 'r') as f:
                        metadata = json.load(f)
                        original_path = metadata.get('original_path')
            
            if original_path is None:
                # Extract from filename and restore to Desktop
                parts = quarantine_path.name.split('_', 2)
                if len(parts) >= 3:
                    original_name = parts[2]
                else:
                    original_name = quarantine_path.name
                
                desktop = Path.home() / "Desktop"
                original_path = str(desktop / original_name)
            
            # Restore the file
            restore_file(str(quarantine_path), original_path)
            
            # Delete metadata file if it exists
            meta_path = Path(str(quarantine_path) + '.meta')
            if meta_path.exists():
                meta_path.unlink()
            
            self.log_message.emit(f"Restored file from quarantine: {Path(original_path).name}", "INFO")
            return True
            
        except Exception as e:
            self.log_message.emit(f"Failed to restore file: {str(e)}", "WARNING")
            return False
    
    def delete_quarantined_file(self, quarantine_path):
        """
        Permanently delete a file from quarantine.
        
        Args:
            quarantine_path: Path to the quarantined file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            quarantine_path = Path(quarantine_path)
            
            # Delete the file
            if quarantine_path.exists():
                quarantine_path.unlink()
            
            # Delete metadata file if it exists
            meta_path = Path(str(quarantine_path) + '.meta')
            if meta_path.exists():
                meta_path.unlink()
            
            self.log_message.emit(f"Permanently deleted from quarantine: {quarantine_path.name}", "WARNING")
            return True
            
        except Exception as e:
            self.log_message.emit(f"Failed to delete file: {str(e)}", "WARNING")
            return False
    
    def restore_all_files(self):
        """
        Restore all files from quarantine.
        
        Returns:
            Number of files successfully restored
        """
        restored_count = 0
        quarantined_files = self.get_quarantined_files()
        
        for file_info in quarantined_files:
            quarantine_path = file_info['quarantine_path']
            if self.restore_file_from_quarantine(quarantine_path):
                restored_count += 1
        
        if restored_count > 0:
            self.log_message.emit(f"Restored {restored_count} file(s) from quarantine", "INFO")
        
        return restored_count
    
    def is_protection_active(self):
        """Check if protection is currently active"""
        return self.protection_active
