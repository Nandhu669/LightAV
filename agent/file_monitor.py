"""
LightAV File Monitor Module

Real-time file system monitoring for Windows using watchdog.
Observes user-writable directories and enqueues file paths for processing.

Monitored directories:
    - ~/Downloads
    - ~/Desktop
    - ~/Documents

Monitored extensions:
    - .exe
    - .dll
"""

import os
from queue import Full
from typing import Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


MONITORED_EXTENSIONS = frozenset({".exe", ".dll"})


class FileEventHandler(FileSystemEventHandler):
    """
    Handles file system events and enqueues file paths.
    
    Only processes file creation and modification events for
    files with monitored extensions. All work is deferred by
    enqueuing paths rather than processing in-handler.
    """
    
    __slots__ = ("_queue",)
    
    def __init__(self, queue):
        """
        Initialize the event handler.
        
        Args:
            queue: Thread-safe queue for enqueuing file paths.
        """
        super().__init__()
        self._queue = queue
    
    def _should_process(self, event: FileSystemEvent) -> bool:
        """Check if event should be processed."""
        if event.is_directory:
            return False
        _, ext = os.path.splitext(event.src_path)
        return ext.lower() in MONITORED_EXTENSIONS
    
    def _enqueue(self, path: str) -> None:
        """Enqueue path without blocking. Silently drop if full."""
        try:
            self._queue.put_nowait(path)
        except Full:
            pass
    
    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        if self._should_process(event):
            self._enqueue(event.src_path)
    
    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if self._should_process(event):
            self._enqueue(event.src_path)


def start_monitor(path: str, queue) -> Optional[Observer]:
    """
    Start monitoring a directory for file events.
    
    Args:
        path: Directory path to monitor.
        queue: Thread-safe queue for enqueuing file paths.
        
    Returns:
        Observer instance if started successfully, None otherwise.
    """
    if not os.path.isdir(path):
        return None
    
    handler = FileEventHandler(queue)
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    return observer
