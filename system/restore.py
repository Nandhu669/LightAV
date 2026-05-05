import shutil
import os
from pathlib import Path
from system.logger import log_restore

def restore_file(quarantine_path, restore_to):
    """
    Restore a file from quarantine to the specified location.
    
    Args:
        quarantine_path: Path to the quarantined file
        restore_to: Destination path to restore the file
    
    Raises:
        Exception: If the restoration fails
    """
    # Ensure the quarantine file exists
    if not os.path.exists(quarantine_path):
        raise FileNotFoundError(f"Quarantined file not found: {quarantine_path}")
    
    # Create destination directory if it doesn't exist
    restore_dir = Path(restore_to).parent
    restore_dir.mkdir(parents=True, exist_ok=True)
    
    # Move the file
    shutil.move(quarantine_path, restore_to)
    
    # Log the restoration
    log_restore(quarantine_path, restore_to)
