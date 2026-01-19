import shutil
from agent.logger import log_restore

def restore_file(quarantine_path, restore_to):
    shutil.move(quarantine_path, restore_to)
    log_restore(quarantine_path, restore_to)
