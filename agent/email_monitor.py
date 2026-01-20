import time
import os
from agent.scanner import process_file

WATCH_DIR = os.path.expanduser("~/Downloads")

def monitor_email_attachments():
    seen = set()

    while True:
        try:
            files = os.listdir(WATCH_DIR)
            for f in files:
                path = os.path.join(WATCH_DIR, f)
                if path not in seen and os.path.isfile(path):
                    if f.lower().endswith((".exe", ".zip", ".pdf", ".docx")):
                        process_file(path)
                        seen.add(path)
        except:
            pass

        time.sleep(10)
