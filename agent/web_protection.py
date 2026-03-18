import os
import ctypes
import threading

HOSTS_FILE = r'C:\Windows\System32\drivers\etc\hosts'
BLOCKLIST = [
    "malicious-site.example.com",
    "phishing-login.example.com",
    "ransomware-c2.example.com"
]
MARKER_START = "# --- LightAV Web Protection Start ---\n"
MARKER_END = "# --- LightAV Web Protection End ---\n"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def enable_web_protection():
    """Adds known malicious domains to the Windows hosts file."""
    if not is_admin():
        print("[WEB-PROTECTION] Cannot enable: LightAV is not running with Administrator privileges.")
        return False
        
    try:
        with open(HOSTS_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
            
        if MARKER_START in content:
            # Already enabled
            return True
            
        with open(HOSTS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n{MARKER_START}")
            for domain in BLOCKLIST:
                f.write(f"0.0.0.0 {domain}\n")
            f.write(MARKER_END)
            
        print("[WEB-PROTECTION] Successfully blocked malicious domains in hosts file.")
        return True
    except Exception as e:
        print(f"[WEB-PROTECTION] Error enabling: {e}")
        return False

def disable_web_protection():
    """Removes LightAV entries from the Windows hosts file."""
    if not is_admin():
        print("[WEB-PROTECTION] Cannot disable: LightAV is not running with Administrator privileges.")
        return False
        
    try:
        with open(HOSTS_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        new_lines = []
        in_block = False
        for line in lines:
            if line.strip() + "\n" == MARKER_START:
                in_block = True
                continue
            if line.strip() + "\n" == MARKER_END:
                in_block = False
                continue
            
            if not in_block:
                new_lines.append(line)
                
        with open(HOSTS_FILE, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
            
        print("[WEB-PROTECTION] Successfully removed blocks from hosts file.")
        return True
    except Exception as e:
        print(f"[WEB-PROTECTION] Error disabling: {e}")
        return False
