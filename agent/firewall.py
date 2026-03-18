import subprocess
import ctypes
import threading

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def toggle_firewall_rule(enable: bool):
    """Adds or removes a custom Windows Firewall rule to block malicious IP ranges."""
    if not is_admin():
        print("[FIREWALL] Cannot execute: LightAV is not running with Administrator privileges.")
        return False
        
    try:
        rule_name = "LightAV_Malicious_IP_Blocklist"
        
        # Remove rule first to avoid duplicates
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True)
        
        if enable:
            # Example: Block a hypothetical bad IP (198.51.100.1)
            bad_ips = "198.51.100.1,203.0.113.50"
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule", 
                f"name={rule_name}", 
                "dir=out", 
                "action=block", 
                f"remoteip={bad_ips}"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("[FIREWALL] Advanced Protection Rule successfully enabled.")
                return True
            else:
                print(f"[FIREWALL] Failed to add rule: {result.stderr}")
                return False
        else:
            print("[FIREWALL] Advanced Protection Rule disabled.")
            return True
            
    except Exception as e:
        print(f"[FIREWALL] Error modifying rules: {e}")
        return False
