import subprocess
import ctypes
import threading

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def toggle_privacy_guard(enable: bool):
    """Adds or removes privacy hardening tweaks to the Windows Registry."""
    if not is_admin():
        print("[PRIVACY-GUARD] Cannot execute: LightAV is not running with Administrator privileges.")
        return False
        
    try:
        if enable:
            # Disable Windows Telemetry (AllowTelemetry = 0)
            subprocess.run([
                "powershell", "-Command",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Value 0 -Type DWord -Force"
            ], capture_output=True)
            # Disable Advertising ID
            subprocess.run([
                "powershell", "-Command",
                "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' -Name 'Enabled' -Value 0 -Type DWord -Force"
            ], capture_output=True)
            print("[PRIVACY-GUARD] System telemetry and ad tracking disabled.")
            return True
        else:
            # Re-enable Windows Telemetry (AllowTelemetry = 1 for Basic)
            subprocess.run([
                "powershell", "-Command",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Value 1 -Type DWord -Force"
            ], capture_output=True)
            # Re-enable Advertising ID
            subprocess.run([
                "powershell", "-Command",
                "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' -Name 'Enabled' -Value 1 -Type DWord -Force"
            ], capture_output=True)
            print("[PRIVACY-GUARD] Telemetry restored to Windows defaults.")
            return True
            
    except Exception as e:
        print(f"[PRIVACY-GUARD] Error altering privacy settings: {e}")
        return False
