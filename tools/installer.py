"""
LightAV Installer
Auto-start and installation management
"""

import os
import sys
import ctypes
import winreg
from pathlib import Path
from typing import Optional


class LightAVInstaller:
    """
    Installer for LightAV production scanner.
    
    Handles:
    - Auto-start on boot
    - Registry entries
    - Desktop shortcuts
    - Uninstallation
    """
    
    def __init__(self):
        self.app_name = "LightAV"
        self.install_dir = Path(__file__).parent.parent.resolve()
        self.main_script = self.install_dir / "run_production.py"
        
        # Registry paths
        self.run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        self.uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\LightAV"
    
    def is_admin(self) -> bool:
        """Check if running as administrator."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def install_autostart(self) -> bool:
        """
        Add LightAV to Windows startup.
        
        Returns:
            True if successful
        """
        try:
            # Open registry key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.run_key,
                0,
                winreg.KEY_WRITE
            )
            
            # Add entry
            python_exe = sys.executable
            command = f'"{python_exe}" "{self.main_script}" --agent'
            
            winreg.SetValueEx(key, self.app_name, 0, winreg.REG_SZ, command)
            winreg.CloseKey(key)
            
            print(f"[Installer] Auto-start enabled: {self.app_name}")
            return True
            
        except Exception as e:
            print(f"[Installer] Failed to enable auto-start: {e}")
            return False
    
    def remove_autostart(self) -> bool:
        """
        Remove LightAV from Windows startup.
        
        Returns:
            True if successful
        """
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.run_key,
                0,
                winreg.KEY_WRITE
            )
            
            winreg.DeleteValue(key, self.app_name)
            winreg.CloseKey(key)
            
            print(f"[Installer] Auto-start disabled: {self.app_name}")
            return True
            
        except FileNotFoundError:
            print(f"[Installer] Auto-start was not enabled")
            return True
        except Exception as e:
            print(f"[Installer] Failed to disable auto-start: {e}")
            return False
    
    def check_autostart(self) -> bool:
        """
        Check if auto-start is enabled.
        
        Returns:
            True if auto-start is enabled
        """
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.run_key,
                0,
                winreg.KEY_READ
            )
            
            value, _ = winreg.QueryValueEx(key, self.app_name)
            winreg.CloseKey(key)
            
            return True
            
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    def create_shortcut(self, location: str = "desktop") -> bool:
        """
        Create a shortcut to LightAV.
        
        Args:
            location: 'desktop' or 'startmenu'
            
        Returns:
            True if successful
        """
        try:
            import winshell
            from win32com.client import Dispatch
            
            if location == "desktop":
                shortcut_path = winshell.desktop()
            elif location == "startmenu":
                shortcut_path = winshell.start_menu()
            else:
                print(f"[Installer] Unknown location: {location}")
                return False
            
            shortcut_file = Path(shortcut_path) / f"{self.app_name}.lnk"
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(str(shortcut_file))
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = f'"{self.main_script}"'
            shortcut.WorkingDirectory = str(self.install_dir)
            shortcut.IconLocation = str(self.install_dir / "assets\icon.ico") if (self.install_dir / "assets\icon.ico").exists() else ""
            shortcut.save()
            
            print(f"[Installer] Created shortcut: {shortcut_file}")
            return True
            
        except ImportError:
            print("[Installer] winshell not installed. Cannot create shortcut.")
            print("[Installer] Install with: pip install winshell pywin32")
            return False
        except Exception as e:
            print(f"[Installer] Failed to create shortcut: {e}")
            return False
    
    def install(self) -> bool:
        """
        Full installation of LightAV.
        
        Returns:
            True if successful
        """
        print("=" * 60)
        print(f"Installing {self.app_name}")
        print("=" * 60)
        print()
        
        success = True
        
        # 1. Enable auto-start
        if not self.install_autostart():
            success = False
        
        # 2. Create shortcuts
        self.create_shortcut("desktop")
        self.create_shortcut("startmenu")
        
        print()
        print("Installation complete!")
        print(f"{self.app_name} will start automatically on boot.")
        
        return success
    
    def uninstall(self) -> bool:
        """
        Uninstall LightAV.
        
        Returns:
            True if successful
        """
        print("=" * 60)
        print(f"Uninstalling {self.app_name}")
        print("=" * 60)
        print()
        
        success = True
        
        # 1. Remove auto-start
        if not self.remove_autostart():
            success = False
        
        # 2. Remove shortcuts
        try:
            import winshell
            desktop_shortcut = Path(winshell.desktop()) / f"{self.app_name}.lnk"
            startmenu_shortcut = Path(winshell.start_menu()) / f"{self.app_name}.lnk"
            
            if desktop_shortcut.exists():
                desktop_shortcut.unlink()
                print(f"[Installer] Removed: {desktop_shortcut}")
            
            if startmenu_shortcut.exists():
                startmenu_shortcut.unlink()
                print(f"[Installer] Removed: {startmenu_shortcut}")
                
        except Exception as e:
            print(f"[Installer] Error removing shortcuts: {e}")
        
        print()
        print("Uninstallation complete!")
        
        return success
    
    def get_status(self) -> dict:
        """Get installation status."""
        return {
            'autostart_enabled': self.check_autostart(),
            'install_directory': str(self.install_dir),
            'main_script': str(self.main_script),
            'is_admin': self.is_admin()
        }


def install():
    """Install LightAV."""
    installer = LightAVInstaller()
    return installer.install()


def uninstall():
    """Uninstall LightAV."""
    installer = LightAVInstaller()
    return installer.uninstall()


def status():
    """Show installation status."""
    installer = LightAVInstaller()
    status_info = installer.get_status()
    
    print("=" * 60)
    print("LightAV Installation Status")
    print("=" * 60)
    print()
    print(f"Auto-start: {'Enabled' if status_info['autostart_enabled'] else 'Disabled'}")
    print(f"Install directory: {status_info['install_directory']}")
    print(f"Main script: {status_info['main_script']}")
    print(f"Admin rights: {'Yes' if status_info['is_admin'] else 'No'}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="LightAV Installer")
    parser.add_argument('action', choices=['install', 'uninstall', 'status'],
                       help='Installation action')
    
    args = parser.parse_args()
    
    if args.action == 'install':
        install()
    elif args.action == 'uninstall':
        uninstall()
    elif args.action == 'status':
        status()
