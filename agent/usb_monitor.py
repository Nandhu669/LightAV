import win32com.client
import time
from agent.scanner import process_file
from PyQt6.QtWidgets import QMessageBox

def monitor_usb(gui=None):
    wmi = win32com.client.GetObject("winmgmts:")
    watcher = wmi.ExecNotificationQuery(
        "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
    )

    while True:
        event = watcher.NextEvent()
        drive = event.DriveName
        if drive:
            if gui:
                reply = QMessageBox.question(
                    gui,
                    "USB Detected",
                    f"USB device detected at {drive}\nDo you want to scan it?",
                    QMessageBox.StandardButton.Yes |
                    QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.Yes:
                    scan_usb(drive)


def scan_usb(drive_path):
    import os
    for root, _, files in os.walk(drive_path):
        for f in files:
            try:
                process_file(os.path.join(root, f))
            except:
                pass
