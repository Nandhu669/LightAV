"""
LightAV PyQt container with embedded React UI
"""
import sys
import os
import threading
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl, QObject, pyqtSlot, pyqtSignal
from PyQt6.QtWebChannel import QWebChannel

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def run_server():
    """Run FastAPI server in background thread"""
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, log_level="error")

class Bridge(QObject):
    usb_detected = pyqtSignal(str)
    
    @pyqtSlot(str)
    def log(self, message):
        print(f"[JS-LOG] {message}", flush=True)

    @pyqtSlot(result=str)
    def select_file(self):
        print("[Bridge] select_file called", flush=True)
        file_path, _ = QFileDialog.getOpenFileName(None, "Select File to Scan")
        print(f"[Bridge] Selected file: {file_path}", flush=True)
        return file_path

    @pyqtSlot(result=str)
    def select_folder(self):
        print("[Bridge] select_folder called", flush=True)
        folder_path = QFileDialog.getExistingDirectory(None, "Select Folder to Scan")
        print(f"[Bridge] Selected folder: {folder_path}", flush=True)
        return folder_path

from PyQt6.QtWebEngineCore import QWebEnginePage

class CustomPage(QWebEnginePage):
    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        print(f"[JS] {message} ({sourceID}:{lineNumber})")

class LightAVWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LightAV")
        self.setGeometry(100, 100, 1200, 800)
        
        # Start FastAPI server
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Wait for server to start
        import time
        time.sleep(2)
        
        # Setup WebChannel
        self.bridge = Bridge()
        self.channel = QWebChannel()
        self.channel.registerObject("pybridge", self.bridge)
        
        # Embed web view
        self.browser = QWebEngineView()
        self.browser.setPage(CustomPage(self))
        self.browser.page().setWebChannel(self.channel)
        
        self.browser.setUrl(QUrl("http://127.0.0.1:8000"))
        self.setCentralWidget(self.browser)

        # Connect USB detection signal
        self.bridge.usb_detected.connect(self.handle_usb_detected)
        
        # Start USB monitor thread
        from agent.usb_monitor import monitor_usb
        usb_thread = threading.Thread(target=monitor_usb, args=(self.bridge.usb_detected,), daemon=True)
        usb_thread.start()

    def handle_usb_detected(self, drive):
        reply = QMessageBox.question(
            self,
            "USB Detected",
            f"USB device detected at {drive}\nDo you want to scan it for threats?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            from agent.usb_monitor import scan_usb
            threading.Thread(target=scan_usb, args=(drive,), daemon=True).start()

def main():
    app = QApplication(sys.argv)
    window = LightAVWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
