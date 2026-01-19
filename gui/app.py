import sys
from pathlib import Path
import psutil
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit,
    QListWidget, QMessageBox, QFileDialog, QProgressBar, QFrame,
    QScrollArea
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QShortcut, QKeySequence

try:
    from plyer import notification
    HAS_NOTIFICATIONS = True
except ImportError:
    HAS_NOTIFICATIONS = False

from agent.runtime_state import RUNNING
from agent.log_reader import read_last_lines
from agent.scanner import process_file
from agent.restore import restore_file
from agent.decision_types import Verdict

QUARANTINE_DIR = Path("quarantine/files")


class LightAVGUI(QWidget):
    def __init__(self):
        super().__init__()

        # Scan statistics
        self.scan_count = 0
        self.threat_count = 0
        self.safe_count = 0
        self.scan_history = []

        self.setWindowTitle("LightAV - Antivirus Scanner")
        self.setStyleSheet("""
    QWidget {
        background-color: #121212;
        color: #eaeaea;
        font-size: 14px;
    }

    QLabel {
        padding: 4px;
    }

    QPushButton {
        background-color: #1f1f1f;
        border: 1px solid #333;
        padding: 8px;
        border-radius: 6px;
    }

    QPushButton:hover {
        background-color: #2a2a2a;
    }

    QPushButton:pressed {
        background-color: #3a3a3a;
    }

    QTextEdit {
        background-color: #1b1b1b;
        border: 1px solid #333;
        border-radius: 6px;
    }

    QListWidget {
        background-color: #1b1b1b;
        border: 1px solid #333;
        border-radius: 6px;
    }
""")

        self.setGeometry(200, 200, 800, 750)
        self.setMinimumWidth(600)
        self.setAcceptDrops(True)

        layout = QVBoxLayout()
        layout.setSpacing(8)

        # Status
        self.status = QLabel("🟢 Status: Running")
        self.status.setStyleSheet("font-weight: bold; font-size: 15px;")
        layout.addWidget(self.status)

        # CPU / RAM
        self.sys_stats = QLabel("💻 CPU: 0% | 🧠 RAM: 0%")
        layout.addWidget(self.sys_stats)

        # ===== SCAN STATISTICS PANEL =====
        self.stats_frame = QFrame()
        self.stats_frame.setStyleSheet("""
            QFrame {
                background-color: #1a1a2e;
                border: 1px solid #16213e;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        stats_layout = QHBoxLayout(self.stats_frame)
        
        self.stats_label = QLabel("📊 Scans: 0 | ✅ Safe: 0 | 🚨 Threats: 0")
        self.stats_label.setStyleSheet("font-weight: bold; border: none;")
        stats_layout.addWidget(self.stats_label)
        
        layout.addWidget(self.stats_frame)

        # Control button
        self.toggle_btn = QPushButton("⏸️ Pause Scanner")
        self.toggle_btn.clicked.connect(self.toggle_scanner)
        layout.addWidget(self.toggle_btn)

        # Drag & Drop info
        self.drop_label = QLabel("📂 Drag & drop files here to scan")
        self.drop_label.setStyleSheet(
            "border: 2px dashed #444; padding: 15px; text-align: center;"
        )
        layout.addWidget(self.drop_label)

        # ===== SCAN BUTTONS ROW =====
        scan_btn_layout = QHBoxLayout()
        
        self.select_file_btn = QPushButton("📁 Select File (Ctrl+O)")
        self.select_file_btn.clicked.connect(self.select_file_to_scan)
        scan_btn_layout.addWidget(self.select_file_btn)
        
        self.select_folder_btn = QPushButton("📂 Scan Folder (Ctrl+D)")
        self.select_folder_btn.clicked.connect(self.select_folder_to_scan)
        scan_btn_layout.addWidget(self.select_folder_btn)
        
        layout.addLayout(scan_btn_layout)

        # Scan Results Section
        self.scan_frame = QFrame()
        self.scan_frame.setStyleSheet("""
            QFrame {
                background-color: #1a1a1a;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        scan_layout = QVBoxLayout(self.scan_frame)
        
        self.scan_title = QLabel("🔍 Scan Results")
        self.scan_title.setStyleSheet("font-weight: bold; font-size: 14px; border: none;")
        scan_layout.addWidget(self.scan_title)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 0)  # Indeterminate
        self.scan_progress.setVisible(False)
        self.scan_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 4px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
        """)
        scan_layout.addWidget(self.scan_progress)
        
        self.scan_result = QLabel("No file scanned yet")
        self.scan_result.setStyleSheet("color: #888; border: none;")
        self.scan_result.setWordWrap(True)
        scan_layout.addWidget(self.scan_result)
        
        layout.addWidget(self.scan_frame)

        # ===== SCAN HISTORY SECTION =====
        self.history_label = QLabel("🕐 Scan History (Last 5)")
        self.history_label.setStyleSheet("font-weight: bold; margin-top: 5px;")
        layout.addWidget(self.history_label)
        
        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(80)
        self.history_list.setStyleSheet("""
            QListWidget {
                background-color: #1b1b1b;
                border: 1px solid #333;
                border-radius: 6px;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.history_list)

        # ===== QUARANTINE SECTION =====
        self.quarantine_label = QLabel("🔒 Quarantined Files:")
        self.quarantine_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.quarantine_label)

        self.quarantine_list = QListWidget()
        self.quarantine_list.setMaximumHeight(80)
        # Truncate long filenames
        self.quarantine_list.setStyleSheet("""
            QListWidget {
                background-color: #1b1b1b;
                border: 1px solid #333;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 4px;
            }
        """)
        self.quarantine_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(self.quarantine_list)

        self.restore_btn = QPushButton("♻️ Restore Selected File")
        self.restore_btn.clicked.connect(self.restore_selected)
        layout.addWidget(self.restore_btn)

        # ===== LOGS SECTION WITH CLEAR BUTTON =====
        logs_header = QHBoxLayout()
        logs_title = QLabel("📜 Live Logs")
        logs_title.setStyleSheet("font-weight: bold;")
        logs_header.addWidget(logs_title)
        logs_header.addStretch()
        
        self.clear_logs_btn = QPushButton("🧹 Clear")
        self.clear_logs_btn.setMaximumWidth(80)
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        logs_header.addWidget(self.clear_logs_btn)
        
        layout.addLayout(logs_header)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(120)
        self.log_view.setStyleSheet("""
            font-family: Consolas, monospace;
            font-size: 11px;
        """)
        layout.addWidget(self.log_view)

        self.setLayout(layout)

        # ===== KEYBOARD SHORTCUTS =====
        self.shortcut_open = QShortcut(QKeySequence("Ctrl+O"), self)
        self.shortcut_open.activated.connect(self.select_file_to_scan)
        
        self.shortcut_folder = QShortcut(QKeySequence("Ctrl+D"), self)
        self.shortcut_folder.activated.connect(self.select_folder_to_scan)
        
        self.shortcut_quit = QShortcut(QKeySequence("Ctrl+Q"), self)
        self.shortcut_quit.activated.connect(self.close)

        # Timers
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_all)
        self.timer.start(2000)

        self.refresh_all()

    # ---------------- GUI EVENTS ----------------

    def toggle_scanner(self):
        if RUNNING.is_set():
            RUNNING.clear()
            self.status.setText("⏸️ Status: Paused")
            self.toggle_btn.setText("▶️ Resume Scanner")
        else:
            RUNNING.set()
            self.status.setText("🟢 Status: Running")
            self.toggle_btn.setText("⏸️ Pause Scanner")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            self._scan_file(file_path)

    def select_file_to_scan(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Scan",
            "",
            "All Files (*.*)"
        )
        if file_path:
            self._scan_file(file_path)

    def select_folder_to_scan(self):
        """Select and scan all files in a folder."""
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Scan",
            ""
        )
        if folder_path:
            folder = Path(folder_path)
            files = [f for f in folder.rglob("*") if f.is_file()]
            
            if not files:
                QMessageBox.information(self, "Scan Folder", "No files found in folder.")
                return
            
            total = len(files)
            threats_before = self.threat_count
            
            self.status.setText(f"📂 Scanning folder: {folder.name} (0/{total})")
            self.scan_progress.setVisible(True)
            self.scan_progress.setRange(0, total)
            self.scan_progress.setValue(0)
            
            for i, file in enumerate(files):
                self.scan_progress.setValue(i + 1)
                self.scan_result.setText(f"Scanning {i+1}/{total}: {file.name}")
                self.status.setText(f"📂 Scanning folder: {folder.name} ({i+1}/{total})")
                QApplication.processEvents()
                self._scan_file_silent(str(file))
            
            self.scan_progress.setVisible(False)
            self.scan_progress.setRange(0, 0)  # Reset to indeterminate
            
            threats_found = self.threat_count - threats_before
            self.status.setText(f"✅ Folder scan complete: {total} files, {threats_found} threats")
            self.scan_result.setText(f"📂 FOLDER SCAN COMPLETE\n\nFolder: {folder.name}\nFiles: {total}\nThreats: {threats_found}")
            if threats_found > 0:
                self.scan_result.setStyleSheet("color: #FF9800; border: none; font-weight: bold;")
            else:
                self.scan_result.setStyleSheet("color: #4CAF50; border: none; font-weight: bold;")
            
            # Show summary notification
            if HAS_NOTIFICATIONS:
                notification.notify(
                    title="LightAV - Folder Scan Complete",
                    message=f"Scanned {total} files. Found {threats_found} threats.",
                    timeout=5
                )

    def _scan_file_silent(self, file_path):
        """Scan a file without updating UI result panel."""
        filename = Path(file_path).name
        
        try:
            verdict = process_file(file_path)
            
            self.scan_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if verdict == Verdict.MALICIOUS:
                self.threat_count += 1
                self._add_to_history(f"🚨 {timestamp} - {filename[:30]}... (THREAT)" if len(filename) > 30 else f"🚨 {timestamp} - {filename} (THREAT)")
                self.update_quarantine()
            else:
                self.safe_count += 1
                self._add_to_history(f"✅ {timestamp} - {filename[:30]}..." if len(filename) > 30 else f"✅ {timestamp} - {filename} (Safe)")
            
            self._update_stats_display()
            
        except Exception:
            pass  # Silent fail for folder scanning

    def _scan_file(self, file_path, show_notification=True):
        """Scan a file with visual feedback."""
        filename = Path(file_path).name
        display_name = filename[:40] + "..." if len(filename) > 40 else filename
        
        # Show scanning state
        self.status.setText(f"🔄 Scanning: {display_name}")
        self.scan_progress.setVisible(True)
        self.scan_result.setText(f"Scanning {display_name}...")
        self.scan_result.setStyleSheet("color: #64B5F6; border: none;")
        QApplication.processEvents()
        
        try:
            verdict = process_file(file_path)
            self.scan_progress.setVisible(False)
            
            self.scan_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if verdict == Verdict.MALICIOUS:
                self.threat_count += 1
                self.status.setText(f"⚠️ Threat: {display_name}")
                self.scan_result.setText(f"🚨 THREAT DETECTED\n\nFile: {display_name}\nStatus: Malicious - Quarantined")
                self.scan_result.setStyleSheet("color: #FF5252; border: none; font-weight: bold;")
                self.update_quarantine()
                
                self._add_to_history(f"🚨 {timestamp} - {display_name} (THREAT)")
                
                if show_notification and HAS_NOTIFICATIONS:
                    notification.notify(
                        title="🚨 LightAV - Threat Detected!",
                        message=f"Malicious file: {display_name}\nFile has been quarantined.",
                        timeout=10
                    )
            else:
                self.safe_count += 1
                self.status.setText(f"✅ Safe: {display_name}")
                self.scan_result.setText(f"✅ FILE IS SAFE\n\nFile: {display_name}\nStatus: No threats detected")
                self.scan_result.setStyleSheet("color: #4CAF50; border: none; font-weight: bold;")
                
                self._add_to_history(f"✅ {timestamp} - {display_name} (Safe)")
            
            self._update_stats_display()
            
        except Exception as e:
            self.scan_progress.setVisible(False)
            self.status.setText(f"❌ Error: {display_name}")
            self.scan_result.setText(f"❌ ERROR\n\nFile: {display_name}\nError: {str(e)[:100]}")
            self.scan_result.setStyleSheet("color: #FF9800; border: none;")

    def _add_to_history(self, entry):
        """Add an entry to scan history (keep last 5)."""
        self.scan_history.insert(0, entry)
        self.scan_history = self.scan_history[:5]
        
        self.history_list.clear()
        for item in self.scan_history:
            self.history_list.addItem(item)

    def _update_stats_display(self):
        """Update the statistics panel."""
        self.stats_label.setText(
            f"📊 Scans: {self.scan_count} | ✅ Safe: {self.safe_count} | 🚨 Threats: {self.threat_count}"
        )

    def clear_logs(self):
        """Clear the log view."""
        self.log_view.clear()

    # ---------------- SYSTEM UPDATES ----------------

    def refresh_all(self):
        self.update_logs()
        self.update_quarantine()
        self.update_system_stats()

    def update_logs(self):
        if self.log_view.toPlainText() == "" and not read_last_lines(1):
            return
            
        lines = read_last_lines(30)
        new_text = "".join(lines)
        
        scrollbar = self.log_view.verticalScrollBar()
        at_bottom = scrollbar.value() >= scrollbar.maximum() - 20
        
        if self.log_view.toPlainText() != new_text:
            self.log_view.setText(new_text)
            
            if at_bottom:
                scrollbar.setValue(scrollbar.maximum())

    def update_quarantine(self):
        self.quarantine_list.clear()
        if QUARANTINE_DIR.exists():
            for f in QUARANTINE_DIR.iterdir():
                # Truncate long filenames for display
                name = f.name
                display_name = name[:50] + "..." if len(name) > 50 else name
                self.quarantine_list.addItem(display_name)

    def update_system_stats(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.sys_stats.setText(f"💻 CPU: {cpu}% | 🧠 RAM: {mem}%")

    # ---------------- RESTORE ----------------

    def restore_selected(self):
        item = self.quarantine_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Restore", "No file selected.")
            return

        # Find actual file (handle truncated names)
        display_name = item.text()
        q_file = None
        
        if QUARANTINE_DIR.exists():
            for f in QUARANTINE_DIR.iterdir():
                if f.name.startswith(display_name.replace("...", "")):
                    q_file = f
                    break
        
        if not q_file or not q_file.exists():
            QMessageBox.warning(self, "Restore", "File not found in quarantine.")
            return

        restore_path = Path("restored")
        restore_path.mkdir(exist_ok=True)
        restore_file(q_file, restore_path)

        QMessageBox.information(self, "Restore", "File restored successfully.")
        self.update_quarantine()


def main():
    app = QApplication(sys.argv)
    gui = LightAVGUI()
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
