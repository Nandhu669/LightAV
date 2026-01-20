"""
LightAV - Lightweight Antivirus GUI
Professional PyQt6 Desktop Application

Author: LightAV Team
Version: 1.0
"""

import sys
import os
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit,
    QGroupBox, QFrame, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QMimeData
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent, QPalette, QColor
import psutil  # For CPU and RAM monitoring

# Add project root to path for backend imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Import backend controller
from gui.backend_controller import BackendController





class LightAVMainWindow(QMainWindow):
    """Main window for LightAV antivirus application"""
    
    # Signals for thread-safe updates
    log_signal = pyqtSignal(str, str)  # message, level
    status_signal = pyqtSignal(bool)   # is_running
    
    def __init__(self):
        super().__init__()
        
        # Application state
        self.is_protection_running = False
        self.quarantined_files = []
        
        # Initialize backend controller
        self.backend = BackendController()
        
        # Initialize UI
        self.init_ui()
        
        # Connect backend signals to GUI slots
        self.backend.scan_started.connect(self.on_scan_started)
        self.backend.scan_completed.connect(self.on_scan_completed)
        self.backend.scan_error.connect(self.on_scan_error)
        self.backend.log_message.connect(self.add_log)
        self.backend.protection_status_changed.connect(self.update_protection_status)
        
        # Start system monitoring timer
        self.system_timer = QTimer()
        self.system_timer.timeout.connect(self.update_system_stats)
        self.system_timer.start(2000)  # Update every 2 seconds
        
        # Connect signals
        self.log_signal.connect(self.add_log_entry)
        self.status_signal.connect(self.update_protection_status)
        
        # Load existing quarantined files
        self.load_quarantined_files()
        
        # Add initial log
        self.add_log("LightAV initialized successfully", "INFO")
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("LightAV - Lightweight Antivirus")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # ============================================================
        # SECTION 1: HEADER
        # ============================================================
        header_layout = self.create_header()
        main_layout.addLayout(header_layout)
        
        # Add separator
        separator1 = self.create_separator()
        main_layout.addWidget(separator1)
        
        # ============================================================
        # SECTION 2: MAIN PANEL (Scan Area)
        # ============================================================
        scan_group = self.create_scan_panel()
        main_layout.addWidget(scan_group)
        
        # ============================================================
        # SECTION 3: QUARANTINE PANEL
        # ============================================================
        quarantine_group = self.create_quarantine_panel()
        main_layout.addWidget(quarantine_group)
        
        # ============================================================
        # SECTION 4: LOGS PANEL
        # ============================================================
        logs_group = self.create_logs_panel()
        main_layout.addWidget(logs_group, stretch=1)
        
        # ============================================================
        # SECTION 5: CONTROL PANEL
        # ============================================================
        control_layout = self.create_control_panel()
        main_layout.addLayout(control_layout)
        
        # Apply dark theme stylesheet
        self.apply_dark_theme()
    
    def create_header(self):
        """Create the header section with app name, status, and system stats"""
        header_layout = QHBoxLayout()
        header_layout.setSpacing(20)
        
        # App name and logo
        app_name_label = QLabel("🛡️ LightAV")
        app_name_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        app_name_label.setStyleSheet("color: #00BFFF;")
        header_layout.addWidget(app_name_label)
        
        header_layout.addStretch()
        
        # Status indicator
        status_container = QHBoxLayout()
        status_label = QLabel("Status:")
        status_label.setFont(QFont("Segoe UI", 11))
        status_container.addWidget(status_label)
        
        self.status_indicator = QLabel("● PAUSED")
        self.status_indicator.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.status_indicator.setStyleSheet("color: #FF6B6B;")
        status_container.addWidget(self.status_indicator)
        
        header_layout.addLayout(status_container)
        header_layout.addSpacing(30)
        
        # CPU usage
        cpu_container = QHBoxLayout()
        cpu_label = QLabel("CPU:")
        cpu_label.setFont(QFont("Segoe UI", 10))
        cpu_container.addWidget(cpu_label)
        
        self.cpu_value = QLabel("0%")
        self.cpu_value.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.cpu_value.setStyleSheet("color: #4ECDC4;")
        cpu_container.addWidget(self.cpu_value)
        
        header_layout.addLayout(cpu_container)
        header_layout.addSpacing(20)
        
        # RAM usage
        ram_container = QHBoxLayout()
        ram_label = QLabel("RAM:")
        ram_label.setFont(QFont("Segoe UI", 10))
        ram_container.addWidget(ram_label)
        
        self.ram_value = QLabel("0%")
        self.ram_value.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.ram_value.setStyleSheet("color: #4ECDC4;")
        ram_container.addWidget(self.ram_value)
        
        header_layout.addLayout(ram_container)
        
        return header_layout
    
    def create_scan_panel(self):
        """Create the main scan panel with drag and drop area"""
        scan_group = QGroupBox("Quick Scan")
        scan_group.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        scan_layout = QVBoxLayout()
        scan_layout.setSpacing(10)
        
        # Drag and drop area
        self.drop_area = DropArea()
        self.drop_area.setMinimumHeight(150)
        self.drop_area.file_dropped.connect(self.handle_file_drop)
        scan_layout.addWidget(self.drop_area)
        
        # Scan status text
        self.scan_status_label = QLabel("Ready to scan. Drag and drop a file here.")
        self.scan_status_label.setFont(QFont("Segoe UI", 10))
        self.scan_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_status_label.setStyleSheet("color: #95A5A6; padding: 10px;")
        scan_layout.addWidget(self.scan_status_label)
        
        scan_group.setLayout(scan_layout)
        return scan_group
    
    def create_quarantine_panel(self):
        """Create the quarantine panel with file list and restore button"""
        quarantine_group = QGroupBox("Quarantine")
        quarantine_group.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        quarantine_layout = QVBoxLayout()
        quarantine_layout.setSpacing(10)
        
        # Quarantine table
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(
            ["Filename", "Threat Type", "Date Quarantined", "Original Path"]
        )
        self.quarantine_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.quarantine_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.quarantine_table.horizontalHeader().setStretchLastSection(True)
        self.quarantine_table.setMinimumHeight(120)
        self.quarantine_table.setMaximumHeight(180)
        
        # Set column widths
        self.quarantine_table.setColumnWidth(0, 200)
        self.quarantine_table.setColumnWidth(1, 150)
        self.quarantine_table.setColumnWidth(2, 180)
        
        quarantine_layout.addWidget(self.quarantine_table)
        
        # Buttons layout
        button_layout = QHBoxLayout()
        
        # Restore All button on the left
        self.restore_all_button = QPushButton("Restore All")
        self.restore_all_button.setFixedWidth(120)
        self.restore_all_button.clicked.connect(self.restore_all_files)
        button_layout.addWidget(self.restore_all_button)
        
        button_layout.addStretch()
        
        self.restore_button = QPushButton("Restore Selected")
        self.restore_button.setFixedWidth(150)
        self.restore_button.clicked.connect(self.restore_selected_file)
        self.restore_button.setEnabled(False)
        button_layout.addWidget(self.restore_button)
        
        self.delete_button = QPushButton("Delete Permanently")
        self.delete_button.setFixedWidth(150)
        self.delete_button.clicked.connect(self.delete_selected_file)
        self.delete_button.setEnabled(False)
        button_layout.addWidget(self.delete_button)
        
        quarantine_layout.addLayout(button_layout)
        
        # Enable buttons when selection changes
        self.quarantine_table.itemSelectionChanged.connect(self.on_quarantine_selection_changed)
        
        quarantine_group.setLayout(quarantine_layout)
        return quarantine_group
    
    def create_logs_panel(self):
        """Create the logs panel with scrollable timestamped entries"""
        logs_group = QGroupBox("Activity Logs")
        logs_group.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        logs_layout = QVBoxLayout()
        
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setMinimumHeight(150)
        logs_layout.addWidget(self.log_text)
        
        # Clear logs button
        clear_button_layout = QHBoxLayout()
        clear_button_layout.addStretch()
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.setFixedWidth(120)
        clear_logs_btn.clicked.connect(self.clear_logs)
        clear_button_layout.addWidget(clear_logs_btn)
        logs_layout.addLayout(clear_button_layout)
        
        logs_group.setLayout(logs_layout)
        return logs_group
    
    def create_control_panel(self):
        """Create the control panel with start/pause button"""
        control_layout = QHBoxLayout()
        control_layout.setSpacing(15)
        
        # Status message area
        self.control_status_label = QLabel("Protection is currently paused")
        self.control_status_label.setFont(QFont("Segoe UI", 10))
        self.control_status_label.setStyleSheet("color: #95A5A6;")
        control_layout.addWidget(self.control_status_label)
        
        control_layout.addStretch()
        
        # Start/Pause button
        self.toggle_protection_button = QPushButton("▶ Start Protection")
        self.toggle_protection_button.setFixedWidth(180)
        self.toggle_protection_button.setFixedHeight(40)
        self.toggle_protection_button.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.toggle_protection_button.clicked.connect(self.toggle_protection)
        control_layout.addWidget(self.toggle_protection_button)
        
        return control_layout
    
    def create_separator(self):
        """Create a horizontal separator line"""
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet("background-color: #34495E;")
        return separator
    
    def apply_dark_theme(self):
        """Apply professional dark theme stylesheet"""
        dark_stylesheet = """
            QMainWindow {
                background-color: #1E1E2E;
            }
            
            QWidget {
                background-color: #1E1E2E;
                color: #ECEFF4;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            QGroupBox {
                border: 2px solid #2C3E50;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                background-color: #252535;
                font-weight: bold;
                color: #ECEFF4;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #00BFFF;
            }
            
            QPushButton {
                background-color: #3498DB;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
                min-height: 30px;
            }
            
            QPushButton:hover {
                background-color: #5DADE2;
            }
            
            QPushButton:pressed {
                background-color: #2874A6;
            }
            
            QPushButton:disabled {
                background-color: #555555;
                color: #999999;
            }
            
            QPushButton#startButton {
                background-color: #27AE60;
            }
            
            QPushButton#startButton:hover {
                background-color: #2ECC71;
            }
            
            QPushButton#pauseButton {
                background-color: #E67E22;
            }
            
            QPushButton#pauseButton:hover {
                background-color: #F39C12;
            }
            
            QTableWidget {
                background-color: #2C2C3C;
                border: 1px solid #34495E;
                border-radius: 5px;
                gridline-color: #34495E;
                color: #ECEFF4;
            }
            
            QTableWidget::item {
                padding: 5px;
            }
            
            QTableWidget::item:selected {
                background-color: #3498DB;
                color: white;
            }
            
            QHeaderView::section {
                background-color: #34495E;
                color: #ECEFF4;
                padding: 8px;
                border: none;
                border-right: 1px solid #2C3E50;
                border-bottom: 1px solid #2C3E50;
                font-weight: bold;
            }
            
            QTextEdit {
                background-color: #2C2C3C;
                border: 1px solid #34495E;
                border-radius: 5px;
                color: #ECEFF4;
                padding: 10px;
            }
            
            QLabel {
                color: #ECEFF4;
            }
            
            QScrollBar:vertical {
                background-color: #2C2C3C;
                width: 12px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #555555;
                border-radius: 6px;
                min-height: 20px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #666666;
            }
        """
        self.setStyleSheet(dark_stylesheet)
    
    # ============================================================
    # EVENT HANDLERS
    # ============================================================
    
    def toggle_protection(self):
        """Toggle protection on/off"""
        self.is_protection_running = not self.is_protection_running
        
        if self.is_protection_running:
            self.start_protection()
        else:
            self.pause_protection()
    
    def start_protection(self):
        """Start real-time protection"""
        self.is_protection_running = True
        
        # Call backend to start protection
        self.backend.start_protection()
        
        # Update UI
        self.status_indicator.setText("● RUNNING")
        self.status_indicator.setStyleSheet("color: #2ECC71;")
        
        self.toggle_protection_button.setText("⏸ Pause Protection")
        self.toggle_protection_button.setObjectName("pauseButton")
        self.toggle_protection_button.setStyleSheet("")  # Reapply stylesheet
        
        self.control_status_label.setText("Protection is active and monitoring your system")
        self.control_status_label.setStyleSheet("color: #2ECC71;")
        

    
    def pause_protection(self):
        """Pause real-time protection"""
        self.is_protection_running = False
        
        # Call backend to stop protection
        self.backend.stop_protection()
        
        # Update UI
        self.status_indicator.setText("● PAUSED")
        self.status_indicator.setStyleSheet("color: #FF6B6B;")
        
        self.toggle_protection_button.setText("▶ Start Protection")
        self.toggle_protection_button.setObjectName("startButton")
        self.toggle_protection_button.setStyleSheet("")  # Reapply stylesheet
        
        self.control_status_label.setText("Protection is currently paused")
        self.control_status_label.setStyleSheet("color: #95A5A6;")
        

    
    def handle_file_drop(self, filepath):
        """Handle file dropped in scan area"""
        # Call backend to scan the file
        self.backend.scan_single_file(filepath)
    
    def on_scan_started(self, filepath):
        """Called when a scan starts (from backend signal)"""
        self.scan_status_label.setText(f"Scanning: {filepath}")
        self.scan_status_label.setStyleSheet("color: #F39C12; padding: 10px;")
    
    def on_scan_completed(self, filepath, result, elapsed_ms):
        """Called when scan is complete (from backend signal)"""
        if result == "CLEAN":
            self.scan_status_label.setText(f"✓ Clean: {filepath}")
            self.scan_status_label.setStyleSheet("color: #2ECC71; padding: 10px;")
        else:
            self.scan_status_label.setText(f"⚠ Threat detected: {filepath}")
            self.scan_status_label.setStyleSheet("color: #E74C3C; padding: 10px;")
            # Reload quarantined files to show the new quarantined file
            self.load_quarantined_files()
    
    def on_scan_error(self, filepath, error_msg):
        """Called when scan encounters an error (from backend signal)"""
        self.scan_status_label.setText(f"⚠ Error scanning: {filepath}")
        self.scan_status_label.setStyleSheet("color: #E74C3C; padding: 10px;")
    
    def load_quarantined_files(self):
        """Load quarantined files from backend and populate table"""
        # Clear existing table
        self.quarantine_table.setRowCount(0)
        
        # Get quarantined files from backend
        quarantined = self.backend.get_quarantined_files()
        
        # Populate table
        for item in quarantined:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(item['filename']))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(item['threat_type']))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(item['date_quarantined']))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem(item['quarantine_path']))
    
    def on_quarantine_selection_changed(self):
        """Enable/disable buttons based on selection"""
        has_selection = len(self.quarantine_table.selectedItems()) > 0
        self.restore_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)
    
    def restore_selected_file(self):
        """Restore selected file from quarantine"""
        selected_rows = set(item.row() for item in self.quarantine_table.selectedItems())
        
        for row in sorted(selected_rows, reverse=True):
            quarantine_path = self.quarantine_table.item(row, 3).text()
            
            # Call backend to restore file
            success = self.backend.restore_file_from_quarantine(quarantine_path)
            
            if success:
                # Reload quarantined files
                self.load_quarantined_files()
    
    def delete_selected_file(self):
        """Permanently delete selected file from quarantine"""
        selected_rows = set(item.row() for item in self.quarantine_table.selectedItems())
        
        for row in sorted(selected_rows, reverse=True):
            quarantine_path = self.quarantine_table.item(row, 3).text()
            
            # Call backend to delete file
            success = self.backend.delete_quarantined_file(quarantine_path)
            
            if success:
                # Reload quarantined files
                self.load_quarantined_files()
    
    def restore_all_files(self):
        """Restore all files from quarantine"""
        # Call backend to restore all files
        restored_count = self.backend.restore_all_files()
        
        if restored_count > 0:
            # Reload quarantined files to refresh the table
            self.load_quarantined_files()
    
    def add_log(self, message, level="INFO"):
        """Add log entry with timestamp and color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        if level == "INFO":
            color = "#4ECDC4"
        elif level == "WARNING":
            color = "#F39C12"
        elif level == "THREAT":
            color = "#E74C3C"
        else:
            color = "#ECEFF4"
        
        # Format log entry
        log_entry = f'<span style="color: #95A5A6;">[{timestamp}]</span> <span style="color: {color};">[{level}]</span> {message}'
        
        # Add to log text area
        self.log_text.append(log_entry)
        
        # Auto-scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def add_log_entry(self, message, level):
        """Slot for thread-safe log updates"""
        self.add_log(message, level)
    
    def update_protection_status(self, is_running):
        """Slot for thread-safe status updates"""
        if is_running:
            self.start_protection()
        else:
            self.pause_protection()
    
    def clear_logs(self):
        """Clear all log entries"""
        self.log_text.clear()
        self.add_log("Logs cleared", "INFO")
    
    def update_system_stats(self):
        """Update CPU and RAM usage displays"""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.cpu_value.setText(f"{cpu_percent:.1f}%")
            
            # Get RAM usage
            ram = psutil.virtual_memory()
            ram_percent = ram.percent
            self.ram_value.setText(f"{ram_percent:.1f}%")
            
            # Color coding based on usage
            if cpu_percent > 80:
                self.cpu_value.setStyleSheet("color: #E74C3C;")
            elif cpu_percent > 50:
                self.cpu_value.setStyleSheet("color: #F39C12;")
            else:
                self.cpu_value.setStyleSheet("color: #4ECDC4;")
            
            if ram_percent > 80:
                self.ram_value.setStyleSheet("color: #E74C3C;")
            elif ram_percent > 50:
                self.ram_value.setStyleSheet("color: #F39C12;")
            else:
                self.ram_value.setStyleSheet("color: #4ECDC4;")
                
        except Exception as e:
            self.cpu_value.setText("N/A")
            self.ram_value.setText("N/A")


class DropArea(QFrame):
    """Custom widget for drag and drop file scanning"""
    
    file_dropped = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.init_ui()
    
    def init_ui(self):
        """Initialize drop area UI"""
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            DropArea {
                background-color: #2C2C3C;
                border: 2px dashed #3498DB;
                border-radius: 8px;
            }
            DropArea:hover {
                background-color: #34344C;
                border-color: #5DADE2;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Icon and text
        drop_label = QLabel("📁 Drag & Drop File Here to Scan")
        drop_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        drop_label.setStyleSheet("color: #3498DB; border: none;")
        drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(drop_label)
        
        hint_label = QLabel("or click to browse")
        hint_label.setFont(QFont("Segoe UI", 9))
        hint_label.setStyleSheet("color: #95A5A6; border: none;")
        hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(hint_label)
        
        self.setLayout(layout)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("""
                DropArea {
                    background-color: #34495E;
                    border: 3px dashed #2ECC71;
                    border-radius: 8px;
                }
            """)
    
    def dragLeaveEvent(self, event):
        """Handle drag leave event"""
        self.setStyleSheet("""
            DropArea {
                background-color: #2C2C3C;
                border: 2px dashed #3498DB;
                border-radius: 8px;
            }
        """)
    
    def dropEvent(self, event: QDropEvent):
        """Handle file drop event"""
        urls = event.mimeData().urls()
        if urls:
            filepath = urls[0].toLocalFile()
            self.file_dropped.emit(filepath)
        
        # Reset style
        self.setStyleSheet("""
            DropArea {
                background-color: #2C2C3C;
                border: 2px dashed #3498DB;
                border-radius: 8px;
            }
        """)
        
        event.acceptProposedAction()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application-wide font
    app.setFont(QFont("Segoe UI", 10))
    
    # Create and show main window
    window = LightAVMainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
