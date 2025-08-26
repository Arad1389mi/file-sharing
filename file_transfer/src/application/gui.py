import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit, 
                            QComboBox, QTableWidget, QTableWidgetItem, QFileDialog, 
                            QHeaderView, QMessageBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor
from datetime import datetime

class FileTransferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Transfer System")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize database
        self.db_path = "logs/file_transfers.db"
        self.init_db()
        
        # Create main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout()
        self.main_widget.setLayout(self.main_layout)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_file_transfer_tab()
        self.create_log_viewer_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Auto-refresh logs every 5 seconds
        self.log_refresh_timer = QTimer()
        self.log_refresh_timer.timeout.connect(self.load_logs)
        self.log_refresh_timer.start(5000)
        
        # Load initial data
        self.load_logs()
    
    def init_db(self):
        """Initialize the database with required tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transfer_type TEXT NOT NULL,
                    transfer_date TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    source TEXT,
                    destination TEXT,
                    src_directory TEXT,
                    dst_directory TEXT,
                    status TEXT
                )
            """)
            conn.commit()
    
    def create_file_transfer_tab(self):
        """Create the file transfer tab with all controls"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Protocol selection
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["FTP", "SFTP", "SCP", "HTTP", "HTTPS"])
        protocol_layout.addWidget(self.protocol_combo)
        protocol_layout.addStretch()
        
        # Transfer type
        transfer_layout = QHBoxLayout()
        transfer_layout.addWidget(QLabel("Transfer Type:"))
        self.transfer_type_combo = QComboBox()
        self.transfer_type_combo.addItems(["Send", "Receive"])
        transfer_layout.addWidget(self.transfer_type_combo)
        transfer_layout.addStretch()
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select file or directory...")
        file_layout.addWidget(self.file_path_edit)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_files)
        file_layout.addWidget(self.browse_button)
        
        # Destination
        dest_layout = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("Destination path or URL...")
        dest_layout.addWidget(self.dest_edit)
        self.browse_dest_button = QPushButton("Browse...")
        self.browse_dest_button.clicked.connect(self.browse_destination)
        dest_layout.addWidget(self.browse_dest_button)
        
        # Transfer button
        self.transfer_button = QPushButton("Start Transfer")
        self.transfer_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.transfer_button.clicked.connect(self.start_transfer)
        
        # Progress/status display (using HTML for rich text)
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.status_display.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        # Add all widgets to layout
        layout.addLayout(protocol_layout)
        layout.addLayout(transfer_layout)
        layout.addLayout(file_layout)
        layout.addLayout(dest_layout)
        layout.addWidget(self.transfer_button)
        layout.addWidget(QLabel("<b>Transfer Status:</b>"))
        layout.addWidget(self.status_display)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "File Transfer")
    
    def create_log_viewer_tab(self):
        """Create the log viewer tab with table display"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        # Protocol filter
        filter_layout.addWidget(QLabel("Protocol:"))
        self.log_protocol_filter = QComboBox()
        self.log_protocol_filter.addItem("All", None)
        self.log_protocol_filter.addItems(["FTP", "SFTP", "SCP", "HTTP", "HTTPS"])
        filter_layout.addWidget(self.log_protocol_filter)
        
        # Transfer type filter
        filter_layout.addWidget(QLabel("Type:"))
        self.log_type_filter = QComboBox()
        self.log_type_filter.addItem("All", None)
        self.log_type_filter.addItems(["Send", "Receive"])
        filter_layout.addWidget(self.log_type_filter)
        
        # Date filter
        filter_layout.addWidget(QLabel("Date:"))
        self.log_date_filter = QComboBox()
        self.log_date_filter.addItem("All", None)
        self.log_date_filter.addItems(["Today", "Last 7 days", "This month"])
        filter_layout.addWidget(self.log_date_filter)
        
        # Refresh button
        self.refresh_logs_button = QPushButton("Refresh")
        self.refresh_logs_button.clicked.connect(self.load_logs)
        filter_layout.addWidget(self.refresh_logs_button)
        
        # Clear filters button
        self.clear_filters_button = QPushButton("Clear Filters")
        self.clear_filters_button.clicked.connect(self.clear_log_filters)
        filter_layout.addWidget(self.clear_filters_button)
        
        # Log table
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(8)
        self.log_table.setHorizontalHeaderLabels([
            "Date/Time", "Type", "Protocol", "File", "Size", "Source", "Destination", "Status"
        ])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Add widgets to layout
        layout.addLayout(filter_layout)
        layout.addWidget(self.log_table)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Transfer Logs")
    
    def create_settings_tab(self):
        """Create the settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Add settings controls here
        layout.addWidget(QLabel("<h2>Application Settings</h2>"))
        layout.addWidget(QLabel("<i>Settings functionality to be implemented</i>"))
        layout.addStretch()
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Settings")
    
    def browse_files(self):
        """Open file dialog to select source file/directory"""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Transfer", "", "All Files (*)", options=options)
        if file_path:
            self.file_path_edit.setText(file_path)
    
    def browse_destination(self):
        """Open directory dialog to select destination"""
        options = QFileDialog.Options()
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Destination Directory", "", options=options)
        if dir_path:
            self.dest_edit.setText(dir_path)
    
    def start_transfer(self):
        """Handle file transfer initiation"""
        file_path = self.file_path_edit.text()
        dest_path = self.dest_edit.text()
        protocol = self.protocol_combo.currentText()
        transfer_type = self.transfer_type_combo.currentText()
        
        if not file_path or not dest_path:
            QMessageBox.warning(self, "Error", "Please select both source and destination paths")
            return
        
        # Update status with HTML formatting
        self.update_status(f"""
            <div style='color: #2c3e50; font-weight: bold;'>
                Starting {transfer_type.lower()} transfer via {protocol}...
            </div>
            <div style='margin-top: 5px;'>
                <b>Source:</b> {file_path}<br>
                <b>Destination:</b> {dest_path}
            </div>
        """)
        
        # In a real application, you would start the actual transfer here
        # For demonstration, we'll simulate a transfer
        QTimer.singleShot(2000, lambda: self.simulate_transfer_complete(file_path, dest_path, protocol, transfer_type))
    
    def simulate_transfer_complete(self, file_path, dest_path, protocol, transfer_type):
        """Simulate a completed file transfer (for demo purposes)"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # Log the transfer
        self.log_transfer(
            transfer_type="sent" if transfer_type == "Send" else "received",
            protocol=protocol,
            file_name=file_name,
            file_size=file_size,
            source="localhost",
            destination="remote_server",
            src_directory=os.path.dirname(file_path),
            dst_directory=dest_path,
            status="Completed"
        )
        
        # Update status with HTML formatting
        self.update_status(f"""
            <div style='color: #27ae60; font-weight: bold;'>
                Transfer completed successfully!
            </div>
            <div style='margin-top: 5px;'>
                <b>File:</b> {file_name}<br>
                <b>Size:</b> {self.format_file_size(file_size)}<br>
                <b>Time:</b> {datetime.now().strftime('%H:%M:%S')}
            </div>
        """)
        
        # Refresh logs
        self.load_logs()
    
    def log_transfer(self, transfer_type, protocol, file_name, file_size, 
                    source, destination, src_directory, dst_directory, status):
        """Log a file transfer to the database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO file_transfers (
                    transfer_type, transfer_date, protocol, file_name, 
                    file_size, source, destination, src_directory, dst_directory, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transfer_type, datetime.now().isoformat(), protocol, file_name,
                file_size, source, destination, src_directory, dst_directory, status
            ))
            conn.commit()
    
    def load_logs(self):
        """Load transfer logs from database and display in table"""
        protocol_filter = self.log_protocol_filter.currentData()
        type_filter = self.log_type_filter.currentData()
        
        query = "SELECT * FROM file_transfers ORDER BY transfer_date DESC LIMIT 100"
        params = []
        
        conditions = []
        if protocol_filter:
            conditions.append("protocol = ?")
            params.append(protocol_filter)
        if type_filter:
            conditions.append("transfer_type = ?")
            params.append(type_filter.lower())
        
        if conditions:
            query = query.replace("FROM", "FROM (" + query + ") WHERE " + " AND ".join(conditions))
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            logs = cursor.fetchall()
        
        self.log_table.setRowCount(len(logs))
        
        for row_idx, log in enumerate(logs):
            # Create styled items for each column
            date_item = QTableWidgetItem(datetime.fromisoformat(log[2]).strftime("%Y-%m-%d %H:%M:%S"))
            
            type_item = QTableWidgetItem(log[1].capitalize())
            type_item.setForeground(QColor("#3498db" if log[1] == "sent" else "#e67e22"))
            
            protocol_item = QTableWidgetItem(log[3])
            
            file_item = QTableWidgetItem(log[4])
            file_item.setToolTip(f"From: {log[8]}\nTo: {log[9]}")
            
            size_item = QTableWidgetItem(self.format_file_size(log[5]))
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            
            source_item = QTableWidgetItem(log[6])
            dest_item = QTableWidgetItem(log[7])
            
            status_item = QTableWidgetItem(log[10])
            if log[10] == "Completed":
                status_item.setForeground(QColor("#27ae60"))
            else:
                status_item.setForeground(QColor("#e74c3c"))
            
            # Add items to table
            self.log_table.setItem(row_idx, 0, date_item)
            self.log_table.setItem(row_idx, 1, type_item)
            self.log_table.setItem(row_idx, 2, protocol_item)
            self.log_table.setItem(row_idx, 3, file_item)
            self.log_table.setItem(row_idx, 4, size_item)
            self.log_table.setItem(row_idx, 5, source_item)
            self.log_table.setItem(row_idx, 6, dest_item)
            self.log_table.setItem(row_idx, 7, status_item)
    
    def clear_log_filters(self):
        """Reset all log filters to default values"""
        self.log_protocol_filter.setCurrentIndex(0)
        self.log_type_filter.setCurrentIndex(0)
        self.log_date_filter.setCurrentIndex(0)
        self.load_logs()
    
    def update_status(self, html_content):
        """Update the status display with HTML-formatted content"""
        self.status_display.setHtml(f"""
            <div style='font-family: Arial; font-size: 12px;'>
                {html_content}
            </div>
        """)
        self.status_display.verticalScrollBar().setValue(
            self.status_display.verticalScrollBar().maximum())
    
    def format_file_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

if __name__ == "__main__":
    import sqlite3
    
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = FileTransferApp()
    window.show()
    
    sys.exit(app.exec_())
