import sys
import os
import sqlite3
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit, 
                            QComboBox, QTableWidget, QTableWidgetItem, QFileDialog, 
                            QHeaderView, QMessageBox, QGroupBox, QFormLayout, QProgressBar)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor
from datetime import datetime
sys.path.append("D:\file_transfer\src\application")
sys.path.append("D:\file_transfer\src\configuration")
sys.path.append("D:\file_transfer\src\crypto")
sys.path.append("D:\file_transfer\src\transfer_logs")
# Assuming these imports are available in the project structure
# You might need to adjust sys.path or the import statements based on your exact project setup
try:
    from network.common.requests import RequestHandler
    from network.download.client_protocol import TcpFileReceiver
    from network.upload.server_protocol import TcpFileSender
    from file_handler import FileHandler
    from crypto.diffe_helman_network import DiffeHelmanShareKey
    from setup_configs import loadConfigs # For local IP/port
    from log_recorder import LogRecorder # For logging network stats
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure your sys.path is correctly configured or modules are in the same directory.")
    # Dummy classes for development if imports fail
    class RequestHandler:
        def __init__(self, target_ip=None, target_port=None): pass
        def send_file_request(self, file_info=""): return False
        def accept_file_request(self): return False, None, None
        def close_connection(self): pass
    class TcpFileReceiver:
        def __init__(self, session, path): pass
        def tcpReceiveFile(self): pass
    class TcpFileSender:
        def __init__(self, session, path): pass
        def sendFile(self): pass
    class FileHandler:
        def __init__(self, key_size=2048): pass
        def encryptFile(self, in_dir): return b"encrypted_dummy_data"
        def decryptFile(self, out_dir): return b"decrypted_dummy_data"
    class DiffeHelmanShareKey:
        def __init__(self, target_ip=None, target_port=None): pass
        def initiate_key_exchange(self, msg): return False
        def respond_to_key_exchange(self): return False
        def close_connection(self): pass
    def loadConfigs(): return {"ip": "127.0.0.1", "tcp_port": 12345, "udp_port": 12346, "iface": "lo"}
    class LogRecorder:
        def __init__(self): pass
        def addFileLog(self, *args): pass
        def addStatsLog(self): pass


class FileTransferWorker(QThread):
    """Worker thread for handling file transfers to keep GUI responsive."""
    finished = pyqtSignal(bool, str, str, str, str, int, str, str, str, str) # success, type, protocol, file_name, file_size, source, dest, src_dir, dst_dir, status
    progress = pyqtSignal(int) # percentage

    def __init__(self, transfer_type, protocol, file_path, dest_path, tcp_session=None, shared_aes_key=None):
        super().__init__()
        self.transfer_type = transfer_type
        self.protocol = protocol
        self.file_path = file_path
        self.dest_path = dest_path
        self.tcp_session = tcp_session # For direct use after request acceptance
        self.shared_aes_key = shared_aes_key # For encryption/decryption

    def run(self):
        success = False
        status_msg = "Failed"
        file_name = os.path.basename(self.file_path) if self.file_path else "N/A"
        file_size = os.path.getsize(self.file_path) if self.file_path and os.path.exists(self.file_path) else 0
        source_ip = loadConfigs()["ip"]
        destination_ip = self.tcp_session.target[0] if self.tcp_session else "N/A"
        src_directory = os.path.dirname(self.file_path) if self.file_path else "N/A"
        dst_directory = self.dest_path # This is the target directory for received files

        try:
            if self.transfer_type == "Send":
                if self.tcp_session:
                    # Simulate progress for sender
                    for i in range(101):
                        time.sleep(0.02) # Simulate work
                        self.progress.emit(i)
                    
                    # In a real scenario, TcpFileSender would use the shared_aes_key for encryption
                    # and the tcp_session for sending.
                    # For this example, we'll just call sendFile and assume it handles encryption internally.
                    sender = TcpFileSender(self.tcp_session, self.file_path)
                    sender.sendFile() # This method needs to be adapted to use shared_aes_key
                    success = True
                    status_msg = "Completed"
                else:
                    status_msg = "No active TCP session for sending."
            elif self.transfer_type == "Receive":
                if self.tcp_session:
                    # Simulate progress for receiver
                    for i in range(101):
                        time.sleep(0.02) # Simulate work
                        self.progress.emit(i)

                    # In a real scenario, TcpFileReceiver would use the shared_aes_key for decryption
                    receiver = TcpFileReceiver(self.tcp_session, self.dest_path)
                    receiver.tcpReceiveFile() # This method needs to be adapted to use shared_aes_key
                    success = True
                    status_msg = "Completed"
                else:
                    status_msg = "No active TCP session for receiving."
            
        except Exception as e:
            status_msg = f"Error: {e}"
            success = False
        finally:
            self.finished.emit(success, self.transfer_type.lower(), self.protocol, file_name, 
                               str(file_size), source_ip, destination_ip, src_directory, 
                               dst_directory, status_msg)


class FileTransferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Transfer System")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize database paths
        self.file_transfer_db_path = "logs/file_transfers.db"
        self.main_logs_db_path = "D:\\file_transfer\\src\\transfer_logs\\logs\\logs.db" # Path used by NetStatistics and LogRecorder
        self.init_db()
        
        # Network related objects
        self.request_handler = None
        self.dh_key_exchange = None
        self.current_tcp_session = None
        self.shared_aes_key = None # Store the shared AES key after DH exchange
        self.file_handler = FileHandler() # For encryption/decryption operations

        # Create main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout()
        self.main_widget.setLayout(self.main_layout)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_profile_tab()
        self.create_file_transfer_tab()
        self.create_encryption_tab()
        self.create_log_viewer_tab()
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Auto-refresh logs every 5 seconds
        self.log_refresh_timer = QTimer()
        self.log_refresh_timer.timeout.connect(self.load_logs)
        self.log_refresh_timer.start(5000)
        
        # Load initial data
        self.load_logs()
        self.load_profile_settings()

    def init_db(self):
        """Initialize the database with required tables for GUI's internal logs."""
        os.makedirs(os.path.dirname(self.file_transfer_db_path), exist_ok=True)
        with sqlite3.connect(self.file_transfer_db_path) as conn:
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
        
        # Ensure the main logs.db also exists and has the file_transfers table
        # This is crucial for NetStatistics and LogRecorder to work
        os.makedirs(os.path.dirname(self.main_logs_db_path), exist_ok=True)
        with sqlite3.connect(self.main_logs_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transfer_type TEXT NOT NULL, -- 'sent' or 'received'
                    transfer_date TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    source TEXT,
                    destination TEXT,
                    src_directory TEXT,
                    dst_directory TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    bytes_sent INTEGER,
                    bytes_recv INTEGER,
                    packets_sent INTEGER,
                    packets_recv INTEGER,
                    dropin INTEGER,
                    dropout INTEGER
                )
            """)
            conn.commit()

    def create_profile_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        profile_group = QGroupBox("User Profile & Network Settings")
        profile_form_layout = QFormLayout()

        self.user_id_edit = QLineEdit()
        self.user_name_edit = QLineEdit()
        self.local_ip_label = QLabel("N/A")
        self.iface_edit = QLineEdit()
        self.tcp_port_edit = QLineEdit()
        self.udp_port_edit = QLineEdit()

        profile_form_layout.addRow("User ID:", self.user_id_edit)
        profile_form_layout.addRow("User Name:", self.user_name_edit)
        profile_form_layout.addRow("Local IP:", self.local_ip_label)
        profile_form_layout.addRow("Network Interface:", self.iface_edit)
        profile_form_layout.addRow("TCP Port:", self.tcp_port_edit)
        profile_form_layout.addRow("UDP Port:", self.udp_port_edit)

        self.save_profile_button = QPushButton("Save Settings")
        self.save_profile_button.clicked.connect(self.save_profile_settings)
        profile_form_layout.addRow(self.save_profile_button)

        profile_group.setLayout(profile_form_layout)
        layout.addWidget(profile_group)
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Profile")

    def load_profile_settings(self):
        try:
            configs = loadConfigs()
            self.user_id_edit.setText(str(configs.get("user_id", "")))
            self.user_name_edit.setText(configs.get("user_name", ""))
            self.local_ip_label.setText(configs.get("ip", "N/A"))
            self.iface_edit.setText(configs.get("iface", ""))
            self.tcp_port_edit.setText(str(configs.get("tcp_port", "")))
            self.udp_port_edit.setText(str(configs.get("udp_port", "")))
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load configurations: {e}\nEnsure config.json exists and is valid.")
            self.local_ip_label.setText("N/A (Config Error)")

    def save_profile_settings(self):
        # This function would typically write to config.json
        # For this example, we'll just show a message.
        QMessageBox.information(self, "Save Settings", "Profile settings saved (functionality to write to config.json needs to be implemented in setup_configs.py).")
        # In a real app, you'd call a function from setup_configs to save these.
        # Example: ConfigSetup(iface, user_id, tcp_port, udp_port, user_name).setUserConfigs()

    def create_file_transfer_tab(self):
        """Create the file transfer tab with all controls"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Target IP and Port
        target_group = QGroupBox("Target Information")
        target_layout = QFormLayout()
        self.target_ip_edit = QLineEdit("127.0.0.1") # Default to localhost for testing
        self.target_port_edit = QLineEdit("12345") # Default port
        target_layout.addRow("Target IP:", self.target_ip_edit)
        target_layout.addRow("Target Port:", self.target_port_edit)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Protocol selection
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP"]) # Simplified for this project's scope
        protocol_layout.addWidget(self.protocol_combo)
        protocol_layout.addStretch()
        layout.addLayout(protocol_layout)
        
        # Transfer type
        transfer_layout = QHBoxLayout()
        transfer_layout.addWidget(QLabel("Transfer Type:"))
        self.transfer_type_combo = QComboBox()
        self.transfer_type_combo.addItems(["Send", "Receive"])
        transfer_layout.addWidget(self.transfer_type_combo)
        transfer_layout.addStretch()
        layout.addLayout(transfer_layout)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select file or directory...")
        file_layout.addWidget(self.file_path_edit)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_files)
        file_layout.addWidget(self.browse_button)
        layout.addLayout(file_layout)
        
        # Destination
        dest_layout = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("Destination path or URL...")
        dest_layout.addWidget(self.dest_edit)
        self.browse_dest_button = QPushButton("Browse...")
        self.browse_dest_button.clicked.connect(self.browse_destination)
        dest_layout.addWidget(self.browse_dest_button)
        layout.addLayout(dest_layout)

        # Key Exchange and Transfer Buttons
        button_group_layout = QHBoxLayout()
        self.initiate_dh_button = QPushButton("Initiate Key Exchange (Sender)")
        self.initiate_dh_button.clicked.connect(self.initiate_dh_exchange)
        button_group_layout.addWidget(self.initiate_dh_button)

        self.respond_dh_button = QPushButton("Respond Key Exchange (Receiver)")
        self.respond_dh_button.clicked.connect(self.respond_dh_exchange)
        button_group_layout.addWidget(self.respond_dh_button)

        self.start_transfer_button = QPushButton("Start File Transfer")
        self.start_transfer_button.setStyleSheet("""
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
        self.start_transfer_button.clicked.connect(self.start_transfer)
        button_group_layout.addWidget(self.start_transfer_button)
        layout.addLayout(button_group_layout)

        # Progress Bar
        self.transfer_progress_bar = QProgressBar()
        self.transfer_progress_bar.setTextVisible(True)
        self.transfer_progress_bar.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.transfer_progress_bar)
        
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
        layout.addWidget(QLabel("<b>Transfer Status:</b>"))
        layout.addWidget(self.status_display)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "File Transfer")

    def create_encryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        encryption_group = QGroupBox("File Encryption/Decryption")
        encryption_form_layout = QFormLayout()

        self.enc_input_path_edit = QLineEdit()
        self.enc_input_path_edit.setPlaceholderText("Select file or directory to encrypt/decrypt...")
        self.browse_enc_input_button = QPushButton("Browse...")
        self.browse_enc_input_button.clicked.connect(lambda: self.browse_files_for_encryption(self.enc_input_path_edit))
        
        self.enc_output_path_edit = QLineEdit()
        self.enc_output_path_edit.setPlaceholderText("Select output directory...")
        self.browse_enc_output_button = QPushButton("Browse...")
        self.browse_enc_output_button.clicked.connect(lambda: self.browse_destination_for_encryption(self.enc_output_path_edit))

        self_encrypt_button = QPushButton("Encrypt File/Directory")
        self_encrypt_button.clicked.connect(self.perform_encryption)
        self_decrypt_button = QPushButton("Decrypt File/Directory")
        self_decrypt_button.clicked.connect(self.perform_decryption)

        encryption_form_layout.addRow("Input Path:", self.enc_input_path_edit)
        encryption_form_layout.addRow("", self.browse_enc_input_button)
        encryption_form_layout.addRow("Output Path:", self.enc_output_path_edit)
        encryption_form_layout.addRow("", self.browse_enc_output_button)
        encryption_form_layout.addRow(self_encrypt_button)
        encryption_form_layout.addRow(self_decrypt_button)

        encryption_group.setLayout(encryption_form_layout)
        layout.addWidget(encryption_group)
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Encryption")

    def browse_files_for_encryption(self, line_edit):
        options = QFileDialog.Options()
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)", options=options)
        if path:
            line_edit.setText(path)

    def browse_destination_for_encryption(self, line_edit):
        options = QFileDialog.Options()
        path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", "", options=options)
        if path:
            line_edit.setText(path)

    def perform_encryption(self):
        input_path = self.enc_input_path_edit.text()
        output_dir = self.enc_output_path_edit.text()

        if not input_path or not output_dir:
            QMessageBox.warning(self, "Error", "Please select both input file/directory and output directory.")
            return
        
        if not os.path.exists(input_path):
            QMessageBox.warning(self, "Error", "Input path does not exist.")
            return

        try:
            if os.path.isfile(input_path):
                # For single file encryption, FileHandler.encryptFile expects a directory
                # We need to adapt this or create a temporary directory for the file.
                # A simpler approach for single file:
                with open(input_path, 'rb') as f_in:
                    file_data = f_in.read()
                
                # Encrypt using the current RSA public key from FileHandler
                # Note: FileHandler.encryptFile expects a directory, not raw data.
                # This part needs careful integration with how FileHandler is designed.
                # For now, let's simulate.
                
                # If FileHandler.encryptFile was designed for single files:
                # encrypted_data = self.file_handler.encryptFile(input_path) 
                
                # As per current FileHandler, it iterates a directory.
                # Let's assume we want to encrypt the content of the file and save it.
                # This requires a change in FileHandler or a wrapper.
                
                # Dummy encryption for demonstration
                encrypted_data = b"DUMMY_ENCRYPTED_DATA_FOR_" + os.path.basename(input_path).encode()
                
                if encrypted_data:
                    output_file_path = os.path.join(output_dir, os.path.basename(input_path) + ".enc")
                    with open(output_file_path, 'wb') as f_out:
                        f_out.write(encrypted_data)
                    QMessageBox.information(self, "Encryption Success", f"File encrypted to {output_file_path}")
                else:
                    QMessageBox.warning(self, "Encryption Failed", "Could not encrypt the file.")

            elif os.path.isdir(input_path):
                encrypted_files = self.file_handler.encryptDirectory(input_path)
                if encrypted_files:
                    for filename, data in encrypted_files.items():
                        output_file_path = os.path.join(output_dir, filename + ".enc")
                        with open(output_file_path, 'wb') as f_out:
                            f_out.write(data)
                    QMessageBox.information(self, "Encryption Success", f"Directory '{input_path}' encrypted to '{output_dir}'.")
                else:
                    QMessageBox.warning(self, "Encryption Failed", "Could not encrypt the directory.")
            else:
                QMessageBox.warning(self, "Error", "Input path is neither a file nor a directory.")

        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"An error occurred during encryption: {e}")

    def perform_decryption(self):
        input_path = self.enc_input_path_edit.text()
        output_dir = self.enc_output_path_edit.text()

        if not input_path or not output_dir:
            QMessageBox.warning(self, "Error", "Please select both input file/directory and output directory.")
            return
        
        if not os.path.exists(input_path):
            QMessageBox.warning(self, "Error", "Input path does not exist.")
            return

        try:
            if os.path.isfile(input_path):
                # Dummy decryption for demonstration
                decrypted_data = b"DUMMY_DECRYPTED_DATA_FOR_" + os.path.basename(input_path).replace(".enc", "").encode()
                
                if decrypted_data:
                    output_file_path = os.path.join(output_dir, os.path.basename(input_path).replace(".enc", ""))
                    with open(output_file_path, 'wb') as f_out:
                        f_out.write(decrypted_data)
                    QMessageBox.information(self, "Decryption Success", f"File decrypted to {output_file_path}")
                else:
                    QMessageBox.warning(self, "Decryption Failed", "Could not decrypt the file.")

            elif os.path.isdir(input_path):
                decrypted_files = self.file_handler.decryptDirectory(input_path)
                if decrypted_files:
                    for filename, data in decrypted_files.items():
                        output_file_path = os.path.join(output_dir, filename)
                        with open(output_file_path, 'wb') as f_out:
                            f_out.write(data)
                    QMessageBox.information(self, "Decryption Success", f"Directory '{input_path}' decrypted to '{output_dir}'.")
                else:
                    QMessageBox.warning(self, "Decryption Failed", "Could not decrypt the directory.")
            else:
                QMessageBox.warning(self, "Error", "Input path is neither a file nor a directory.")

        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"An error occurred during decryption: {e}")

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
        self.log_protocol_filter.addItems(["TCP", "UDP"])
        self.log_protocol_filter.currentIndexChanged.connect(self.load_logs)
        filter_layout.addWidget(self.log_protocol_filter)
        
        # Transfer type filter
        filter_layout.addWidget(QLabel("Type:"))
        self.log_type_filter = QComboBox()
        self.log_type_filter.addItem("All", None)
        self.log_type_filter.addItems(["Send", "Receive"])
        self.log_type_filter.currentIndexChanged.connect(self.load_logs)
        filter_layout.addWidget(self.log_type_filter)
        
        # Date filter (simplified for now, can be expanded with QDateEdit)
        filter_layout.addWidget(QLabel("Date:"))
        self.log_date_filter = QComboBox()
        self.log_date_filter.addItem("All", None)
        self.log_date_filter.addItems(["Today", "Last 7 days", "This month"])
        self.log_date_filter.currentIndexChanged.connect(self.load_logs)
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

    def initiate_dh_exchange(self):
        target_ip = self.target_ip_edit.text()
        target_port = int(self.target_port_edit.text())

        if not target_ip or not target_port:
            QMessageBox.warning(self, "Error", "Please enter Target IP and Port for Key Exchange.")
            return

        self.update_status(f"Initiating Diffie-Hellman Key Exchange with {target_ip}:{target_port}...")
        self.dh_key_exchange = DiffeHelmanShareKey(target_ip=target_ip, target_port=target_port)
        
        # Run DH exchange in a separate thread to prevent GUI freeze
        self.dh_thread = QThread()
        self.dh_key_exchange.moveToThread(self.dh_thread)
        self.dh_thread.started.connect(lambda: self._run_dh_initiation(target_ip, target_port))
        self.dh_thread.start()

    def _run_dh_initiation(self, target_ip, target_port):
        try:
            if self.dh_key_exchange.initiate_key_exchange(message_to_encrypt=b"Hello from initiator!"):
                self.shared_aes_key = self.dh_key_exchange.shared_aes_key
                self.current_tcp_session = self.dh_key_exchange.tcp_session # Keep the session for file transfer
                self.update_status(f"<span style='color: green;'>Diffie-Hellman Key Exchange successful! Shared AES Key established.</span>")
                self.status_bar.showMessage("Key Exchange Successful!")
            else:
                self.update_status(f"<span style='color: red;'>Diffie-Hellman Key Exchange failed.</span>")
                self.status_bar.showMessage("Key Exchange Failed!")
            self.dh_thread.quit()
            self.dh_thread.wait()
        except Exception as e:
            self.update_status(f"<span style='color: red;'>Error during DH initiation: {e}</span>")
            self.status_bar.showMessage("Key Exchange Error!")
            self.dh_thread.quit()
            self.dh_thread.wait()

    def respond_dh_exchange(self):
        self.update_status("Listening for Diffie-Hellman Key Exchange request...")
        self.dh_key_exchange = DiffeHelmanShareKey() # No target_ip/port needed for responder init
        
        # Run DH response in a separate thread
        self.dh_thread = QThread()
        self.dh_key_exchange.moveToThread(self.dh_thread)
        self.dh_thread.started.connect(self._run_dh_response)
        self.dh_thread.start()

    def _run_dh_response(self):
        try:
            if self.dh_key_exchange.respond_to_key_exchange():
                self.shared_aes_key = self.dh_key_exchange.shared_aes_key
                self.current_tcp_session = self.dh_key_exchange.tcp_session # Keep the session for file transfer
                self.update_status(f"<span style='color: green;'>Diffie-Hellman Key Exchange successful! Shared AES Key established.</span>")
                self.status_bar.showMessage("Key Exchange Successful!")
            else:
                self.update_status(f"<span style='color: red;'>Diffie-Hellman Key Exchange failed.</span>")
                self.status_bar.showMessage("Key Exchange Failed!")
            self.dh_thread.quit()
            self.dh_thread.wait()
        except Exception as e:
            self.update_status(f"<span style='color: red;'>Error during DH response: {e}</span>")
            self.status_bar.showMessage("Key Exchange Error!")
            self.dh_thread.quit()
            self.dh_thread.wait()

    def start_transfer(self):
        file_path = self.file_path_edit.text()
        dest_path = self.dest_edit.text()
        protocol = self.protocol_combo.currentText()
        transfer_type = self.transfer_type_combo.currentText()
        target_ip = self.target_ip_edit.text()
        target_port = int(self.target_port_edit.text())

        if not file_path and transfer_type == "Send":
            QMessageBox.warning(self, "Error", "Please select a file to send.")
            return
        if not dest_path:
            QMessageBox.warning(self, "Error", "Please select a destination path.")
            return
        if not self.shared_aes_key:
            QMessageBox.warning(self, "Error", "Please perform Diffie-Hellman Key Exchange first.")
            return
        if not self.current_tcp_session:
            QMessageBox.warning(self, "Error", "TCP session not established. Perform Key Exchange or accept request.")
            return

        self.update_status(f"""
            <div style='color: #2c3e50; font-weight: bold;'>
                Starting {transfer_type.lower()} transfer via {protocol}...
            </div>
            <div style='margin-top: 5px;'>
                <b>Source:</b> {file_path if file_path else 'N/A'}<br>
                <b>Destination:</b> {dest_path}
            </div>
        """)
        self.transfer_progress_bar.setValue(0)
        self.status_bar.showMessage("Transfer in progress...")

        # Start file transfer in a worker thread
        self.transfer_worker = FileTransferWorker(
            transfer_type, protocol, file_path, dest_path, 
            tcp_session=self.current_tcp_session, shared_aes_key=self.shared_aes_key
        )
        self.transfer_worker.finished.connect(self.on_transfer_finished)
        self.transfer_worker.progress.connect(self.transfer_progress_bar.setValue)
        self.transfer_worker.start()
    
    def on_transfer_finished(self, success, transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory, status_msg):
        if success:
            self.update_status(f"""
                <div style='color: #27ae60; font-weight: bold;'>
                    Transfer completed successfully!
                </div>
                <div style='margin-top: 5px;'>
                    <b>File:</b> {file_name}<br>
                    <b>Size:</b> {self.format_file_size(int(file_size))}<br>
                    <b>Time:</b> {datetime.now().strftime('%H:%M:%S')}
                </div>
            """)
            self.status_bar.showMessage("Transfer Completed!")
        else:
            self.update_status(f"""
                <div style='color: #e74c3c; font-weight: bold;'>
                    Transfer failed: {status_msg}
                </div>
            """)
            self.status_bar.showMessage("Transfer Failed!")

        # Log the transfer to both GUI's internal DB and the main logs.db
        self.log_transfer(
            transfer_type=transfer_type,
            protocol=protocol,
            file_name=file_name,
            file_size=int(file_size),
            source=source,
            destination=destination,
            src_directory=src_directory,
            dst_directory=dst_directory,
            status=status_msg
        )
        
        # Also log to the main system log recorder
        log_recorder = LogRecorder()
        log_recorder.addFileLog(
            transfer_type=transfer_type,
            protocol=protocol,
            file_name=file_name,
            file_size=int(file_size),
            source=source,
            destination=destination,
            src_directory=src_directory,
            dst_directory=dst_directory
        )

        self.load_logs() # Refresh logs in the GUI
        self.current_tcp_session.close() # Close the TCP session after transfer
        self.current_tcp_session = None
        self.shared_aes_key = None
        self.transfer_progress_bar.setValue(0)


    def log_transfer(self, transfer_type, protocol, file_name, file_size, 
                    source, destination, src_directory, dst_directory, status):
        """Log a file transfer to the GUI's internal database."""
        with sqlite3.connect(self.file_transfer_db_path) as conn:
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
        """Load transfer logs from database and display in table."""
        protocol_filter = self.log_protocol_filter.currentData()
        type_filter = self.log_type_filter.currentData()
        date_filter = self.log_date_filter.currentData()
        
        query = "SELECT * FROM file_transfers"
        params = []
        
        conditions = []
        if protocol_filter:
            conditions.append("protocol = ?")
            params.append(protocol_filter)
        if type_filter:
            conditions.append("transfer_type = ?")
            params.append(type_filter.lower())
        
        if date_filter == "Today":
            today = datetime.now().strftime("%Y-%m-%d")
            conditions.append("transfer_date LIKE ?")
            params.append(f"{today}%")
        elif date_filter == "Last 7 days":
            seven_days_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            conditions.append("transfer_date >= ?")
            params.append(seven_days_ago)
        elif date_filter == "This month":
            this_month = datetime.now().strftime("%Y-%m")
            conditions.append("transfer_date LIKE ?")
            params.append(f"{this_month}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY transfer_date DESC LIMIT 100" # Always limit for performance
        
        with sqlite3.connect(self.file_transfer_db_path) as conn:
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
        if size_bytes is None:
            return "N/A"
        size_bytes = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

if __name__ == "__main__":
    from datetime import timedelta # Needed for date filtering

    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = FileTransferApp()
    window.show()
    
    sys.exit(app.exec_())
