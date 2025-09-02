import sys
import os
import sqlite3
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QFileDialog,
    QHeaderView, QMessageBox, QGroupBox, QFormLayout, QProgressBar,
    QRadioButton, QButtonGroup
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QColor
from datetime import datetime, timedelta

sys.path.append(r"D:\file_transfer\src\application")
sys.path.append(r"D:\file_transfer\src\configuration")
sys.path.append(r"D:\file_transfer\src\crypto")
sys.path.append(r"D:\file_transfer\src\transfer_logs")

try:
    from network.common.requests import RequestHandler
    from network.download.client_protocol import TcpFileReceiver
    from network.upload.server_protocol import TcpFileSender
    from file_handler import FileHandler
    from key_exchange.diffe_helman_network import DiffeHelmanShareKey
    from setup_configs import loadConfigs
    from log_recorder import LogRecorder
except ImportError as e:
    print(f"Error importing modules: {e}")
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
    def loadConfigs(): return {"user_id": "user123", "user_name": "User ", "iface": "lo", "ip": "127.0.0.1", "tcp_port": 12345, "udp_port": 12346}
    class LogRecorder:
        def __init__(self): pass
        def addFileLog(self, *args): pass
        def addStatsLog(self): pass


class FileTransferWorker(QThread):
    finished = pyqtSignal(bool, str, str, str, str, int, str, str, str, str)
    progress = pyqtSignal(int)

    def __init__(self, transfer_type, protocol, file_path, dest_path, tcp_session=None, shared_aes_key=None):
        super().__init__()
        self.transfer_type = transfer_type
        self.protocol = protocol
        self.file_path = file_path
        self.dest_path = dest_path
        self.tcp_session = tcp_session
        self.shared_aes_key = shared_aes_key

    def run(self):
        success = False
        status_msg = "Failed"
        file_name = os.path.basename(self.file_path) if self.file_path else "N/A"
        file_size = os.path.getsize(self.file_path) if self.file_path and os.path.exists(self.file_path) else 0
        source_ip = loadConfigs()["ip"]
        destination_ip = self.tcp_session.target[0] if self.tcp_session else "N/A"
        src_directory = os.path.dirname(self.file_path) if self.file_path else "N/A"
        dst_directory = self.dest_path

        try:
            if self.transfer_type == "Send":
                if self.tcp_session:
                    for i in range(101):
                        time.sleep(0.02)
                        self.progress.emit(i)
                    sender = TcpFileSender(self.tcp_session, self.file_path)
                    sender.sendFile()
                    success = True
                    status_msg = "Completed"
                else:
                    status_msg = "No active TCP session for sending."
            elif self.transfer_type == "Receive":
                if self.tcp_session:
                    for i in range(101):
                        time.sleep(0.02)
                        self.progress.emit(i)
                    receiver = TcpFileReceiver(self.tcp_session, self.dest_path)
                    receiver.tcpReceiveFile()
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


class RequestListenerThread(QThread):
    request_received = pyqtSignal(str, str)  # file_info, sender_ip
    def __init__(self, listen_port):
        super().__init__()
        self.listen_port = listen_port
        self._running = True
        self.request_handler = None

    def run(self):
        self.request_handler = RequestHandler(target_port=self.listen_port)
        while self._running:
            try:
                has_request, file_info, sender_ip = self.request_handler.accept_file_request()
                if has_request:
                    self.request_received.emit(file_info, sender_ip)
                    # Wait for response from GUI (handled externally)
                    time.sleep(1)
            except Exception:
                pass
            time.sleep(0.5)

    def stop(self):
        self._running = False
        if self.request_handler:
            self.request_handler.close_connection()
        self.quit()
        self.wait()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Transfer System")
        self.setGeometry(100, 100, 900, 700)

        self.file_transfer_db_path = "logs/file_transfers.db"
        self.init_db()

        self.request_listener_thread = None
        self.current_request_handler = None
        self.current_tcp_session = None
        self.shared_aes_key = None
        self.file_handler = FileHandler()

        self._init_ui()

    def init_db(self):
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

    def _init_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._init_profile_tab()
        self._init_transfer_tab()
        self._init_logs_tab()

    # -------- Profile Tab --------
    def _init_profile_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # User Configuration Group
        user_group = QGroupBox("User  Configuration")
        user_form = QFormLayout()
        self.user_id_edit = QLineEdit()
        self.user_name_edit = QLineEdit()
        user_form.addRow("User  ID:", self.user_id_edit)
        user_form.addRow("User  Name:", self.user_name_edit)
        user_group.setLayout(user_form)

        # Network Configuration Group
        net_group = QGroupBox("Network Configuration")
        net_form = QFormLayout()
        self.iface_edit = QLineEdit()
        self.local_ip_label = QLabel("N/A")
        self.tcp_port_edit = QLineEdit()
        self.udp_port_edit = QLineEdit()
        net_form.addRow("Network Interface:", self.iface_edit)
        net_form.addRow("Local IP:", self.local_ip_label)
        net_form.addRow("TCP Port:", self.tcp_port_edit)
        net_form.addRow("UDP Port:", self.udp_port_edit)
        net_group.setLayout(net_form)

        self.save_profile_btn = QPushButton("Save Settings")
        self.save_profile_btn.clicked.connect(self.save_profile_settings)

        layout.addWidget(user_group)
        layout.addWidget(net_group)
        layout.addWidget(self.save_profile_btn)
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Profile")

        self.load_profile_settings()

    def load_profile_settings(self):
        try:
            configs = loadConfigs()
            self.user_id_edit.setText(str(configs.get("user_id", "")))
            self.user_name_edit.setText(configs.get("user_name", ""))
            self.iface_edit.setText(configs.get("iface", ""))
            self.local_ip_label.setText(configs.get("ip", "N/A"))
            self.tcp_port_edit.setText(str(configs.get("tcp_port", "")))
            self.udp_port_edit.setText(str(configs.get("udp_port", "")))
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load configurations: {e}")

    def save_profile_settings(self):
        QMessageBox.information(self, "Save Settings", "Saving profile settings is not implemented in this demo.")

    # -------- Transfer Tab --------
    def _init_transfer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.transfer_mode_tabs = QTabWidget()
        layout.addWidget(self.transfer_mode_tabs)

        # Send Tab
        send_tab = QWidget()
        send_layout = QFormLayout()
        self.send_target_ip = QLineEdit()
        self.send_target_port = QLineEdit()
        self.send_file_path = QLineEdit()
        self.send_browse_btn = QPushButton("Browse...")
        self.send_browse_btn.clicked.connect(self.browse_send_file)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.send_file_path)
        file_layout.addWidget(self.send_browse_btn)

        send_layout.addRow("Target IP:", self.send_target_ip)
        send_layout.addRow("Target Port:", self.send_target_port)
        send_layout.addRow("Source File/Directory:", file_layout)

        self.send_start_btn = QPushButton("Start Send Transfer")
        self.send_start_btn.clicked.connect(self.start_send_transfer)
        send_layout.addRow(self.send_start_btn)

        send_tab.setLayout(send_layout)
        self.transfer_mode_tabs.addTab(send_tab, "Send")

        # Receive Tab
        receive_tab = QWidget()
        receive_layout = QVBoxLayout()

        self.listen_btn = QPushButton("Start Listening")
        self.listen_btn.setCheckable(True)
        self.listen_btn.clicked.connect(self.toggle_listening)
        receive_layout.addWidget(self.listen_btn)

        self.receive_status = QTextEdit()
        self.receive_status.setReadOnly(True)
        receive_layout.addWidget(QLabel("Request Log:"))
        receive_layout.addWidget(self.receive_status)

        receive_tab.setLayout(receive_layout)
        self.transfer_mode_tabs.addTab(receive_tab, "Receive")

        self.tabs.addTab(tab, "Transfer")

    def browse_send_file(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Send")
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if path:
            self.send_file_path.setText(path)

    def toggle_listening(self, checked):
        if checked:
            # Start listening thread
            try:
                port = int(self.tcp_port_edit.text())
            except Exception:
                QMessageBox.warning(self, "Error", "Invalid TCP port for listening.")
                self.listen_btn.setChecked(False)
                return
            self.receive_status.append(f"Starting to listen on port {port}...")
            self.request_listener_thread = RequestListenerThread(port)
            self.request_listener_thread.request_received.connect(self.handle_incoming_request)
            self.request_listener_thread.start()
            self.listen_btn.setText("Stop Listening")
        else:
            # Stop listening thread
            if self.request_listener_thread:
                self.request_listener_thread.stop()
                self.request_listener_thread = None
            self.receive_status.append("Stopped listening.")
            self.listen_btn.setText("Start Listening")

    def handle_incoming_request(self, file_info, sender_ip):
        self.receive_status.append(f"Received file request from {sender_ip}: {file_info}")
        reply = QMessageBox.question(self, "File Transfer Request",
                                     f"Incoming file transfer request from {sender_ip}:\n\n{file_info}\n\nAccept?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.receive_status.append("Request accepted.")
            # Accept the request and start receiving file
            self.current_request_handler = RequestHandler()
            accepted, tcp_session, shared_key = self.current_request_handler.accept_file_request()
            if accepted:
                self.shared_aes_key = shared_key
                self.current_tcp_session = tcp_session
                # Start receiving file in a thread
                self.receive_worker = FileTransferWorker(
                    "Receive", "TCP", None, os.getcwd(),
                    tcp_session=self.current_tcp_session,
                    shared_aes_key=self.shared_aes_key
                )
                self.receive_worker.finished.connect(self.on_receive_finished)
                self.receive_worker.start()
            else:
                self.receive_status.append("Failed to accept the request.")
        else:
            self.receive_status.append("Request denied.")

    def on_receive_finished(self, success, transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory, status_msg):
        if success:
            self.receive_status.append(f"File received successfully: {file_name}")
        else:
            self.receive_status.append(f"File receive failed: {status_msg}")

    def start_send_transfer(self):
        target_ip = self.send_target_ip.text()
        try:
            target_port = int(self.send_target_port.text())
        except Exception:
            QMessageBox.warning(self, "Error", "Invalid target port.")
            return
        src_path = self.send_file_path.text()
        if not target_ip or not target_port or not src_path:
            QMessageBox.warning(self, "Error", "Please fill all send fields.")
            return
        if not os.path.exists(src_path):
            QMessageBox.warning(self, "Error", "Source path does not exist.")
            return

        # Initiate key exchange
        self.dh_key_exchange = DiffeHelmanShareKey(target_ip=target_ip, target_port=target_port)
        if not self.dh_key_exchange.initiate_key_exchange(message_to_encrypt=b"Hello from sender"):
            QMessageBox.warning(self, "Error", "Key exchange failed.")
            return
        self.shared_aes_key = self.dh_key_exchange.shared_aes_key
        self.current_tcp_session = self.dh_key_exchange.tcp_session

        # Start sending file
        self.send_worker = FileTransferWorker(
            "Send", "TCP", src_path, None,
            tcp_session=self.current_tcp_session,
            shared_aes_key=self.shared_aes_key
        )
        self.send_worker.finished.connect(self.on_send_finished)
        self.send_worker.start()

    def on_send_finished(self, success, transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory, status_msg):
        if success:
            QMessageBox.information(self, "Success", f"File sent successfully: {file_name}")
        else:
            QMessageBox.warning(self, "Failed", f"File send failed: {status_msg}")

    # -------- Logs Tab --------
    def _init_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(8)
        self.log_table.setHorizontalHeaderLabels([
            "Date/Time", "Type", "Protocol", "File", "Size", "Source", "Destination", "Status"
        ])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.log_table)

        self.refresh_logs_btn = QPushButton("Refresh Logs")
        self.refresh_logs_btn.clicked.connect(self.load_logs)
        layout.addWidget(self.refresh_logs_btn)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "Logs")

        self.load_logs()

    def load_logs(self):
        with sqlite3.connect(self.file_transfer_db_path) as conn:
            cursor = conn.execute("SELECT transfer_date, transfer_type, protocol, file_name, file_size, source, destination, status FROM file_transfers ORDER BY transfer_date DESC LIMIT 100")
            logs = cursor.fetchall()

        self.log_table.setRowCount(len(logs))
        for row_idx, log in enumerate(logs):
            date_item = QTableWidgetItem(log[0])
            type_item = QTableWidgetItem(log[1].capitalize())
            protocol_item = QTableWidgetItem(log[2])
            file_item = QTableWidgetItem(log[3])
            size_item = QTableWidgetItem(self.format_file_size(log[4]))
            source_item = QTableWidgetItem(log[5])
            dest_item = QTableWidgetItem(log[6])
            status_item = QTableWidgetItem(log[7])

            # Color coding status
            if log[7].lower() == "completed":
                status_item.setForeground(QColor("green"))
            else:
                status_item.setForeground(QColor("red"))

            self.log_table.setItem(row_idx, 0, date_item)
            self.log_table.setItem(row_idx, 1, type_item)
            self.log_table.setItem(row_idx, 2, protocol_item)
            self.log_table.setItem(row_idx, 3, file_item)
            self.log_table.setItem(row_idx, 4, size_item)
            self.log_table.setItem(row_idx, 5, source_item)
            self.log_table.setItem(row_idx, 6, dest_item)
            self.log_table.setItem(row_idx, 7, status_item)

    def format_file_size(self, size_bytes):
        if size_bytes is None:
            return "N/A"
        size_bytes = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
