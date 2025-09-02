
import sys
import sqlite3
from datetime import datetime
sys.path.append("D:\\file_transfer\\src\\application\\network\\statistics")
from net_statistic import NetStatistics

class LogRecorder:

    def __init__(self):
        self.dbPath = "D:\\file_transfer\\src\\transfer_logs\\logs.db"
        if not os.path.exists(self.dbPath):
            self._create_tables()

    def _create_tables(self):
        """Creates the necessary database tables if they don't exist."""
        conn = sqlite3.connect(self.dbPath)
        cursor = conn.cursor()

        # Create network_stats table
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

        # Create file_transfers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_type TEXT NOT NULL, -- 'sent' or 'received'
                transfer_date TEXT NOT NULL,
                protocol TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER,
                source TEXT,
                destination TEXT
                src_directory TEXT
                dst_directory TEXT
            )
        """)
        conn.commit()
        conn.close()

    def addStatsLog(self):
        """
        Records current network statistics into the database.
        This method should be called periodically to log network activity.
        """
        net_stats = NetStatistics()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        bytes_sent = net_stats.getBytesSent()
        bytes_recv = net_stats.getBytesRecv()
        packets_sent = net_stats.getPacketsSent()
        packets_recv = net_stats.getPacketsRecv()
        dropin = net_stats.getDroppedInPackets()
        dropout = net_stats.getDroppedOutPackets()

        conn = sqlite3.connect(self.dbPath)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO network_stats (date, bytes_sent, bytes_recv, packets_sent, packets_recv, dropin, dropout)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (current_time, bytes_sent, bytes_recv, packets_sent, packets_recv, dropin, dropout))
        conn.commit()
        conn.close()
        print(f"Network statistics logged at {current_time}")

    def addFileLog(self, transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory):
        """
        Records details of a file transfer (sent or received) into the database.

        Args:
            transfer_type (str): 'sent' or 'received'.
            file_name (str): The name of the file transferred.
            file_size (int): The size of the file in bytes.
            source (str): The source of the file (e.g., IP address, username).
            destination (str): The destination of the file (e.g., IP address, username).
        """
        if transfer_type not in ['sent', 'received']:
            print("Error: transfer_type must be 'sent' or 'received'.")
            return

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(self.dbPath)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO file_transfers (transfer_type, transfer_date, protocol, file_name, file_size, source, destination, src_directory, dst_directory)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (transfer_type, current_time, protocol, file_name, file_size, source, destination, src_directory, dst_directory))
        conn.commit()
        conn.close()
        print(f"File transfer '{file_name}' ({transfer_type}) logged at {current_time}")

