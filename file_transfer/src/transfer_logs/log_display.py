import sqlite3
import os
from datetime import datetime

# Database Handler Class
class LogDatabaseHandler:
    def __init__(self, db_path='logs/logs.db'):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
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
            conn.commit()

    def add_transfer_log(self, transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory):
        """Add a new file transfer log entry"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO file_transfers (transfer_date, transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), transfer_type, protocol, file_name, file_size, source, destination, src_directory, dst_directory)
            )
            conn.commit()

    def get_transfer_logs(self, limit=100, transfer_type=None, protocol=None):
        """Retrieve file transfer logs with optional filters"""
        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT * FROM file_transfers"
            params = []
            
            conditions = []
            if transfer_type:
                conditions.append("transfer_type = ?")
                params.append(transfer_type)
            if protocol:
                conditions.append("protocol = ?")
                params.append(protocol)
                
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
                
            query += " ORDER BY transfer_date DESC LIMIT ?"
            params.append(limit)
            
            cursor = conn.execute(query, params)
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor]

    def clear_logs(self):
        """Clear all logs from the database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM file_transfers")
            conn.commit()

# Example usage
if __name__ == '__main__':
    log_db = LogDatabaseHandler()
    
    # Add some test logs (in a real app, these would come from your application)
    log_db.add_transfer_log("sent", "FTP", "example_file.txt", 2048, "192.168.1.10", "192.168.1.20", "/src/path", "/dst/path")
    log_db.add_transfer_log("received", "SFTP", "another_file.txt", 1024, "192.168.1.20", "192.168.1.10", "/src/path", "/dst/path")
    
    # Retrieve and print logs
    logs = log_db.get_transfer_logs(limit=10)
    for log in logs:
        print(log)
