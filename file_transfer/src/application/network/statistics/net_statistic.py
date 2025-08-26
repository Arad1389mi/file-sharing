import psutil
import sqlite3
from datetime import datetime

class NetStatistics:
    
    def __init__(self):
        self.networkIO = psutil.net_io_counters()

    def getBytesSent(self):
        return self.networkIO.bytes_sent

    def getBytesRecv(self):
        return self.networkIO.bytes_recv

    def getPacketsSent(self):
        return self.networkIO.packets_sent

    def getPacketsRecv(self):
        return self.networkIO.packets_recv

    def getDroppedInPackets(self):
        return self.networkIO.dropin
    
    def getDroppedOutPackets(self):
        return self.networkIO.dropout

    def getNetworkConnections(self):
        connections = psutil.net_connections()
        return [{'local_address': conn.laddr, 'remote_address': conn.raddr, 'status': conn.status} for conn in connections]
    
    def getTransferedFilesByDate(self, date1, date2):
        """Retrieve transferred files between two dates."""
        conn = sqlite3.connect("D:\\file_transfer\\src\\transfer_logs\\logs\\logs.db")
        cursor = conn.cursor()
        
        query = """
        SELECT file_name, transfer_date, file_size, protocol
        FROM file_transfers 
        WHERE transfer_date BETWEEN ? AND ?
        """
        
        cursor.execute(query, (date1, date2))
        results = cursor.fetchall()
        
        conn.close()
        
        return [{'file_name': row[0], 'transfer_date': row[1], 'size': row[2], 'protocol': row[3]} for row in results]

    def getNetworkStatsByDate(self, date1, date2):
        """Retrieve network statistics between two dates."""
        conn = sqlite3.connect("D:\\file_transfer\\src\\transfer_logs\\logs\\logs.db")
        cursor = conn.cursor()

        
        query = """
        SELECT date, bytes_sent, bytes_recv, packets_sent, packets_recv, dropin, dropout 
        FROM network_stats 
        WHERE date BETWEEN ? AND ?
        """
        
        cursor.execute(query, (date1, date2))
        results = cursor.fetchall()
        
        conn.close()
        
        return [{'date': row[0], 'bytes_sent': row[1], 'bytes_recv': row[2], 
                 'packets_sent': row[3], 'packets_recv': row[4], 
                 'dropin': row[5], 'dropout': row[6]} for row in results]
