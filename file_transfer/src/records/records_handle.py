import sqlite3
import os

class RecordHandler:

    def __init__(self, record_number, file_path, sender_ip, sender_username):

        self.recordNumber = record_number
        self.filePath = file_path
        self.fileFormat = os.path.splitext(file_path)
        self.fileSize = os.path.getsize(file_path)
        self.senderIp = sender_ip
        self.senderUsername = sender_username
        self.sendingTime = None

    def saveNewRecord(self):
        dbDirectory = ""
        pass
        
        
