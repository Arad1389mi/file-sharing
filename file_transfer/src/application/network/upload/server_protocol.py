import os
import sys
sys.path.append("D:\file_transfer\src\configuration\setup_configs.py")
sys.path.append("D:\file_transfer\src\application\file_handler.py")
sys.path.append("D:\file_transfer\src\application\network\common\network_tcp_protocol.py")
sys.path.append("D:\file_transfer\src\application\network\common\network_udp_protocol.py")
sys.path.append("D:\file_transfer\src\transfer_logs\log_recorder.py")

from setup_configs import loadConfigs
from file_handler import FileHandler
from log_recorder import LogRecorder
from network_tcp_protocol import TcpSession
from network_udp_protocol import UdpSession
from scapy.all import *

def run(tcpSessionObject):
    tcpSessionObject.acceptConnection()
    tcpFileSenderObject = TcpFileSender(tcpSessionObject, input())
    tcpFileSenderObject.sendFile()
    ####################
    ####################
    ####################
    ####################
    tcpSessionObject.close()
    
def tcpSendData(session, data):
    
    if session.connected:
        packet = session.ip/TCP(sport=session.sport, dport=session.dport, flags='PA', seq=session.seq, ack=session.ack)/Raw(load=data)
        send(packet)
        session.seq += len(data)

def udpSendData(session, data):
    pass

class TcpFileSender:
    
    def __init__(self, tcp_session, file_path):
        
        self.tcpSession = tcp_session
        self.filePath = file_path
        self.fileHandler = FileHandler(self.filePath)
        self.logRecorder = LogRecorder()

    def sendFile(self):
        self.tcpSession.accept_connection()
        # fileData = self.fileHandler.readFile()
        encData = self.fileHandler.encryptFile(None)
        index = 0
        while True:
            
            data = encData[index: index+1024]
            if data == '':
                break
            
            tcpSendData(self.tcpSession, data)
        
        self.logRecorder.addFileLog("send", self.file_path.split('\\')[-1].split('.')[-1],
                                    "tcp", os.path.getsize(self.file_path), self.file_path, "none"
                                    )

class UdpFileSender:

    def __init__(self, udp_session, file_path):

        self.udpSession = udp_session
        self.filePath = file_path
        self.fileHandler = FileHandler(self.filePath)

    def sendFile(self):
        encData = self.fileHandler.encryptFile(None)
        index = 0
        while True:
            
            data = encData[index: index+1024]
            if data == '':
                break
            
            udpSendData(self.udpSession, data)

        self.logRecorder.addFileLog("send", self.file_path.split('\\')[-1].split('.')[-1],
                                    "udp", os.path.getsize(self.file_path), self.file_path, "none"
                                    )

        
            
        


   
   
