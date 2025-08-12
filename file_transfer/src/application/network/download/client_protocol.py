import os
import sys
from scapy.all import *
sys.path.append("D:\file_transfer\src\application\network\common\network_udp_protocol.py")
sys.path.append("D:\file_transfer\src\configuration\setup_configs.py")
sys.path.append("D:\file_transfer\src\application\file_handler.py")
sys.path.append("D:\file_transfer\src\application\network\common\network_tcp_protocol.py")
from setup_configs import loadConfigs
from file_handler import FileHandler
from network_tcp_protocol import TcpSession
from network_udp_protocol import UdpSession

class TcpFileReceiver:
    
    def __init__(self, tcp_session, output_file_path):
        self.tcpSession = tcp_session
        self.outputFilePath = output_file_path
        self.fileHandler = FileHandler(self.outputFilePath)

    def tcpReceiveFile(self):
        self.tcpSession.connect()

        downloadedData = b""
        
        while self.tcpSession.connected:
            packet = sniff(filter=f"tcp and port {self.tcpSession.dport}", count=1)
            if packet:
                data = bytes(packet[0][Raw])
                if data:
                    decData = self.fileHandler.decryptFile(data)
                    downloadedData += data
                    self.tcpSession.ack += len(data)
#                    print(f"Received and saved {len(data)} bytes.")
        self.fileHandler.writeFile(downloadedData)
        self.tcpSession.close()

class UdpFileReciver:

    def __init__(self, udp_session, output_path):
        self.udpSession = udp_session
        self.outputPath = output_path

    def udpReceiveFile(self):
        self.udpSession.receiveFile(input())


        
