
from scapy.all import *
import os
import sys
sys.path.append("\file_transfer\src\configuration\setup_configs.py")
from setup_configs import loadConfigs

class UdpSession:
    
    def __init__(self, target):
        self.target = target
        self.ip = IP(dst=target[0])
        self.sport = loadConfigs()["udp_port"]
        self.dport = target[1]

    def sendFile(self, file_path):
        """Send a file over UDP"""
        if not os.path.isfile(file_path):
            print("File does not exist.")
            return
        
        with open(file_path, 'rb') as f:
            packet_id = 0
            while True:
                data = f.read(1024) 
                if not data:
                    break 
                packet = (self.ip / UDP(sport=self.sport, dport=self.dport) / Raw(load=data))
                send(packet)
                packet_id += 1

    def receiveFile(self, output_path):

        packets = sniff(filter=f"udp and port {self.dport}", count=0)
        data = b""
        with open(output_path, 'wb') as file:
            for packet in packets:
                if Raw in packet:
                    data += packet[Raw].load
            decData = self.fileHandler.decryptFile(None)
            file.write(decData)
            file.close()



