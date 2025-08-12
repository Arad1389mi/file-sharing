from scapy.all import *
sys.path.append("D:\file_transfer\src\configuration\setup_configs.py")
from setup_configs import loadConfigs

class TcpSession:
    def __init__(self, target):
        
        self.target = target
        self.seq = 0
        self.ack = 0
        self.ip = IP(src=loadConfigs()["ip"], dst=target[0])
        self.sport = loadConfigs()["tcp_port"]
        self.dport = target[1]
        self.connected = False


    def accept_connection(self):
        """Server-side connection acceptance"""
        # Listen for SYN
        syn_packet = sniff(filter=f"tcp port {self.sport}", count=1, iface=loadConfigs()["iface"])
        client_ip = syn_packet[0][IP].src
        client_port = syn_packet[0][TCP].sport
        
        # Send SYN-ACK
        self.seq = 1000  # Server initial sequence
        self.ack = syn_packet[0][TCP].seq + 1
        synack = (IP(src=loadConfigs()["ip"], dst=client_ip)/TCP(
            sport=self.sport, 
            dport=client_port,
            flags="SA",
            seq=self.seq,
            ack=self.ack
        ))
        send(synack, iface=loadConfigs()["iface"])
        
        # Wait for ACK
        ack_packet = sniff(filter=f"tcp port {self.sport}", count=1, iface=loadConfigs()["iface"])
        self.connected = True


    def connect(self):
        
        syn = self.ip/TCP(sport=RandShort(), dport=self.dport, flags='S')
        synack = sr1(syn, iface=loadConfigs()["iface"])
        self.ack = synack.seq + 1
        self.seq = synack.ack
        ack = self.ip/TCP(
            sport=synack.dport, 
            dport=synack.sport, 
            flags='A',
            seq=self.seq,
            ack=self.ack
        )
        send(ack, iface=loadConfigs()["iface"])
        self.connected = True


    def close(self):

        fin = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        send(fin, iface=loadConfigs()["iface"])
        self.connected = False
