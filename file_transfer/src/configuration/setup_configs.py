import json
import psutil
import os

class ConfigSetup:
    
    def __init__(self, iface, user_id, tcp_port, udp_port, user_nam):

        self.iface = iface
        self.userId = user_id
        self.tcpPort = tcp_port
        self.udpPort = udp_port
        self.userName = user_name


    def setConfigs(self):
        if os.path.exists("config.json"):
            return False
        configs = {"user_id":self.userId,
                   "iface": self.iface
                   "ip": psutil.net_if_addrs[self.iface],
                   "tcp_port":self.tcpPort,
                   "udp_port":self.udpPort,
                   "user_name":self.userName,
                   }
        with open("config.json", "w") as json_file:
            json.dump(configs, json_file)

def loadConfigs():

    if os.path.exists("config.json"):
        configs = json.load("config.json")
        return configs
