import netifaces
import json
import psutil
import os

class Network:

    def __init__(self, iface):
        self.iface = iface
        self.subnet = self.getSubnetMask()
        self.nodes = self.scanNetwork(self.subnet)
        
    def getSubnetMask(self):
        try:
            interface = self.iface
            ifaceInfo = netifaces.ifaddresses(interface)
            subnetMask = ifaceInfo[netifaces.AF_INET][0]['netmask']
            return subnetMask

        except KeyError:
            return False
        
    def scanNetwork(ip_range):
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn')  # -sn: Ping scan
        devices = []
        
        for host in nm.all_hosts():
            devices.append({'ip': host, 'status': nm[host].state()})
            
        return devices

    def setNetworkConfigs(self):
        if os.path.exists("net_configs.json"):
            return False
        netConfigs = {"iface":self.iface,
                      "subNetMask":self.subnet,
                      "nodes":self.nodes,
                      }
        
        with open("net_config.json", "w") as json_file:
            json.dump(netConfigs, json_file)


class ConfigSetup:
    
    def __init__(self, iface, user_id, tcp_port, udp_port, user_nam):

        self.iface = iface
        self.userId = user_id
        self.tcpPort = tcp_port
        self.udpPort = udp_port
        self.userName = user_name


    def setUserConfigs(self):
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

    def setNetworkConfigs(self):
        import nmap

def loadConfigs():

    if os.path.exists("config.json"):
        configs = json.load("config.json")
        return configs
