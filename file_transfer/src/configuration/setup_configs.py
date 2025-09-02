import json
import psutil
import os
import socket
import struct

class Network:

    def __init__(self, iface):
        self.iface = iface
        self.subnet = self.getSubnetMask()
        self.nodes = self.scanNetwork(self.subnet) if self.subnet else []

    def getSubnetMask(self):
        """
        Get subnet mask for the interface using psutil.
        Returns subnet mask as string or False if not found.
        """
        addrs = psutil.net_if_addrs()
        if self.iface not in addrs:
            return False
        for addr in addrs[self.iface]:
            if addr.family == socket.AF_INET:
                return addr.netmask
        return False

    @staticmethod
    def scanNetwork(ip_range):
        """
        Scan the network for active hosts using nmap.
        ip_range should be a string like '192.168.1.0/24'.
        Returns list of dicts with 'ip' and 'status'.
        """
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn')  # Ping scan
        devices = []
        for host in nm.all_hosts():
            devices.append({'ip': host, 'status': nm[host].state()})
        return devices

    def setNetworkConfigs(self):
        """
        Save network configuration to net_config.json if it doesn't exist.
        """
        if os.path.exists("net_config.json"):
            return False
        netConfigs = {
            "iface": self.iface,
            "subNetMask": self.subnet,
            "nodes": self.nodes,
        }
        with open("net_config.json", "w") as json_file:
            json.dump(netConfigs, json_file)
        return True


class ConfigSetup:

    def __init__(self, iface, user_id, tcp_port, udp_port, user_name):
        self.iface = iface
        self.userId = user_id
        self.tcpPort = tcp_port
        self.udpPort = udp_port
        self.userName = user_name

    def get_ip_address(self):
        """
        Get the IPv4 address of the interface using psutil.
        Returns IP as string or None if not found.
        """
        addrs = psutil.net_if_addrs()
        if self.iface not in addrs:
            return None
        for addr in addrs[self.iface]:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    def setUserConfigs(self):
        """
        Save user and network configs to config.json if it doesn't exist.
        """
        if os.path.exists("config.json"):
            return False
        ip_addr = self.get_ip_address()
        configs = {
            "user_id": self.userId,
            "iface": self.iface,
            "ip": ip_addr if ip_addr else "",
            "tcp_port": self.tcpPort,
            "udp_port": self.udpPort,
            "user_name": self.userName,
        }
        with open("config.json", "w") as json_file:
            json.dump(configs, json_file)
        return True

    def setNetworkConfigs(self):
        # Placeholder for any network config setup if needed
        pass


def loadConfigs():
    """
    Load configuration from config.json.
    Returns dict or None if file not found.
    """
    if os.path.exists("config.json"):
        with open("config.json", "r") as f:
            configs = json.load(f)
        return configs
    return None
