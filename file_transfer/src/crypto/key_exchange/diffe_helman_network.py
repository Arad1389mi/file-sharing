from scapy.all import *
import sys
import json
import time

sys.path.append("D:\\file_transfer\\src\\application\\file_cryption")
sys.path.append("D:\\file_transfer\\src\\configuration")
sys.path.append("D:\\file_transfer\\src\\application\\network\\common")

from diffe_helman import HybridEncryptionSystem
from network_tcp_protocol import TcpSession
from setup_configs import loadConfigs

DH_REQUEST = b"DH_REQUEST"
DH_RESPONSE = b"DH_RESPONSE"

class DiffeHelmanShareKey:
    def __init__(self, target_ip=None, target_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.local_ip = loadConfigs()["ip"]
        self.local_port = loadConfigs()["tcp_port"]
        self.iface = loadConfigs()["iface"]
        self.dh_system = HybridEncryptionSystem()
        self.tcp_session = None
        self.shared_aes_key = None

    def _send_raw_data(self, session, data_bytes):
        if not session.connected:
            print("Error: Session not connected.")
            return False

        packet = session.ip / TCP(
            sport=session.sport,
            dport=session.dport,
            flags='PA',
            seq=session.seq,
            ack=session.ack
        ) / Raw(load=data_bytes)

        try:
            send(packet, iface=self.iface, verbose=0)
            session.seq += len(data_bytes)
            return True
        except Exception as e:
            print(f"Error sending data: {e}")
            return False

    def _receive_raw_data(self, session, timeout=30):
        try:
            received_packet = sniff(
                filter=f"tcp and src host {session.target[0]} and src port {session.target[1]} and dst port {self.local_port}",
                count=1,
                timeout=timeout,
                iface=self.iface
            )
            if received_packet and Raw in received_packet[0]:
                return received_packet[0][Raw].load
            return None
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None

    def initiate_key_exchange(self, message_to_encrypt=b"Hello, secure world!"):
        if not self.target_ip or not self.target_port:
            print("Error: Target IP and Port must be set for initiating key exchange.")
            return False

        self.tcp_session = TcpSession((self.target_ip, self.target_port))
        print(f"Attempting to connect to {self.target_ip}:{self.target_port} for DH exchange...")
        try:
            self.tcp_session.connect()
            if not self.tcp_session.connected:
                print("Failed to establish TCP connection for DH exchange.")
                return False
            print(f"Successfully connected to {self.target_ip}:{self.target_port}.")

            encrypted_dh_params = self.dh_system.encryptWithDHParams(message_to_encrypt)
            payload = DH_REQUEST + b":" + json.dumps(encrypted_dh_params).encode('utf-8')
            print("Sending DH request with encrypted parameters...")
            if not self._send_raw_data(self.tcp_session, payload):
                self.close_connection()
                return False

            print("Waiting for peer's DH response...")
            response_data = self._receive_raw_data(self.tcp_session)

            if response_data and response_data.startswith(DH_RESPONSE):
                received_json_str = response_data[len(DH_RESPONSE)+1:].decode('utf-8')
                peer_encrypted_params = json.loads(received_json_str)
                decrypted_message, peer_dh_public, prime, generator = self.dh_system.decryptDHParams(peer_encrypted_params)
                self.shared_aes_key = self.dh_system.sharedSecret

                print(f"DH Key Exchange successful! Shared AES Key (derived): {self.shared_aes_key.hex()}")
                print(f"Decrypted message from peer: {decrypted_message.decode()}")
                return True
            else:
                print("Did not receive a valid DH response from peer.")
                return False

        except Exception as e:
            print(f"An error occurred during key exchange initiation: {e}")
            return False
        finally:
            if not self.shared_aes_key:
                self.close_connection()

    def respond_to_key_exchange(self):
        self.tcp_session = TcpSession((self.local_ip, self.local_port))
        print(f"Listening for incoming DH key exchange requests on {self.local_ip}:{self.local_port}...")

        try:
            self.tcp_session.accept_connection()
            if not self.tcp_session.connected:
                print("Failed to accept incoming TCP connection for DH exchange.")
                return False
            print(f"Connection established with {self.tcp_session.target[0]}:{self.tcp_session.target[1]}.")

            print("Waiting for peer's DH request...")
            request_data = self._receive_raw_data(self.tcp_session)

            if request_data and request_data.startswith(DH_REQUEST):
                received_json_str = request_data[len(DH_REQUEST)+1:].decode('utf-8')
                peer_encrypted_params = json.loads(received_json_str)
                decrypted_message, peer_dh_public, prime, generator = self.dh_system.decryptDHParams(peer_encrypted_params)
                self.shared_aes_key = self.dh_system.sharedSecret

                print(f"Received DH request. Decrypted message: {decrypted_message.decode()}")
                print(f"Shared AES Key (derived): {self.shared_aes_key.hex()}")

                response_message = b"DH exchange complete from responder!"
                encrypted_response_params = self.dh_system.encryptWithDHParams(response_message)

                payload = DH_RESPONSE + b":" + json.dumps(encrypted_response_params).encode('utf-8')
                print("Sending DH response with encrypted parameters...")
                if not self._send_raw_data(self.tcp_session, payload):
                    self.close_connection()
                    return False

                print("DH Key Exchange successful!")
                return True
            else:
                print("Did not receive a valid DH request from peer.")
                return False

        except Exception as e:
            print(f"An error occurred during key exchange response: {e}")
            return False
        finally:
            if not self.shared_aes_key:
                self.close_connection()

    def close_connection(self):
        if self.tcp_session and self.tcp_session.connected:
            self.tcp_session.close()
            print(f"Connection to {self.tcp_session.target[0]}:{self.tcp_session.target[1]} closed.")
        elif self.tcp_session:
            print("No active connection to close.")

"""if __name__ == "__main__":
    TARGET_IP = "192.168.1.101"
    TARGET_PORT = 12345

    mode = input("Run as (i)nitiator or (r)esponder? ").lower().strip()

    if mode == 'i':
        print("\n--- Running as INITIATOR (Client) ---")
        dh_client = DiffeHelmanShareKey(target_ip=TARGET_IP, target_port=TARGET_PORT)
        if dh_client.initiate_key_exchange(message_to_encrypt=b"Secret message from client!"):
            print("Initiator: Key exchange completed. Shared AES key is available.")
        else:
            print("Initiator: Key exchange failed.")
        dh_client.close_connection()

    elif mode == 'r':
        print("\n--- Running as RESPONDER (Server) ---")
        dh_server = DiffeHelmanShareKey()
        if dh_server.respond_to_key_exchange():
            print("Responder: Key exchange completed. Shared AES key is available.")
        else:
            print("Responder: Key exchange failed.")
        dh_server.close_connection()

    else:
        print("Invalid mode. Please choose 'i' for initiator or 'r' for responder.")"""
