from scapy.all import *
import sys
import time
import os
import threading

sys.path.append("D:\\file_transfer\\src\\application\\network\\common")
sys.path.append("D:\\file_transfer\\src\\configuration")
sys.path.append("D:\\file_transfer\\src\\application\\network\\upload")
sys.path.append("D:\\file_transfer\\src\\application\\network\\download")

from network_tcp_protocol import TcpSession
from server_protocol import TcpFileSender
from client_protocol import TcpFileReceiver
from setup_configs import loadConfigs

REQUEST_MSG = b"FILE_REQUEST"
ACCEPT_MSG = b"ACCEPT_FILE"
REJECT_MSG = b"REJECT_FILE"

class RequestHandler:
    def __init__(self, target_ip=None, target_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.tcp_session = None
        self.connected = False
        self.local_ip = loadConfigs()["ip"]
        self.local_port = loadConfigs()["tcp_port"]
        self.iface = loadConfigs()["iface"]

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

    def send_file_request(self, file_info=""):
        if not self.target_ip or not self.target_port:
            print("Error: Target IP and Port must be set for sending requests.")
            return False

        self.tcp_session = TcpSession((self.target_ip, self.target_port))
        print(f"Attempting to connect to {self.target_ip}:{self.target_port}...")
        try:
            self.tcp_session.connect()
            self.connected = self.tcp_session.connected
            if not self.connected:
                print(f"Failed to establish TCP connection to {self.target_ip}:{self.target_port}.")
                return False
            print(f"Successfully connected to {self.target_ip}:{self.target_port}.")

            request_payload = REQUEST_MSG + b":" + file_info.encode('utf-8')
            print(f"Sending file request: '{request_payload.decode()}'...")
            if not self._send_raw_data(self.tcp_session, request_payload):
                self.close_connection()
                return False

            print("Waiting for receiver's response (ACCEPT/REJECT)...")
            response_packet = sniff(
                filter=f"tcp and src host {self.target_ip} and src port {self.target_port} and dst port {self.local_port}",
                count=1,
                timeout=30,
                iface=self.iface
            )

            if response_packet and Raw in response_packet[0]:
                response_data = response_packet[0][Raw].load
                if response_data == ACCEPT_MSG:
                    print("Receiver accepted the file transfer!")
                    return True
                elif response_data == REJECT_MSG:
                    print("Receiver rejected the file transfer.")
                    return False
                else:
                    print(f"Received unexpected response: {response_data.decode()}")
                    return False
            else:
                print("No response received from receiver within timeout.")
                return False

        except Exception as e:
            print(f"An error occurred during request sending: {e}")
            return False
        finally:
            if not self.connected:
                self.close_connection()

    def accept_file_request(self):
        self.tcp_session = TcpSession((self.local_ip, self.local_port))
        print(f"Receiver listening for incoming requests on {self.local_ip}:{self.local_port}...")

        try:
            self.tcp_session.accept_connection()
            self.connected = self.tcp_session.connected
            if not self.connected:
                print("Failed to accept incoming TCP connection.")
                return False, None, None
            print(f"Connection established with {self.tcp_session.target[0]}:{self.tcp_session.target[1]}.")

            print("Waiting for file request message...")
            request_packet = sniff(
                filter=f"tcp and src host {self.tcp_session.target[0]} and src port {self.tcp_session.target[1]} and dst port {self.local_port}",
                count=1,
                timeout=30,
                iface=self.iface
            )

            if request_packet and Raw in request_packet[0]:
                request_data = request_packet[0][Raw].load
                if request_data.startswith(REQUEST_MSG):
                    file_info = request_data[len(REQUEST_MSG)+1:].decode('utf-8')
                    print(f"\n--- Incoming File Request from {self.tcp_session.target[0]} ---")
                    print(f"File Info: '{file_info}'")

                    user_response = input("Do you want to accept this file transfer? (yes/no): ").lower().strip()

                    if user_response == 'yes':
                        print("Sending ACCEPTANCE...")
                        self._send_raw_data(self.tcp_session, ACCEPT_MSG)
                        print("Request accepted. Connection ready for file transfer.")
                        return True, self.tcp_session, file_info
                    else:
                        print("Sending REJECTION...")
                        self._send_raw_data(self.tcp_session, REJECT_MSG)
                        print("Request rejected.")
                        self.close_connection()
                        return False, None, None
                else:
                    print(f"Received unexpected message: {request_data.decode()}")
                    self.close_connection()
                    return False, None, None
            else:
                print("No file request message received within timeout.")
                self.close_connection()
                return False, None, None

        except Exception as e:
            print(f"An error occurred during request acceptance: {e}")
            self.close_connection()
            return False, None, None

    def close_connection(self):
        if self.tcp_session and self.connected:
            self.tcp_session.close()
            self.connected = False
            print(f"Connection to {self.tcp_session.target[0]}:{self.tcp_session.target[1]} closed.")
        elif self.tcp_session:
            print("No active connection to close.")

if __name__ == "__main__":
    TARGET_IP = "192.168.1.101"
    TARGET_PORT = 12345

    mode = input("Run as (s)ender or (r)eceiver? ").lower().strip()

    if mode == 's':
        print("\n--- Running as SENDER ---")
        sender = RequestHandler(target_ip=TARGET_IP, target_port=TARGET_PORT)
        file_to_send_name = "document.pdf"
        if sender.send_file_request(file_info=f"File: {file_to_send_name}, Size: 1.2MB"):
            print("Sender: Request accepted! You can now proceed with file transfer using sender.tcp_session.")
            file_path = input("Enter your file path: ")
            file_sender_obj = TcpFileSender(sender.tcp_session, file_path)
            file_sender_obj.sendFile()
        else:
            print("Sender: Request not accepted or failed.")
        sender.close_connection()

    elif mode == 'r':
        print("\n--- Running as RECEIVER ---")
        receiver = RequestHandler()
        accepted, session, file_info = receiver.accept_file_request()
        if accepted:
            print(f"Receiver: Request accepted! Session is ready for receiving file: {file_info}")
            output_path = f"received_{file_info.split(': ')[1].split(',')[0]}"
            file_receiver_obj = TcpFileReceiver(session, output_path)
            file_receiver_obj.tcpReceiveFile()
        else:
            print("Receiver: Request not accepted or failed.")

    else:
        print("Invalid mode. Please choose 's' for sender or 'r' for receiver.")
