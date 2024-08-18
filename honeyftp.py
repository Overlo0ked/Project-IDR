import os
import socket
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Configuration for monitoring
MONITOR_IP = '192.168.29.130'  # Change to the IP of the monitoring system
MONITOR_PORT = 8888            # Port for sending logs

# Logging function
def send_log(message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message.encode(), (MONITOR_IP, MONITOR_PORT))
    except Exception as e:
        print(f"Failed to send log: {e}")

# Custom FTP handler to log commands
class LoggingFTPHandler(FTPHandler):
    def on_connect(self):
        # Use self.remote_ip and self.remote_port to get the address of the client
        print(f"[*] Connection established from {self.remote_ip}:{self.remote_port}")
        send_log(f"[*] Connection established from {self.remote_ip}:{self.remote_port}")

    def on_disconnect(self):
        # Use self.remote_ip and self.remote_port to get the address of the client
        print(f"[*] Connection closed from {self.remote_ip}:{self.remote_port}")
        send_log(f"[*] Connection closed from {self.remote_ip}:{self.remote_port}")

    def on_file_received(self, file):
        print(f"[*] File uploaded: {file}")
        send_log(f"[*] File uploaded: {file}")

    def on_file_sent(self, file):
        print(f"[*] File downloaded: {file}")
        send_log(f"[*] File downloaded: {file}")

    def on_incomplete_file_received(self, file):
        print(f"[*] Incomplete file uploaded: {file}")
        send_log(f"[*] Incomplete file uploaded: {file}")

# Main function to start the FTP server
def start_ftp_honeypot():
    # Configure authorizers
    authorizer = DummyAuthorizer()
    authorizer.add_user('user', '12345', homedir='.', perm='elradfmwMT')  # Add user with permissions
    authorizer.add_anonymous('.')  # Allow anonymous access

    # Initialize FTP handler
    handler = LoggingFTPHandler
    handler.authorizer = authorizer

    # Configure and start the FTP server
    server = FTPServer(('0.0.0.0', 21), handler)  # Bind to all interfaces on port 21
    print("[*] FTP Honeypot running on port 21...")
    server.serve_forever()

if __name__ == "__main__":
    start_ftp_honeypot()
