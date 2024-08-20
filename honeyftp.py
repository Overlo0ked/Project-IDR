import os
import socket
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Configuration monitoring
LISTENER_IP = '192.168.29.130'  # Change to the IP of the listener system
LISTENER_PORT = 8889             # Port for sending logs to the listener
ALERT_IP = '192.168.29.130'      # Change to the IP of the alert system
ALERT_PORT = 8888                # Port for sending logs to the alert system

# Logging function
def send_log(message, ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message.encode(), (ip, port))
    except Exception as e:  # Fixed the exception syntax
        print(f"Failed to send log to {ip}:{port} - {e}")

# Custom FTP handler to log commands
class LoggingFTPHandler(FTPHandler):
    failed_login_attempts = 0

    def on_connect(self):
        message = f"[*] Connection established from {self.remote_ip}:{self.remote_port}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_disconnect(self):
        message = f"[*] Connection closed from {self.remote_ip}:{self.remote_port}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_login(self, username):
        message = f"[*] User {username} logged in from {self.remote_ip}:{self.remote_port}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_login_failed(self, username, password):
        self.failed_login_attempts += 1
        if self.failed_login_attempts % 5 == 0:
            message = f"[!] {self.failed_login_attempts} failed login attempts from {self.remote_ip}:{self.remote_port} with username: {username}"  # Fixed typo
            print(message)
            send_log(message, LISTENER_IP, LISTENER_PORT)
            send_log(message, ALERT_IP, ALERT_PORT)

    def on_file_received(self, file):
        message = f"[*] File uploaded: {file}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_file_sent(self, file):
        message = f"[*] File downloaded: {file}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)  # Fixed typo (missing comma)

    def on_incomplete_file_received(self, file):
        message = f"[*] Incomplete file uploaded: {file}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_command(self, command, arg):
        message = f"[*] Command received: {command} {arg}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

# Main function to start the FTP server
def start_ftp_honeypot():
    # Configure author
    authorizer = DummyAuthorizer()
    authorizer.add_user('user', '12345', homedir='.', perm='radfmwMT')  # Add user with permissions
    authorizer.add_anonymous('.')  # Allow anonymous access

    # Initialize FTP handler
    handler = LoggingFTPHandler
    handler.authorizer = authorizer

    # Configure and start the FTP server
    server = FTPServer(('0.0.0.0', 21), handler)  # Bind to all interfaces on port 21
    print("[*] FTP Honeypot running on port 21...")
    server.serve_forever()  # Fixed indentation issue before the if statement

if __name__ == "__main__":
    start_ftp_honeypot()
                                                   
