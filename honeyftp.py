import os
import socket
import threading
import string
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    except Exception as e:
        print(f"Failed to send log to {ip}:{port} - {e}")

# Custom FTP handler to log commands and manage users
class LoggingFTPHandler(FTPHandler):
    failed_login_attempts = 0
    USERNAMES = ["admin", "user", "Admin", "Administrator", "anonymous", "guest"]
    PASSWORDS = ["admin", "1234", "password", "Admin", "guest", "anonymous"]

    def on_connect(self):
        message = f"[*] FTP Connection established from {self.remote_ip}:{self.remote_port}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_disconnect(self):
        message = f"[*] FTP Connection closed from {self.remote_ip}:{self.remote_port}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_login(self, username):
        message = f"[*] FTP User {username} logged in from {self.remote_ip}:{self.remote_port}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def on_login_failed(self, username, password):
        self.failed_login_attempts += 1
        if self.failed_login_attempts % 5 == 0:
            message = f"[!] {self.failed_login_attempts} failed FTP login attempts from {self.remote_ip}:{self.remote_port} with username: {username}"
            print(message)
            send_log(message, LISTENER_IP, LISTENER_PORT)
            send_log(message, ALERT_IP, ALERT_PORT)

    def on_command(self, command, arg):
        message = f"[*] FTP Command received: {command} {arg}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

    def cmd_USER(self, username):
        if username in self.USERNAMES:
            self.send_response(331, "Username accepted, password required.")
        else:
            self.send_response(530, "Invalid username.")
            self.on_login_failed(username, None)

    def cmd_PASS(self, password):
        # Here, we simulate password checking
        if password in self.PASSWORDS:
            self.on_login(self.current_username)  # Use current username set in cmd_USER
            self.send_response(230, "Authentication successful.")
        else:
            self.send_response(530, "Invalid password.")
            self.on_login_failed(self.current_username, password)

# Custom HTTP handler to log requests and collect client info
class ClientInfoHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            js_script = """  
            <script>  
            function collectClientInfo() {  
                let clientInfo = {  
                    deviceType: navigator.userAgent,  
                    os: navigator.platform,  
                    browser: navigator.userAgent,  
                    screenResolution: `${window.screen.width}x${window.screen.height}`,  
                    language: navigator.language,  
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,  
                    cpuArchitecture: navigator.hardwareConcurrency ? navigator.hardwareConcurrency : "unknown",  
                    memory: navigator.deviceMemory ? `${navigator.deviceMemory}GB` : "unknown"  
                };  
                fetch('/collect', {  
                    method: 'POST',  
                    headers: {'Content-Type': 'application/json'},  
                    body: JSON.stringify(clientInfo)  
                });  
            }  
            window.onload = collectClientInfo;  
            </script>  
            <h1>Welcome to the Honeypot HTTP Server</h1>  
            """  
            self.send_response(200)  
            self.send_header("Content-type", "text/html")  
            self.end_headers()  
            self.wfile.write(js_script.encode('utf-8'))  

    def do_POST(self):
        if self.path == '/collect':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')

            # Format the JSON data for better readability
            client_data = json.loads(post_data)  # Convert string to JSON

            # Create a formatted string
            formatted_data = (
                f"[Client Data]\n"
                f"  Device Type: {client_data.get('deviceType', 'unknown')}\n"
                f"  Operating System: {client_data.get('os', 'unknown')}\n"
                f"  Browser: {client_data.get('browser', 'unknown')}\n"
                f"  Screen Resolution: {client_data.get('screenResolution', 'unknown')}\n"
                f"  Language: {client_data.get('language', 'unknown')}\n"
                f"  Timezone: {client_data.get('timezone', 'unknown')}\n"
                f"  CPU Architecture: {client_data.get('cpuArchitecture', 'unknown')}\n"
                f"  Memory: {client_data.get('memory', 'unknown')}\n"
            )
            
            # Get current timestamp
            timestamp = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
            client_ip = self.client_address[0]
            
            # Log the formatted message
            message = f"{client_ip} - - [{timestamp}] \"POST /collect HTTP/1.1\" 200 -\n{formatted_data}"
            print(message)
            
            send_log(message, LISTENER_IP, LISTENER_PORT)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Data collected successfully")

# Main function to start the FTP and HTTP servers
def start_honeypot():
    # Configure FTP authorizer
    ftp_authorizer = DummyAuthorizer()
    ftp_authorizer.add_user('user', '12345', homedir='.', perm='elradfmwMT')  # Add user with all permissions
    ftp_authorizer.add_anonymous('.')  # Allow anonymous access

    # Initialize FTP handler
    ftp_handler = LoggingFTPHandler
    ftp_handler.authorizer = ftp_authorizer

    # Configure and start the FTP server
    ftp_server = FTPServer(('0.0.0.0', 21), ftp_handler)  # Bind to all interfaces on port 21
    print("[*] FTP Honeypot running on port 21...")

    # Configure and start the HTTP server
    http_server = HTTPServer(('0.0.0.0', 80), ClientInfoHTTPRequestHandler)
    print("[*] HTTP Honeypot running on port 80...")

    # Start both servers concurrently
    ftp_thread = threading.Thread(target=ftp_server.serve_forever)
    http_thread = threading.Thread(target=http_server.serve_forever)
    ftp_thread.start()
    http_thread.start()

    # Wait for both servers to finish (optional)
    ftp_thread.join()
    http_thread.join()

# Start the honeypot server

if __name__ == "__main__":
    start_honeypot()
