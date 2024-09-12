import os
import socket
import requests
import threading
from collections import defaultdict
from time import strftime, gmtime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Configuration
LISTENER_IP = '192.168.29.130'  # Change to the IP of the listener system
LISTENER_PORT = 8889             # Port for sending logs to the listener
ALERT_IP = '192.168.29.130'      # Change to the IP of the alert system
ALERT_PORT = 8888                # Port for sending logs to the alert system

# Brute force attempt tracking
class BruteForceTracker:
    def __init__(self):
        self.failed_attempts = defaultdict(int)
        self.brute_force_threshold = 5  # Number of failed attempts before alerting
        self.alerting = False
        self.timers = {}

    def on_login_failed(self, remote_ip):
        self.failed_attempts[remote_ip] += 1
        print(f"Failed login attempt from {remote_ip}. Total attempts: {self.failed_attempts[remote_ip]}")

        if self.failed_attempts[remote_ip] == self.brute_force_threshold:
            self.alerting = True
            message = f"BRUTEFORCE ATTEMPT FOUND AT FTP FROM {remote_ip}"
            print(message)
            send_log(message, LISTENER_IP, LISTENER_PORT)
            send_log(message, ALERT_IP, ALERT_PORT)

            # Start a timer for 10 seconds to check for further attempts
            if remote_ip in self.timers:
                self.timers[remote_ip].cancel()

            self.timers[remote_ip] = threading.Timer(10, self.reset_attempts, args=(remote_ip,))
            self.timers[remote_ip].start()

    def reset_attempts(self, remote_ip):
        print(f"Resetting failed attempts for {remote_ip}.")
        self.failed_attempts[remote_ip] = 0
        self.alerting = False

        if remote_ip in self.timers:
            self.timers[remote_ip].cancel()
            del self.timers[remote_ip]

# Global instance of brute force tracker
brute_force_tracker = BruteForceTracker()

# Function to get the location of the IP address
def get_location(ip):
    try:
        if ip.startswith(('192.', '10.', '172.')):
            return "Private IP Address - Unknown location"

        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return f"{data['city']}, {data['regionName']}, {data['country']} - {data['isp']}"
            else:
                return "Unknown location"
        else:
            return "Error retrieving location"
    except Exception as e:
        print(f"Error fetching location for IP {ip}: {e}")
        return "Unknown location"

# Logging function
def send_log(message, ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message.encode(), (ip, port))
    except Exception as e:
        print(f"Failed to send log to {ip}:{port} - {e}")

# Custom FTP handler to log commands
class LoggingFTPHandler(FTPHandler):
    def on_log_in(self, username):
        location = get_location(self.remote_ip)
        message = f"[*] {strftime('%Y-%m-%d %H:%M:%S', gmtime())} - User {username} logged in from {self.remote_ip}:{self.remote_port} - {location}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

        # Reset failed attempts on successful login
        brute_force_tracker.reset_attempts(self.remote_ip)

    def on_login_failed(self, username, password):
        brute_force_tracker.on_login_failed(self.remote_ip)

        # Log the failed login attempt
        location = get_location(self.remote_ip)
        message = f"[*] {strftime('%Y-%m-%d %H:%M:%S', gmtime())} - Failed login attempt from {self.remote_ip}:{self.remote_port} for {username} - {location}"
        print(message)
        send_log(message, LISTENER_IP, LISTENER_PORT)
        send_log(message, ALERT_IP, ALERT_PORT)

# Main function to start the FTP server
def start_ftp_honeypot():
    authorizer = DummyAuthorizer()
    authorizer.add_user('user', '12345', homedir='.', perm='elradfmwMT')
    authorizer.add_anonymous('.')

    handler = LoggingFTPHandler
    handler.authorizer = authorizer

    server = FTPServer(('0.0.0.0', 21), handler)
    print("[*] FTP Honeypot running on port 21...")
    server.serve_forever()

if __name__ == "__main__":
    start_ftp_honeypot()
