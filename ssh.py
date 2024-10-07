import socket
import threading
import paramiko
import logging
import requests
from collections import defaultdict
from time import time

# Logging Configuration
logging.basicConfig(filename='ssh_honeypot.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# SSH Honeypot Configuration
HONEYPOT_HOST = '0.0.0.0'
HONEYPOT_PORT = 2222
HOST_KEY = paramiko.RSAKey.generate(2048)

# Username and Password Configuration
ALLOWED_USERNAME = "elonmusk"
ALLOWED_PASSWORD = "spacex123"

# Brute Force Tracking
class BruteForceTracker:
    def __init__(self):
        self.failed_attempts = defaultdict(int)
        self.brute_force_threshold = 5
        self.lockout_duration = 60
        self.locked_ips = {}

    def record_failed_attempt(self, remote_ip):
        if remote_ip in self.locked_ips:
            if time() - self.locked_ips[remote_ip] > self.lockout_duration:
                del self.locked_ips[remote_ip]
            else:
                logging.info(f"Blocked attempt from {remote_ip} due to lockout.")
                return False

        self.failed_attempts[remote_ip] += 1
        logging.info(f"Failed login attempt from {remote_ip}. Total attempts: {self.failed_attempts[remote_ip]}")

        if self.failed_attempts[remote_ip] >= self.brute_force_threshold:
            logging.warning(f"BRUTE FORCE DETECTED from {remote_ip}. Locking out for {self.lockout_duration} seconds.")
            self.locked_ips[remote_ip] = time()
            self.failed_attempts[remote_ip] = 0
            return False

        return True

    def record_successful_attempt(self, remote_ip):
        if remote_ip in self.failed_attempts:
            del self.failed_attempts[remote_ip]

brute_force_tracker = BruteForceTracker()

# IP Geolocation Function
def get_geolocation(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            location = data.get('city', 'Unknown') + ", " + data.get('country', 'Unknown')
            logging.info(f"IP {ip} is from {location}.")
            return location
        return "Unknown location"
    except Exception as e:
        logging.error(f"Failed to fetch geolocation for {ip}: {e}")
        return "Unknown location"

# Fake Shell Commands and Responses
def fake_shell(channel):
    channel.send("\r\nWelcome to the spaceX server!\r\n")
    channel.send("Authorized access only. Use of this system is monitored.\r\n\r\n")
    current_user = "elonmusk"
    current_path = "/home/elonmusk"

    # Simulated file system
    file_system = {
        "/": ["home", "etc", "var", "usr"],
        "/home": ["elonmusk"],
        "/home/elonmusk": ["projects", "documents", ".ssh", "passwords.txt"],
        "/home/elonmusk/.ssh": ["authorized_keys"],
        "/etc": ["passwd", "shadow", "network_config"],
        "/var": ["log"],
        "/var/log": ["auth.log"]
    }

    fake_files = {
        "/home/elonmusk/passwords.txt": "root:toor\nadmin:admin123\nelonmusk:spacex123\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nelonmusk:x:1000:1000:,,,:/home/elonmusk:/bin/bash\n",
        "/var/log/auth.log": "Jan 1 12:00:00 spaceX sshd[1234]: Accepted password for elonmusk from 192.168.0.1 port 22\n",
        "/home/elonmusk/.ssh/authorized_keys": ""
    }

    while True:
        try:
            channel.send(f"{current_user}@spaceX:{current_path}$ ")
            command = channel.recv(1024).decode("utf-8").strip()
            if not command:
                continue

            client_ip = channel.getpeername()[0]
            log_message = f"[SSH COMMAND] {client_ip} executed: {command}"
            logging.info(log_message)

            # Handle common commands with simulated output
            if command.lower() == "help":
                channel.send("Available commands: ls, pwd, whoami, cd, cat, uname, ps, netstat, history, exit\r\n")
            elif command.lower() == "ls":
                channel.send("  ".join(file_system.get(current_path, [])) + "\r\n")
            elif command.lower() == "pwd":
                channel.send(f"{current_path}\r\n")
            elif command.lower() == "whoami":
                channel.send(f"{current_user}\r\n")
            elif command.lower() == "uname -a":
                channel.send("Linux spaceX 5.4.0-73-generic #82-Ubuntu SMP x86_64 GNU/Linux\r\n")
            elif command.lower() == "ps":
                channel.send("PID TTY          TIME CMD\n 1234 pts/0    00:00:01 bash\n 1235 pts/0    00:00:00 ps\r\n")
            elif command.lower() == "netstat":
                channel.send("Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\r\n")
            elif command.startswith("cd"):
                parts = command.split()
                if len(parts) > 1:
                    new_path = parts[1]
                    if new_path == "..":
                        current_path = "/" if current_path.count("/") <= 1 else current_path.rsplit("/", 1)[0]
                    elif new_path in file_system.get(current_path, []):
                        current_path += f"/{new_path}"
                    else:
                        channel.send(f"bash: cd: {new_path}: No such file or directory\r\n")
                else:
                    channel.send("bash: cd: missing argument\r\n")
            elif command.startswith("cat"):
                parts = command.split()
                if len(parts) > 1:
                    file_to_cat = current_path + "/" + parts[1] if parts[1] in file_system.get(current_path, []) else parts[1]
                    if file_to_cat in fake_files:
                        channel.send(fake_files[file_to_cat])
                    else:
                        channel.send(f"bash: cat: {parts[1]}: No such file or directory\r\n")
            elif command.startswith("echo") and ">" in command:
                # Attacker attempting persistence by adding to authorized_keys
                parts = command.split(">")
                if len(parts) == 2 and ".ssh/authorized_keys" in parts[1]:
                    fake_files["/home/elonmusk/.ssh/authorized_keys"] += parts[0].replace("echo ", "").strip() + "\n"
                    logging.info(f"Persistence attempt: {client_ip} added key to authorized_keys")
                    channel.send("\r\n")
            elif command.lower() == "exit":
                channel.send("Goodbye!\r\n")
                break
            else:
                channel.send(f"bash: {command}: command not found\r\n")

        except Exception as e:
            logging.error(f"Channel error: {e}")
            break

    channel.close()

# SSH Server Handler
class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.client_address = None  # Initialize the client address

    def check_auth_password(self, username, password):
        client_ip = self.client_address[0]

        # Brute-force protection
        if username != ALLOWED_USERNAME or password != ALLOWED_PASSWORD:
            if not brute_force_tracker.record_failed_attempt(client_ip):
                return paramiko.AUTH_FAILED
            return paramiko.AUTH_FAILED

        # Successful login
        logging.info(f"Successful login from {client_ip} using {username}:{password}")
        brute_force_tracker.record_successful_attempt(client_ip)
        get_geolocation(client_ip)  # Get the attacker's location
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# Start SSH Honeypot Server
def start_ssh_honeypot():
    ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssh_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssh_socket.bind((HONEYPOT_HOST, HONEYPOT_PORT))
    ssh_socket.listen(100)

    logging.info(f"[*] SSH Honeypot (spaceX) running on port {HONEYPOT_PORT}...")

    while True:
        try:
            client_socket, client_addr = ssh_socket.accept()
            logging.info(f"Connection from {client_addr[0]}:{client_addr[1]}")

            transport = paramiko.Transport(client_socket)
            transport.add_server_key(HOST_KEY)

            server = SSHServer()
            server.client_address = client_addr  # Save client address

            transport.start_server(server=server)

            channel = transport.accept(20)
            if channel is None:
                logging.error("No channel.")
                continue

            logging.info("Authenticated successfully. Starting fake shell...")
            fake_shell(channel)

        except Exception as e:
            logging.error(f"Error in connection handling: {e}")
        finally:
            client_socket.close()

if __name__ == "__main__":
    start_ssh_honeypot()
