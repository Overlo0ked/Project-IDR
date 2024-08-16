import socket
import time
import logging
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

class CustomFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_server_ip = '192.168.1.101'  # Replace with the actual IP of VM2
        self.log_server_port = 5005  # The port on which VM2 is listening

    def send_attack_attempt(self, attack_type, filename=None):
        # Prepare the message
        message = f"Attack Attempt: {attack_type}, "
        if filename:
            message += f"File: {filename}, "
        message += f"IP: {self.remote_address}"
        
        # Send the message to VM2
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.log_server_ip, self.log_server_port))
                s.sendall(message.encode())
            except Exception as e:
                print(f"Failed to send message to VM2: {e}")

    def ftp_LOGIN(self, username, password):
        # Log login attempts
        logging.info(f"Login Attempt: User: {username}, IP: {self.remote_address}")
        self.send_attack_attempt("LOGIN", username)
        super().ftp_LOGIN(username, password)

    def ftp_RETR(self, filename):
        # Simulate file retrieval
        if filename in self.authorizer.get_user(self.username).file_list:
            self.send_response("150 Opening data connection for " + filename)
            time.sleep(1)  # Simulate file transfer delay
            self.send_response("226 Transfer complete.")
            logging.info(f"IP: {self.remote_address} - RETR: {filename}")
            self.send_attack_attempt("RETR", filename)  # Log file retrieval attempt
        else:
            self.send_response("550 File not found.")
            self.send_attack_attempt("RETR FAILED", filename)  # Log failed retrieval

    def ftp_STOR(self, filename):
        # Simulate file upload
        self.send_response("150 Opening data connection for " + filename)
        time.sleep(1)  # Simulate file upload delay
        self.send_response("226 Transfer complete.")
        logging.info(f"IP: {self.remote_address} - STOR: {filename}")
        self.send_attack_attempt("STOR", filename)  # Log file upload attempt

def run_honeypot():
    # Set up logging
    logging.basicConfig(filename='ftp_honeypot.log', level=logging.INFO)

    # Set up the authorizer
    authorizer = DummyAuthorizer()
    authorizer.add_user("user", "12345", "/srv/ftp", perm="elradfmwMT")
    authorizer.add_anonymous("/srv/ftp")

    # Set up the handler
    handler = CustomFTPHandler
    handler.authorizer = authorizer

    # Create and start the server
    server = FTPServer(("192.168.1.101", 21), handler)
    server.serve_forever()

if __name__ == "__main__":
    run_honeypot()
