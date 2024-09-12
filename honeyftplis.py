import socket
import datetime

# Listening configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 8889       # Port for receiving logs from the honeypot

def start_monitor():
    # Set up a UDP socket to receive logs
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))

    print(f"[*] Monitoring system listening on port {PORT}...")

    while True:
        log_message, addr = server.recvfrom(1024)  # Set buffer size to 1024 bytes
        # Get the current timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Print the log with a timestamp and sender address
        print(f"[{timestamp}] [LOG] From {addr}: {log_message.decode()}")

if __name__ == "__main__":
    start_monitor() 
