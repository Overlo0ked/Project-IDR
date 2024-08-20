import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
import socket

# Twilio settings
TWILIO_FROM_ADDR = "+12564725887"
TWILIO_TO_ADDR = "+918590477437"
TWILIO_ACCOUNT_SID = "AC32c0d23405b7f5a0d2619ff299638e7b"
TWILIO_AUTH_TOKEN = "548bd82d44199791ae64bc4ddb935da8"

# Email settings
EMAIL_SUBJECT = "FTP Honeypot Alert"
EMAIL_FROM_ADDR = "demouservictim@gmail.com"
EMAIL_TO_ADDR = "mysticragan66@gmail.com"
EMAIL_PASSWORD = "llzq mxfq ygde kden"

# Alert functions
def send_sms(message):
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    client.messages.create(
        body=message,
        from_=TWILIO_FROM_ADDR,
        to=TWILIO_TO_ADDR
    )
    print("SMS alert sent successfully!")

def send_email(message):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM_ADDR
        msg['To'] = EMAIL_TO_ADDR
        msg['Subject'] = EMAIL_SUBJECT
        msg.attach(MIMEText(message, 'plain'))  # Fixed the class name to MIMEText
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_FROM_ADDR, EMAIL_PASSWORD)
        server.send_message(msg)
        print("Email alert sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()

# Listening configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 8888       # Port for receiving logs from the honeypot

def start_alert_system():
    # Set up a UDP socket to receive logs
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Fixed the assignment operator
    server.bind((HOST, PORT))

    print(f"[*] Alert system listening on port {PORT}...")

    while True:
        log_message, addr = server.recvfrom(1024)  # Buffer size is 1024 bytes
        message = log_message.decode()
        print(f"[ALERT] From {addr}: {message}")
        send_sms(message)
        send_email(message)

if __name__ == "__main__":
    start_alert_system()
