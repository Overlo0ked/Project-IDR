import smtplib
from email.mime.text import MIMEText

from twilio.rest import Client

def send_sms(message, from_addr, to_addr, account_sid, auth_token):
    client = Client(account_sid, auth_token)
    client.messages.create(
        body=message,
        from_=from_addr,
        to=to_addr
    )

message = "Hello, this is a test SMS!"
from_addr = "+12564725887"
to_addr = "+918590477437"
account_sid = "AC32c0d23405b7f5a0d2619ff299638e7b"
auth_token = "7cca590db6985eb8b04f912e7568f8e2"

message = input("Enter the message:")

send_sms(message, from_addr, to_addr, account_sid, auth_token)

print("THE MESSAGE HAS BEEN SENT SUCCESFULLY!!")
