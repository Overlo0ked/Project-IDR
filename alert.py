import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client

# Twilio settings
message = "Hello, this is a test SMS!"
from_addr = "+12564725887"
to_addr = "+918590477437"
account_sid = "AC32c0d23405b7f5a0d2619ff299638e7b"
auth_token = "7cca590db6985eb8b04f912e7568f8e2"

# Email settings
subject = "Test Email"
fromaddr = "demouservictim@gmail.com"
toaddr = "mysticraganork66@gmail.com"
password = "llzq mxfq ygde kden"

def send_sms(message, from_addr, to_addr, account_sid, auth_token):
    client = Client(account_sid, auth_token)
    client.messages.create(
        body=message,
        from_=from_addr,
        to=to_addr
    )
    print("THE MESSAGE HAS BEEN SENT SUCCESFULLY!!")

def send_email(subject, mssg, fromaddr, toaddr, password):
    try:
        msg = MIMEMultipart()
        msg['From'] = fromaddr
        msg['To'] = toaddr
        msg['Subject'] = subject
        msg.attach(MIMEText(mssg, 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(fromaddr, password)
        server.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()

print("Alert System")
print("")
print("")
print("0.BOTH")
print("1.SMS")
print("2.EMAIL")
ch = int(input("ENTER 1 / 2 / 0 :-->"))

if(ch == 0):
    mssg = input("Enter the email message:")
    send_email(subject, mssg, fromaddr, toaddr, password)
    message = input("Enter the SMS message:")
    send_sms(message, from_addr, to_addr, account_sid, auth_token)
elif(ch == 1):
    message = input("Enter the SMS message:")
    send_sms(message, from_addr, to_addr, account_sid, auth_token)
elif(ch == 2):
    mssg = input("Enter the email message:")
    send_email(subject, mssg, fromaddr, toaddr, password)
else:
    print("INVALID ARGUMENT!!")
