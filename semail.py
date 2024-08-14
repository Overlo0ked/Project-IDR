import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, message, from_addr, to_addr, password):
    try:
        # Create the email
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject

        # Attach the message
        msg.attach(MIMEText(message, 'plain'))

        # Set up the server
        server = smtplib.SMTP('smtp.gmail.com', 587)  # Use Gmail's SMTP server
        server.starttls()  # Start TLS for security
        server.login(from_addr, password)  # Log in using the email and password

        # Send the email
        server.send_message(msg)
        print("Email sent successfully!")
        
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()  # Close the SMTP server connection

# Example usage
subject = "Test Email"
message = "This is a test email sent from Python."
from_addr = "demouservictim@gmail.com"  # Replace with your email
to_addr = "mysticraganork66@gmail.com"  # Replace with recipient's email
password = "llzq mxfq ygde kden"  # Use your email password or app-specific password

send_email(subject, message, from_addr, to_addr, password)
