from flask import Flask
from flask_mail import Mail, Message
from app.config import Config  # Adjusted import

app = Flask(__name__)
app.config.from_object(Config)

mail = Mail(app)

with app.app_context():
    msg = Message('Test Email', recipients=['1020037769@qq.com'])
    msg.body = 'This is a test email.'
    try:
        mail.send(msg)
        print('Email sent successfully!')
    except Exception as e:
        print(f'Failed to send email: {e}')
