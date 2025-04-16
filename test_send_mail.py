import base64
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from database import Session, Recipient
from crypto import generate_aes_key, encrypt_aes, encrypt_rsa

def test_send_mail():
    test_data = {
        'to': 'sohanisical@gmail.com',
        'message': 'This is a secret test message'
    }

    db_session = Session()
    recipient = db_session.query(Recipient).filter_by(email=test_data['to']).first()
    if not recipient:
        print("Recipient not found!")
        return

    aes_key = generate_aes_key()
    iv, encrypted_data, tag = encrypt_aes(test_data['message'].encode(), aes_key)

    encrypted_aes_key = encrypt_rsa(aes_key, recipient.public_key)

    msg = MIMEMultipart()
    msg['To'] = test_data['to']
    msg['From'] = "weseecsc24@gmail.com" 
    msg['Subject'] = 'TEST - Encrypted Email'

    for data, filename in [
        (encrypted_data, 'encrypted.bin'),
        (encrypted_aes_key, 'key.bin'),
        (iv, 'iv.bin'),
        (tag, 'tag.bin')
    ]:
        part = MIMEApplication(data)
        part.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(part)

    print("✅ Test successful!")
    print(f"Original message: {test_data['message']}")
    print(f"AES Key: {aes_key.hex()}")
    print(f"Encrypted AES Key (hex): {encrypted_aes_key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Tag: {tag.hex()}")
    print("\nMIME Message Structure:")
    print(msg.as_string())

    

if __name__ == '__main__':
    test_send_mail()