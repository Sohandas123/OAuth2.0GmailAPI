from database import Session, Recipient

session = Session()
recipients = session.query(Recipient).all()

for recipient in recipients:
    print(f"Email: {recipient.email}")
    print(f"Public Key (first 50 chars): {recipient.public_key[:50]}...\n")