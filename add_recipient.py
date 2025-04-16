from database import Session, Recipient

def add_recipient(email, public_key_path):
    with open(public_key_path, "r") as f:
        public_key = f.read()
    session = Session()
    recipient = Recipient(email=email, public_key=public_key)
    session.add(recipient)
    session.commit()
    print(f"Added {email} to database")
    

# Add both recipients
if __name__=='__main__':
    pass
    # add_recipient("weseecsc24@gmail.com", "weseecsc24@gmail.com_public.pem")
    # add_recipient("sohanisical@gmail.com", "sohanisical@gmail.com_public.pem")