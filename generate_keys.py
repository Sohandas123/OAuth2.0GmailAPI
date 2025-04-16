from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_and_save_keys(email):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Save private key (for recipient)
    with open(f"{email}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save public key (for database)
    with open(f"{email}_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Generated keys for {email}")



# Generate keys for both recipients
if __name__=='__main__':
    # generate_and_save_keys("weseecsc24@gmail.com")
    # generate_and_save_keys("sohanisical@gmail.com")
    generate_and_save_keys("poifghjkl44@gmail.com")