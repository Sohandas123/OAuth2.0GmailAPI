import base64
from crypto import decrypt_rsa, decrypt_aes
from cryptography.hazmat.primitives import serialization

# Load recipient's private key (keep this secure!)
with open('private_key.pem', 'r') as f:
    private_key_pem = f.read()

# Assume encrypted_aes_key, iv, tag, encrypted_data are extracted from email
encrypted_aes_key = ...  # From key.bin
iv = ...                 # From iv.bin
tag = ...                # From tag.bin
encrypted_data = ...     # From encrypted.bin

# Decrypt AES key
aes_key = decrypt_rsa(encrypted_aes_key, private_key_pem)

# Decrypt data
decrypted_data = decrypt_aes(iv, encrypted_data, tag, aes_key)
print(decrypted_data.decode())