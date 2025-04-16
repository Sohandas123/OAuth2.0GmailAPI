from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_aes_key():
    return os.urandom(32)  # AES-256

def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return iv, encrypted, encryptor.tag

def decrypt_aes(iv, encrypted, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

def encrypt_rsa(plaintext, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(ciphertext, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# def encrypt_file(file_data, filename, aes_key):
#     """Encrypt file data using AES and return encrypted components with filename"""
#     iv, encrypted_data, tag = encrypt_aes(file_data, aes_key)
#     return {
#         'iv': iv,
#         'data': encrypted_data,
#         'tag': tag,
#         'original_name': filename
#     }

def encrypt_file(file_storage, filename, aes_key):
    """Encrypt file data using AES and return encrypted components"""
    try:
        # Ensure we're at the start of the file
        file_storage.seek(0)
        
        # Read the file data
        file_data = file_storage.read()
        
        # Verify we got data
        if not file_data:
            logger.warning(f"Empty file: {filename}")
            raise ValueError("Empty file content")
            
        # Encrypt the data
        iv, encrypted_data, tag = encrypt_aes(file_data, aes_key)
        
        return {
            'iv': iv,
            'data': encrypted_data,
            'tag': tag,
            'original_name': filename
        }
    except Exception as e:
        logger.error(f"Failed to encrypt {filename}: {str(e)}")
        raise

def decrypt_file(iv, encrypted_data, tag, aes_key, original_filename):
    """Decrypt file and return original file data"""
    decrypted_data = decrypt_aes(iv, encrypted_data, tag, aes_key)
    return {
        'data': decrypted_data,
        'filename': original_filename
    }