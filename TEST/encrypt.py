# Test this in Python shell
from werkzeug.datastructures import FileStorage
from io import BytesIO
from crypto import generate_aes_key, encrypt_file

# Create a test file
test_data = b"This is a test file"
test_file = FileStorage(stream=BytesIO(test_data), filename="test.txt")

# Test encryption
key = generate_aes_key()
encrypted = encrypt_file(test_file, "test.txt", key)
print(f"FileStorage: {encrypted['original_name']}")
print(f"IV: {len(encrypted['iv'])} bytes: {encrypted['iv']}")
print(f"Data: {len(encrypted['data'])} bytes: {encrypted['data']}")
print(f"Tag: {len(encrypted['tag'])} bytes: {encrypted['tag']}")