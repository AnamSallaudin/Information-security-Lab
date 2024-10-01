import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Generate Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Generate private keys for both parties
private_key_a = parameters.generate_private_key()
private_key_b = parameters.generate_private_key()

# Generate public keys for both parties
public_key_a = private_key_a.public_key()
public_key_b = private_key_b.public_key()

# Exchange public keys and compute shared secrets
shared_secret_a = private_key_a.exchange(public_key_b)
shared_secret_b = private_key_b.exchange(public_key_a)

# Ensure both parties have the same shared secret
assert shared_secret_a == shared_secret_b

# Derive a symmetric key from the shared secret
salt = os.urandom(16)  # Generate a random salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # Length of the derived key
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

key = kdf.derive(shared_secret_a)

# Encrypt the message "Hello"
def encrypt_message(key, message):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be multiple of block size
    padding_length = 16 - len(message) % 16
    padded_message = message + (chr(padding_length) * padding_length)
    
    ciphertext = encryptor.update(padded_message.encode('utf-8')) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Encrypt the message
message = "Hello"
encrypted_message = encrypt_message(key, message)

print("Encrypted Message:", encrypted_message)
