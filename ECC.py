import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# Derive the public key
public_key = private_key.public_key()

# Generate a second ECC private key for demonstration (another party)
private_key_b = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key_b = private_key_b.public_key()

# Derive a shared secret using the public key of the other party
shared_secret = private_key.exchange(ec.ECDH(), public_key_b)

# Derive a symmetric key from the shared secret
kdf = Scrypt(
    salt=os.urandom(16),
    length=32,
    n=2**14,
    r=8,
    p=1,
    backend=default_backend()
)

key = kdf.derive(shared_secret)

# Encrypt the message "Secure Transactions"
def encrypt_message(key, message):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the message to be a multiple of the block size
    padding_length = 16 - len(message) % 16
    padded_message = message + (chr(padding_length) * padding_length)

    ciphertext = encryptor.update(padded_message.encode('utf-8')) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Encrypt the message
message = "Secure Transactions"
encrypted_message = encrypt_message(key, message)

print("Encrypted Message:", encrypted_message)

# Decrypt the message
def decrypt_message(key, encrypted_message):
    data = base64.b64decode(encrypted_message)
    iv = data[:16]  # Extract the IV
    ciphertext = data[16:]  # Extract the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = decrypted_padded[-1]
    return decrypted_padded[:-padding_length].decode('utf-8')

# Decrypt the message
decrypted_message = decrypt_message(key, encrypted_message)

print("Decrypted Message:", decrypted_message)
