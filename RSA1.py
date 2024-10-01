Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, e). Then 
decrypt the ciphertext with the private key (n, d) to verify the original message.

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Print keys (for demonstration purposes, usually you wouldn't do this)
print("Private Key:")
print(private_key.decode())
print("\nPublic Key:")
print(public_key.decode())

# Encrypt the message
message = "Asymmetric Encryption"
cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
ciphertext = cipher.encrypt(message.encode('utf-8'))

# Encode the ciphertext for storage or transmission
encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
print("\nCiphertext (Base64 Encoded):", encoded_ciphertext)

# Decrypt the message
cipher_decrypt = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted = cipher_decrypt.decrypt(base64.b64decode(encoded_ciphertext))

# Convert decrypted bytes back to string
decrypted_message = decrypted.decode('utf-8')
print("\nDecrypted message:", decrypted_message)
