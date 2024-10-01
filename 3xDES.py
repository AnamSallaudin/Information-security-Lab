from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64

# Triple DES key must be 24 bytes long
key = b'1234567890ABCDEF1234567890ABCDEF'
key = key[:24]  # Ensure the key is 24 bytes

# Message to encrypt
message = "Classified Text"
message_bytes = message.encode('utf-8')

# Create a Triple DES cipher object
cipher = DES3.new(key, DES3.MODE_CBC)

# Encrypt the message
iv = cipher.iv
ciphertext = cipher.encrypt(pad(message_bytes, DES3.block_size))

# Encode the IV and ciphertext for storage or transmission
encoded_iv = base64.b64encode(iv).decode('utf-8')
encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')

# Print the results
print("IV:", encoded_iv)
print("Ciphertext:", encoded_ciphertext)

# Decrypt the message
# Create a new cipher object for decryption
cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
decrypted = unpad(cipher_decrypt.decrypt(ciphertext), DES3.block_size)

# Convert decrypted bytes back to string
decrypted_message = decrypted.decode('utf-8')

# Print the decrypted message
print("Decrypted message:", decrypted_message)
