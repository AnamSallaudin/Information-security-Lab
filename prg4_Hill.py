import numpy as np


def matrix_mod_inv(matrix, mod):
    det = int(round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, mod)  # Modular inverse of determinant
    matrix_mod = matrix % mod
    matrix_inv = det_inv * np.round(det * np.linalg.inv(matrix_mod)).astype(int) % mod
    return matrix_inv


def hill_cipher_encrypt(message, key_matrix):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    message = message.upper().replace(' ', '').replace('J', 'I')  # Replace 'J' with 'I'

    # Convert message to numeric format
    message_nums = [alphabet.index(char) for char in message]

    # Pad message if necessary
    while len(message_nums) % 2 != 0:
        message_nums.append(alphabet.index('X'))  # Padding character

    # Convert message numbers into a matrix
    message_matrix = np.array(message_nums).reshape(-1, 2)

    # Encrypt the message
    encrypted_nums = []
    for block in message_matrix:
        encrypted_block = np.dot(key_matrix, block) % 26
        encrypted_nums.extend(encrypted_block)

    # Convert encrypted numbers back to letters
    encrypted_message = ''.join(alphabet[num] for num in encrypted_nums)

    return encrypted_message


def hill_cipher_decrypt(encrypted_message, key_matrix):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encrypted_message = encrypted_message.upper().replace(' ', '').replace('J', 'I')  # Replace 'J' with 'I'

    # Convert encrypted message to numeric format
    encrypted_nums = [alphabet.index(char) for char in encrypted_message]

    # Convert encrypted numbers into a matrix
    encrypted_matrix = np.array(encrypted_nums).reshape(-1, 2)

    # Find the inverse key matrix
    key_matrix_inv = matrix_mod_inv(key_matrix, 26)

    # Decrypt the message
    decrypted_nums = []
    for block in encrypted_matrix:
        decrypted_block = np.dot(key_matrix_inv, block) % 26
        decrypted_nums.extend(decrypted_block)

    # Convert decrypted numbers back to letters
    decrypted_message = ''.join(alphabet[num] for num in decrypted_nums)

    return decrypted_message


# Key matrix
key_matrix = np.array([
    [3, 3],
    [2, 7]
])

# Message to encrypt
message = "We live in an insecure world"

# Encrypt the message
encrypted_message = hill_cipher_encrypt(message, key_matrix)
print(f'Encrypted message: {encrypted_message}')

# Decrypt the message
decrypted_message = hill_cipher_decrypt(encrypted_message, key_matrix)
print(f'Decrypted message: {decrypted_message}')
