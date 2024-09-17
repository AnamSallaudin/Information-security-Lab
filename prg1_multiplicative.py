def modular_inverse(a, m):
    # Compute the modular inverse of a under modulo m using Extended Euclidean Algorithm
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


def encrypt_multiplicative(plaintext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key % 26  # Ensure key is within 0-25
    ciphertext = ''

    for char in plaintext.upper():
        if char in alphabet:
            pos = alphabet.index(char)
            new_pos = (key * pos) % 26
            ciphertext += alphabet[new_pos]
        else:
            ciphertext += char

    return ciphertext


def decrypt_multiplicative(ciphertext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key % 26  # Ensure key is within 0-25
    inverse_key = modular_inverse(key, 26)
    plaintext = ''

    for char in ciphertext.upper():
        if char in alphabet:
            pos = alphabet.index(char)
            new_pos = (inverse_key * pos) % 26
            plaintext += alphabet[new_pos]
        else:
            plaintext += char

    return plaintext


# Key for the multiplicative cipher
key = 15

# Message to encrypt
message = "I am learning information security"
message = message.replace(' ', '')  # Remove spaces

# Encrypt the message
encrypted_message = encrypt_multiplicative(message, key)
print(f'Encrypted message: {encrypted_message}')

# Decrypt the message
decrypted_message = decrypt_multiplicative(encrypted_message, key)
print(f'Decrypted message: {decrypted_message}')
