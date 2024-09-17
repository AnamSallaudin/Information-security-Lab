def encrypt_additive(plaintext, key):
    # Define the alphabet
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    # Convert plaintext to uppercase and remove spaces
    plaintext = plaintext.replace(' ', '').upper()

    # Encrypt each letter
    ciphertext = ''
    for char in plaintext:
        if char in alphabet:
            # Find the position in the alphabet
            pos = alphabet.index(char)
            # Shift position by key
            new_pos = (pos + key) % 26
            # Append the corresponding letter
            ciphertext += alphabet[new_pos]
        else:
            # If character is not in alphabet (like punctuation), append it as-is
            ciphertext += char

    return ciphertext


def decrypt_additive(ciphertext, key):
    # Define the alphabet
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    # Decrypt each letter
    plaintext = ''
    for char in ciphertext:
        if char in alphabet:
            # Find the position in the alphabet
            pos = alphabet.index(char)
            # Shift position back by key
            new_pos = (pos - key) % 26
            # Append the corresponding letter
            plaintext += alphabet[new_pos]
        else:
            # If character is not in alphabet (like punctuation), append it as-is
            plaintext += char

    return plaintext


# Key for the additive cipher
key = 20

# Message to encrypt
message = "I am learning information security"

# Encrypt the message
encrypted_message = encrypt_additive(message, key)
print(f'Encrypted message: {encrypted_message}')

# Decrypt the message
decrypted_message = decrypt_additive(encrypted_message, key)
print(f'Decrypted message: {decrypted_message}')

