def vigenere_encrypt(plaintext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key.upper()
    plaintext = plaintext.upper().replace(' ', '')
    key_repeated = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]

    ciphertext = ''
    for p_char, k_char in zip(plaintext, key_repeated):
        if p_char in alphabet:
            p_index = alphabet.index(p_char)
            k_index = alphabet.index(k_char)
            c_index = (p_index + k_index) % 26
            ciphertext += alphabet[c_index]
        else:
            ciphertext += p_char  # If character is not in alphabet, add it as is

    return ciphertext


def vigenere_decrypt(ciphertext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key.upper()
    ciphertext = ciphertext.upper().replace(' ', '')
    key_repeated = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]

    plaintext = ''
    for c_char, k_char in zip(ciphertext, key_repeated):
        if c_char in alphabet:
            c_index = alphabet.index(c_char)
            k_index = alphabet.index(k_char)
            p_index = (c_index - k_index) % 26
            plaintext += alphabet[p_index]
        else:
            plaintext += c_char  # If character is not in alphabet, add it as is

    return plaintext


# Key for the Vigenère cipher
key = "dollars"

# Message to encrypt
message = "the house is being sold tonight"
message = message.replace(' ', '')  # Remove spaces

# Encrypt the message
encrypted_message = vigenere_encrypt(message, key)
print(f'Encrypted message: {encrypted_message}')

# Decrypt the message
decrypted_message = vigenere_decrypt(encrypted_message, key)
print(f'Decrypted message: {decrypted_message}')
