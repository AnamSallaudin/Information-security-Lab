def autokey_encrypt(plaintext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = chr((key % 26) + ord('A'))  # Convert numeric key to a single letter
    plaintext = plaintext.upper().replace(' ', '')
    key_repeated = key + plaintext  # Start with the key and append plaintext

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


def autokey_decrypt(ciphertext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = chr((key % 26) + ord('A'))  # Convert numeric key to a single letter
    ciphertext = ciphertext.upper().replace(' ', '')
    key_repeated = key  # Start with the key

    plaintext = ''
    for c_char in ciphertext:
        if c_char in alphabet:
            c_index = alphabet.index(c_char)
            k_index = alphabet.index(key_repeated[0])  # Use the first letter of key_repeated
            p_index = (c_index - k_index) % 26
            plaintext += alphabet[p_index]
            key_repeated += alphabet[p_index]  # Append the decrypted character to key_repeated
        else:
            plaintext += c_char  # If character is not in alphabet, add it as is

    return plaintext


# Key for the Autokey cipher
key = 7

# Message to encrypt
message = "the house is being sold tonight"
message = message.replace(' ', '')  # Remove spaces

# Encrypt the message
encrypted_message = autokey_encrypt(message, key)
print(f'Encrypted message: {encrypted_message}')

# Decrypt the message
decrypted_message = autokey_decrypt(encrypted_message, key)
print(f'Decrypted message: {decrypted_message}')
