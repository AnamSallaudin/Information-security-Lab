def generate_playfair_matrix(key):
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # 'J' is omitted
    key = key.upper().replace('J', 'I')  # Replace 'J' with 'I' for consistency
    matrix = []
    used_chars = set()

    # Create the matrix with the key
    for char in key:
        if char not in used_chars and char in alphabet:
            matrix.append(char)
            used_chars.add(char)

    # Fill the rest of the matrix with remaining letters of the alphabet
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = text.upper().replace('J', 'I').replace(' ', '')
    prepared = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if (i + 1) < len(text) else 'X'
        if a == b:
            prepared.append((a, 'X'))
            i += 1
        else:
            prepared.append((a, b))
            i += 2
    return prepared


def find_position(matrix, char):
    for row in range(5):
        if char in matrix[row]:
            return row, matrix[row].index(char)
    return None


def encrypt_playfair_digraph(matrix, digraph):
    row1, col1 = find_position(matrix, digraph[0])
    row2, col2 = find_position(matrix, digraph[1])

    if row1 == row2:
        # Same row: shift columns
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        # Same column: shift rows
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    else:
        # Rectangle: swap columns
        return matrix[row1][col2] + matrix[row2][col1]


def playfair_encrypt(text, key):
    matrix = generate_playfair_matrix(key)
    digraphs = prepare_text(text)
    ciphertext = ''.join(encrypt_playfair_digraph(matrix, digraph) for digraph in digraphs)
    return ciphertext


# Key and message
key = "GUIDANCE"
message = "The key is hidden under the door pad"

# Encrypt the message
encrypted_message = playfair_encrypt(message, key)
print(f'Encrypted message: {encrypted_message}')
