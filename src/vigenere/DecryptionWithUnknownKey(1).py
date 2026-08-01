from collections import Counter


def calculate_ioc(text):
    letters = []
    for char in text:
        if char.isalpha():
            letters.append(char.upper())

    n = len(letters)
    if n <= 1:
        return 0.0

    # Gives a dictionary like : {'A':2,'B':3,...}
    counts = Counter(letters)

    numerator = 0
    for count in counts.values():
        numerator += count * (count - 1)

    denominator = n * (n - 1)

    return numerator / denominator


def find_key_length(ciphertext):
    best_len = 1
    best_ioc = 0.0

    max_length = len(ciphertext) // 2

    if max_length < 1:
        max_length = 1

    for length in range(1, max_length + 1):

        columns = []
        for i in range(length):
            columns.append("")

        index = 0
        for char in ciphertext:
            if char.isalpha():
                col_index = index % length
                columns[col_index] = columns[col_index] + char
                index += 1

        total_ioc = 0
        valid_columns_count = 0

        for col in columns:
            if len(col) > 1:
                ioc_value = calculate_ioc(col)
                total_ioc += ioc_value
                valid_columns_count += 1

        if valid_columns_count > 0:
            avg_ioc = total_ioc / valid_columns_count
        else:
            avg_ioc = 0.0

        if avg_ioc > best_ioc:
            best_ioc = avg_ioc
            best_len = length

    return best_len


def decrypt_vigenere(ciphertext, keyword):
    plaintext = []
    keyword = keyword.upper()
    keyword_index = 0

    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            c_val = ord(char) - ascii_offset

            k_char = keyword[keyword_index % len(keyword)]
            k_val = ord(k_char) - ord('A')

            p_val = (c_val - k_val + 26) % 26
            decrypted_char = chr(p_val + ascii_offset)

            plaintext.append(decrypted_char)
            keyword_index += 1
        else:
            plaintext.append(char)

    return "".join(plaintext)
