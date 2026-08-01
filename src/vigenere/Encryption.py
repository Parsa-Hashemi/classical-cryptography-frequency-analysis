def vigenere_encrypt(plain_text, keyword):
    ciphertext = []
    keyword = keyword.upper()
    keyword_index = 0

    for char in plain_text:
        if char.isalpha():
            if char.isupper():
                ascii_offset = ord('A')
            else:
                ascii_offset = ord('a')
            p_val = ord(char) - ascii_offset

            k_char = keyword[keyword_index % len(keyword)]
            k_val = ord(k_char) - ord('A')

            c_val = (p_val + k_val) % 26
            encrypted_char = chr(c_val + ascii_offset)

            ciphertext.append(encrypted_char)
            keyword_index += 1
        else:
            ciphertext.append(char)

    return "".join(ciphertext)
