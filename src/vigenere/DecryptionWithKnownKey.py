def vigenere_decrypt(ciphertext, keyword):
    plaintext = []
    keyword = keyword.upper()
    keyword_index = 0

    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                ascii_offset = ord('A')
            else:
                ascii_offset = ord('a')

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
