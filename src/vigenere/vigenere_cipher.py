
def is_english_letter(character):

    if "A" <= character <= "Z":
        return True

    if "a" <= character <= "z":
        return True

    return False


def validate_key(key):

    if not isinstance(key, str):
        raise TypeError("key must be a string")

    if len(key) == 0:
        raise ValueError("key must not be empty")

    for character in key:
        if not is_english_letter(character):
            raise ValueError("key must contain only English letters A-Z")

    key = key.upper()
    return key


def encrypt(plaintext, key):

    key = validate_key(key)
    encrypted_characters = []
    key_index = 0

    for character in plaintext:
        if is_english_letter(character):
            if "A" <= character <= "Z":
                alphabet_a = ord("A")
            else:
                alphabet_a = ord("a")

            plaintext_number = ord(character) - alphabet_a

            current_key_character = key[key_index % len(key)]
            key_number = ord(current_key_character) - ord("A")

            encrypted_number = (plaintext_number + key_number) % 26
            encrypted_character = chr(alphabet_a + encrypted_number)
            encrypted_characters.append(encrypted_character)

            key_index = key_index + 1
        else:
            # spaces and other characters exist as same as they were
            encrypted_characters.append(character)

    ciphertext = "".join(encrypted_characters)
    return ciphertext


def decrypt(ciphertext, key):

    key = validate_key(key)
    decrypted_characters = []
    key_index = 0

    for character in ciphertext:
        if is_english_letter(character):
            if "A" <= character <= "Z":
                alphabet_a = ord("A")
            else:
                alphabet_a = ord("a")

            ciphertext_number = ord(character) - alphabet_a

            current_key_character = key[key_index % len(key)]
            key_number = ord(current_key_character) - ord("A")

            decrypted_number = (ciphertext_number - key_number) % 26
            decrypted_character = chr(alphabet_a + decrypted_number)
            decrypted_characters.append(decrypted_character)

            key_index = key_index + 1
        else:
            decrypted_characters.append(character)

    plaintext = "".join(decrypted_characters)
    return plaintext
