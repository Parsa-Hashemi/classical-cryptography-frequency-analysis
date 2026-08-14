"""Text cleaning, key generation, encryption, and decryption."""

import random
import string


ENGLISH_ALPHABET = string.ascii_lowercase
PERSIAN_ALPHABET = "ابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"


def normalize_persian_text(text):
    """Merge Arabic/Persian variants used by the project's 32-letter alphabet."""

    text = text.replace("ك", "ک").replace("ي", "ی")
    return text.replace("آ", "ا").replace("أ", "ا").replace("إ", "ا")


def clean_text_en(text):
    """Convert English text to lowercase and keep only A-Z letters."""

    text = text.lower()
    allowed_chars = set(ENGLISH_ALPHABET)
    cleaned = "".join([char for char in text if char in allowed_chars])
    return cleaned


def clean_text_fa(text):
    """Standardize Arabic forms and keep only Persian alphabet letters."""

    allowed_chars = set(PERSIAN_ALPHABET)
    text = normalize_persian_text(text)
    cleaned = "".join([char for char in text if char in allowed_chars])
    return cleaned


def get_alphabet(language="en"):
    """Return the alphabet used by the selected language."""

    if language == "en":
        return ENGLISH_ALPHABET

    if language == "fa":
        return PERSIAN_ALPHABET

    raise ValueError("language must be 'en' or 'fa'")


def generate_random_key(language="en", random_generator=None):
    """Generate a random monoalphabetic substitution mapping."""

    alphabet = list(get_alphabet(language))
    shuffled_alphabet = alphabet.copy()

    if random_generator is None:
        random.shuffle(shuffled_alphabet)
    else:
        random_generator.shuffle(shuffled_alphabet)

    key = {}
    for index in range(len(alphabet)):
        key[alphabet[index]] = shuffled_alphabet[index]

    return key


def encrypt_substitution(plaintext, key, is_persian=False):
    """Encrypt letters while preserving case and every non-letter position."""

    encrypted_characters = []

    for character in plaintext:
        if is_persian:
            normalized_character = normalize_persian_text(character)
            encrypted_character = key.get(
                normalized_character,
                character
            )
        else:
            lowercase_character = character.lower()

            if lowercase_character in key:
                encrypted_character = key[lowercase_character]

                if character.isupper():
                    encrypted_character = encrypted_character.upper()
            else:
                encrypted_character = character

        encrypted_characters.append(encrypted_character)

    return "".join(encrypted_characters)


def decrypt_substitution(ciphertext, key):
    """Decrypt letters while preserving case and every non-letter position."""

    reverse_key = {value: character for character, value in key.items()}
    decrypted_characters = []

    for character in ciphertext:
        lowercase_character = character.lower()

        if lowercase_character in reverse_key:
            decrypted_character = reverse_key[lowercase_character]

            if character.isupper():
                decrypted_character = decrypted_character.upper()
        else:
            normalized_character = normalize_persian_text(character)
            decrypted_character = reverse_key.get(
                normalized_character,
                character
            )

        decrypted_characters.append(decrypted_character)

    return "".join(decrypted_characters)


def key_from_string(key_text, language="en"):
    """Convert an alphabet permutation string into the dictionary key format."""

    alphabet = get_alphabet(language)
    normalized_key = key_text.lower() if language == "en" else key_text

    if len(normalized_key) != len(alphabet):
        raise ValueError(
            "key must contain exactly " + str(len(alphabet)) + " letters"
        )

    if set(normalized_key) != set(alphabet):
        raise ValueError("key must be a permutation of the selected alphabet")

    key = {}
    for index in range(len(alphabet)):
        key[alphabet[index]] = normalized_key[index]

    return key


def key_to_string(key, language="en"):
    """Write a dictionary substitution key as one alphabet permutation string."""

    alphabet = get_alphabet(language)
    characters = []

    for character in alphabet:
        if character not in key:
            raise ValueError("key does not contain every alphabet letter")
        characters.append(key[character])

    key_text = "".join(characters)

    if set(key_text) != set(alphabet):
        raise ValueError("key values must be a permutation of the alphabet")

    return key_text
