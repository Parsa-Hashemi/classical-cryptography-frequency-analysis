"""Small utility functions used by the project."""


def is_english_letter(character):
    """Returns True when the character is one of A-Z or a-z."""

    if "A" <= character <= "Z":
        return True

    if "a" <= character <= "z":
        return True

    return False


def clean_ascii_letters(text):
    """Keeps only English letters and converts them to uppercase."""

    letters = []

    for character in text:
        if is_english_letter(character):
            letters.append(character.upper())

    return "".join(letters)
