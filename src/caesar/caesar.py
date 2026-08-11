"""Caesar cipher implementation.

This module contains only the core Caesar cipher operations. English letters
are shifted, while spaces, numbers, punctuation, and non-English characters
remain unchanged.
"""

from __future__ import annotations

import string


ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = len(ALPHABET)


def normalize_key(key: int) -> int:
    """Validate the key and normalize it to the range 0 through 25."""

    if isinstance(key, bool) or not isinstance(key, int):
        raise TypeError("key must be an integer")
    return key % ALPHABET_SIZE


def _shift_character(character: str, key: int) -> str:
    """Shift an English letter and leave all other characters unchanged."""

    if "A" <= character <= "Z":
        index = (ord(character) - ord("A") + key) % ALPHABET_SIZE
        return chr(ord("A") + index)
    if "a" <= character <= "z":
        index = (ord(character) - ord("a") + key) % ALPHABET_SIZE
        return chr(ord("a") + index)
    return character


def encrypt(text: str, key: int) -> str:
    """Encrypt text with a Caesar key.

    Keys greater than 26 and negative keys are supported modulo 26.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    normalized_key = normalize_key(key)
    return "".join(_shift_character(character, normalized_key) for character in text)


def decrypt(text: str, key: int) -> str:
    """Decrypt Caesar ciphertext with a known key."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    normalized_key = normalize_key(key)
    return "".join(_shift_character(character, -normalized_key) for character in text)


def brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """Return all 26 decryptions as ``(key, plaintext)`` pairs.

    Each returned key is the key tested for decryption. For example, the
    result for ``Khoor`` contains ``Hello`` at key 3.
    """

    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a string")
    return [(key, decrypt(ciphertext, key)) for key in range(ALPHABET_SIZE)]
