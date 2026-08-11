"""Tests for the Caesar cipher core and statistical functions."""

import math

import pytest

from src.analysis import (
    chi_square,
    crack_caesar,
    index_of_coincidence,
    letter_counts,
    ngram_counts,
    shannon_entropy,
)
from src.caesar import brute_force, decrypt, encrypt, normalize_key


def test_basic_encryption_and_decryption() -> None:
    assert encrypt("ABC", 3) == "DEF"
    assert decrypt("DEF", 3) == "ABC"


def test_wrap_around() -> None:
    assert encrypt("XYZ", 3) == "ABC"
    assert decrypt("ABC", 3) == "XYZ"


def test_case_spaces_numbers_and_punctuation_are_preserved() -> None:
    assert encrypt("Hello, World! 123", 3) == "Khoor, Zruog! 123"
    assert decrypt("Khoor, Zruog! 123", 3) == "Hello, World! 123"


@pytest.mark.parametrize("key", [0, 26, 52, -26, 29, -3])
def test_round_trip_for_normalized_keys(key: int) -> None:
    text = "The quick brown fox jumps over the lazy dog."
    assert decrypt(encrypt(text, key), key) == text


def test_key_validation() -> None:
    assert normalize_key(29) == 3
    assert normalize_key(-3) == 23
    with pytest.raises(TypeError):
        normalize_key(3.0)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        normalize_key(True)  # type: ignore[arg-type]


def test_brute_force_generates_all_keys() -> None:
    candidates = brute_force("Khoor Zruog!")
    assert len(candidates) == 26
    assert candidates[3] == (3, "Hello World!")


def test_chi_square_finds_key_on_repeated_english_text() -> None:
    plaintext = ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 12).strip()
    ciphertext = encrypt(plaintext, 7)
    result = crack_caesar(ciphertext)
    assert result["key"] == 7
    assert result["plaintext"] == plaintext


def test_frequency_and_ngrams() -> None:
    assert letter_counts("Aa! B2") == {
        "A": 2,
        "B": 1,
        **{letter: 0 for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ"},
    }
    assert ngram_counts("The THE", 2)["TH"] == 2
    assert ngram_counts("The THE", 3)["THE"] == 2


def test_empty_statistics_are_safe() -> None:
    assert index_of_coincidence("") == 0.0
    assert shannon_entropy("") == 0.0
    assert math.isinf(chi_square(""))
