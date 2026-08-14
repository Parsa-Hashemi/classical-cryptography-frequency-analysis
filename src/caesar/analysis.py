"""Statistical text analysis for simple Caesar cryptanalysis.

Chi-Square is the primary key-selection method in this project. N-gram
analysis, the index of coincidence, and Shannon entropy are also calculated
for experiments and reports, but IC alone cannot identify a Caesar key.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

try:
    from .caesar import ALPHABET, brute_force
except ImportError:  # pragma: no cover - supports direct execution from src.
    from caesar import ALPHABET, brute_force


# Approximate English letter frequencies expressed as proportions.
ENGLISH_FREQUENCIES: dict[str, float] = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02288,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}


COMMON_BIGRAMS: dict[str, float] = {
    "TH": 1.00,
    "HE": 0.95,
    "IN": 0.90,
    "ER": 0.88,
    "AN": 0.86,
    "RE": 0.84,
    "ON": 0.82,
    "AT": 0.80,
    "EN": 0.78,
    "ND": 0.76,
    "TI": 0.74,
    "ES": 0.72,
    "OR": 0.70,
    "TE": 0.68,
    "OF": 0.66,
    "ED": 0.64,
    "IS": 0.62,
    "IT": 0.60,
    "AL": 0.58,
    "AR": 0.56,
}


COMMON_TRIGRAMS: dict[str, float] = {
    "THE": 1.00,
    "AND": 0.96,
    "ING": 0.92,
    "HER": 0.88,
    "ERE": 0.84,
    "ENT": 0.80,
    "THA": 0.76,
    "NTH": 0.72,
    "WAS": 0.68,
    "ETH": 0.64,
    "FOR": 0.60,
    "DTH": 0.56,
    "HES": 0.52,
    "VER": 0.48,
    "TER": 0.44,
}


def clean_letters(text: str) -> str:
    """Return only English letters, converted to uppercase."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return "".join(character for character in text.upper() if character in ALPHABET)


def letter_counts(text: str) -> dict[str, int]:
    """Return occurrence counts for every letter from A through Z."""

    counts = {letter: 0 for letter in ALPHABET}
    for letter in clean_letters(text):
        counts[letter] += 1
    return counts


def letter_frequencies(text: str) -> dict[str, float]:
    """Return relative letter frequencies, summing to 1 for nonempty text."""

    counts = letter_counts(text)
    total = sum(counts.values())
    if total == 0:
        return {letter: 0.0 for letter in ALPHABET}
    return {letter: counts[letter] / total for letter in ALPHABET}


def frequency_rows(text: str) -> list[dict[str, float | int | str]]:
    """Produce rows ready for printing or saving to CSV."""

    counts = letter_counts(text)
    frequencies = letter_frequencies(text)
    return [
        {
            "letter": letter,
            "count": counts[letter],
            "frequency": frequencies[letter],
            "percentage": frequencies[letter] * 100,
        }
        for letter in ALPHABET
    ]


def frequency_distance(text: str) -> float:
    """Calculate the L1 distance from the standard English distribution."""

    frequencies = letter_frequencies(text)
    return sum(
        abs(frequencies[letter] - ENGLISH_FREQUENCIES[letter]) for letter in ALPHABET
    )


def chi_square(text: str, expected: dict[str, float] | None = None) -> float:
    """Calculate a Chi-Square score; lower values are better."""

    expected = expected or ENGLISH_FREQUENCIES
    counts = letter_counts(text)
    total = sum(counts.values())
    if total == 0:
        return float("inf")

    score = 0.0
    for letter in ALPHABET:
        expected_count = total * expected[letter]
        if expected_count > 0:
            score += (counts[letter] - expected_count) ** 2 / expected_count
    return score


def chi_square_scores(ciphertext: str) -> list[dict[str, int | float | str]]:
    """Generate plaintext and Chi-Square score data for every key."""

    return [
        {"key": key, "plaintext": plaintext, "score": chi_square(plaintext)}
        for key, plaintext in brute_force(ciphertext)
    ]


def crack_caesar(ciphertext: str) -> dict[str, int | float | str]:
    """Select the most likely key by minimizing the Chi-Square score."""

    scores = chi_square_scores(ciphertext)
    best = min(scores, key=lambda item: float(item["score"]))
    return {
        "key": int(best["key"]),
        "plaintext": str(best["plaintext"]),
        "score": float(best["score"]),
        "method": "chi-square",
    }


def ngram_counts(text: str, n: int) -> dict[str, int]:
    """Count text n-grams after removing spaces and punctuation."""

    if not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive integer")
    letters = clean_letters(text)
    return dict(Counter(letters[index : index + n] for index in range(len(letters) - n + 1)))


def common_ngram_score(text: str, n: int) -> float:
    """Calculate a simple score based on common n-grams."""

    if n == 2:
        weights = COMMON_BIGRAMS
    elif n == 3:
        weights = COMMON_TRIGRAMS
    else:
        raise ValueError("only bigrams and trigrams are supported")

    counts = ngram_counts(text, n)
    total = max(sum(counts.values()), 1)
    return sum(counts.get(gram, 0) * weight for gram, weight in weights.items()) / total


def ngram_score(text: str) -> float:
    """Return a small combined score for comparing brute-force outputs."""

    return 0.35 * common_ngram_score(text, 2) + 0.65 * common_ngram_score(text, 3)


def ngram_scores(ciphertext: str) -> list[dict[str, int | float | str]]:
    """Generate an n-gram score for every key."""

    return [
        {"key": key, "plaintext": plaintext, "score": ngram_score(plaintext)}
        for key, plaintext in brute_force(ciphertext)
    ]


def crack_by_ngram(ciphertext: str) -> dict[str, int | float | str]:
    """Select the key whose plaintext has the strongest common n-grams."""

    scores = ngram_scores(ciphertext)
    best = max(scores, key=lambda item: float(item["score"]))
    return {
        "key": int(best["key"]),
        "plaintext": str(best["plaintext"]),
        "score": float(best["score"]),
        "method": "ngram",
    }


def index_of_coincidence(text: str) -> float:
    """Calculate the index of coincidence using the standard formula."""

    counts = letter_counts(text)
    total = sum(counts.values())
    if total < 2:
        return 0.0
    numerator = sum(count * (count - 1) for count in counts.values())
    return numerator / (total * (total - 1))


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of the letter distribution in bits."""

    frequencies = letter_frequencies(text)
    return -sum(
        probability * math.log2(probability)
        for probability in frequencies.values()
        if probability > 0
    )


def compare_statistics(plaintext: str, ciphertext: str) -> dict[str, float]:
    """Compare IC and entropy for plaintext and ciphertext."""

    return {
        "plaintext_ic": index_of_coincidence(plaintext),
        "ciphertext_ic": index_of_coincidence(ciphertext),
        "plaintext_entropy": shannon_entropy(plaintext),
        "ciphertext_entropy": shannon_entropy(ciphertext),
    }


def summarize_statistics(text: str) -> dict[str, float | int]:
    """Produce a statistical summary suitable for CLI output."""

    return {
        "letter_count": len(clean_letters(text)),
        "index_of_coincidence": index_of_coincidence(text),
        "shannon_entropy": shannon_entropy(text),
        "frequency_distance": frequency_distance(text),
        "chi_square": chi_square(text),
    }
