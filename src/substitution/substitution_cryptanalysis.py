"""Frequency and n-gram attacks for a monoalphabetic substitution cipher."""

import math
import random

from .substitution_cipher import ENGLISH_ALPHABET
from .substitution_cipher import PERSIAN_ALPHABET
from .substitution_cipher import clean_text_en
from .substitution_cipher import clean_text_fa
from .substitution_cipher import normalize_persian_text
from .text_statistics import calculate_frequencies
from .text_statistics import ngram_counts


STD_ENGLISH_FREQ = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97,
    "n": 6.75, "s": 6.33, "h": 6.09, "r": 5.99, "d": 4.25,
    "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41, "w": 2.36,
    "f": 2.23, "g": 2.02, "y": 1.97, "p": 1.93, "b": 1.29,
    "v": 0.98, "k": 0.77, "j": 0.15, "x": 0.15, "q": 0.10,
    "z": 0.07
}


# Counts from 10% of the 2015 Persian Wikipedia dump. The count of آ is
# merged into ا because this project uses the standard 32-letter alphabet.
# Source: github.com/jadijadi/persianlettercount
PERSIAN_WIKIPEDIA_COUNTS = {
    "ا": 4101513, "ی": 2915877, "ر": 2525170, "د": 1861543,
    "ن": 1831045, "ه": 1638034, "و": 1606199, "م": 1541968,
    "ت": 1510602, "ب": 1191550, "س": 1129394, "ل": 729613,
    "ک": 728996, "ش": 692128, "ز": 551658, "ع": 392996,
    "ف": 372662, "گ": 348562, "خ": 291213, "ق": 287271,
    "ج": 287223, "ح": 211581, "پ": 210176, "غ": 174189,
    "ط": 142536, "ص": 140904, "چ": 92149, "ث": 59821,
    "ض": 57585, "ذ": 50086, "ظ": 38914, "ژ": 34366
}

persian_total = sum(PERSIAN_WIKIPEDIA_COUNTS.values())
STD_PERSIAN_FREQ = {}
for character in PERSIAN_WIKIPEDIA_COUNTS:
    count = PERSIAN_WIKIPEDIA_COUNTS[character]
    STD_PERSIAN_FREQ[character] = (count / persian_total) * 100


def apply_deduced_key(ciphertext, deduced_key, is_persian=False):
    """Apply a guessed key without losing case, spaces, or punctuation."""

    plaintext_characters = []

    for character in ciphertext:
        if is_persian:
            normalized_character = normalize_persian_text(character)

            if normalized_character in PERSIAN_ALPHABET:
                plaintext_character = deduced_key.get(normalized_character, "?")
            else:
                plaintext_character = character
        else:
            lowercase_character = character.lower()

            if lowercase_character in ENGLISH_ALPHABET:
                plaintext_character = deduced_key.get(lowercase_character, "?")

                if character.isupper():
                    plaintext_character = plaintext_character.upper()
            else:
                plaintext_character = character

        plaintext_characters.append(plaintext_character)

    return "".join(plaintext_characters)


def build_ngram_language_model(training_text, is_persian=False, smoothing=0.05):
    """Build logarithmic bigram and trigram probabilities from reference text."""

    if is_persian:
        cleaned_training_text = clean_text_fa(training_text)
        alphabet_size = len(PERSIAN_ALPHABET)
    else:
        cleaned_training_text = clean_text_en(training_text)
        alphabet_size = len(ENGLISH_ALPHABET)

    if len(cleaned_training_text) < 100:
        raise ValueError("n-gram reference corpus must contain at least 100 letters")

    model = {}

    for size in [2, 3]:
        counts = ngram_counts(training_text, size, is_persian)
        total = sum(counts.values())
        denominator = total + smoothing * (alphabet_size ** size)
        log_probabilities = {}

        for ngram in counts:
            probability = (counts[ngram] + smoothing) / denominator
            log_probabilities[ngram] = math.log(probability)

        floor_probability = smoothing / denominator
        model[size] = {
            "log_probabilities": log_probabilities,
            "floor_log_probability": math.log(floor_probability)
        }

    return model


def score_with_ngrams(cleaned_text, language_model):
    """Score a candidate plaintext using reference bigrams and trigrams."""

    score = 0.0

    for size in [2, 3]:
        information = language_model[size]
        probabilities = information["log_probabilities"]
        floor = information["floor_log_probability"]
        weight = 1.0 if size == 2 else 1.35

        for start in range(len(cleaned_text) - size + 1):
            ngram = cleaned_text[start:start + size]
            score = score + weight * probabilities.get(ngram, floor)

    return score


def complete_frequency_key(ciphertext, reference_freq, is_persian=False):
    """Create a complete cipher-to-plaintext key from frequency ranks."""

    if is_persian:
        alphabet = PERSIAN_ALPHABET
        cleaned_cipher = clean_text_fa(ciphertext)
    else:
        alphabet = ENGLISH_ALPHABET
        cleaned_cipher = clean_text_en(ciphertext)

    if len(reference_freq) < len(alphabet):
        raise ValueError("reference frequency must contain the complete alphabet")

    counts = {}
    for character in alphabet:
        counts[character] = 0

    for character in cleaned_cipher:
        counts[character] = counts[character] + 1

    cipher_characters = list(alphabet)
    cipher_characters.sort(key=lambda character: counts[character], reverse=True)
    reference_characters = list(reference_freq.keys())
    key = {}

    for index in range(len(alphabet)):
        key[cipher_characters[index]] = reference_characters[index]

    return key


def decrypt_cleaned_text(cleaned_ciphertext, decryption_key):
    """Quickly apply a complete cipher-to-plaintext key to cleaned text."""

    return "".join([
        decryption_key[character]
        for character in cleaned_ciphertext
    ])


def swap_key_values(key, first_character, second_character):
    """Return a neighboring key by swapping two plaintext assignments."""

    candidate = key.copy()
    candidate[first_character], candidate[second_character] = (
        candidate[second_character],
        candidate[first_character]
    )
    return candidate


def score_cipher_ngrams(cipher_ngram_counts, decryption_key, language_model):
    """Score a key directly from unique ciphertext n-grams and their counts."""

    score = 0.0

    for size in [2, 3]:
        information = language_model[size]
        probabilities = information["log_probabilities"]
        floor = information["floor_log_probability"]
        weight = 1.0 if size == 2 else 1.35

        for cipher_ngram in cipher_ngram_counts[size]:
            plain_ngram = "".join([
                decryption_key[character]
                for character in cipher_ngram
            ])
            ngram_score = probabilities.get(plain_ngram, floor)
            count = cipher_ngram_counts[size][cipher_ngram]
            score = score + weight * count * ngram_score

    return score


def affected_ngram_items(cipher_ngram_counts, alphabet):
    """Index the ciphertext n-grams affected by swapping each key entry."""

    affected = {}
    for character in alphabet:
        affected[character] = set()

    for size in [2, 3]:
        for cipher_ngram in cipher_ngram_counts[size]:
            for character in set(cipher_ngram):
                affected[character].add((size, cipher_ngram))

    return affected


def score_selected_ngrams(
    selected_items,
    cipher_ngram_counts,
    decryption_key,
    language_model
):
    """Score only n-grams changed by one proposed key swap."""

    score = 0.0

    for size, cipher_ngram in selected_items:
        information = language_model[size]
        probabilities = information["log_probabilities"]
        floor = information["floor_log_probability"]
        weight = 1.0 if size == 2 else 1.35
        plain_ngram = "".join([
            decryption_key[character]
            for character in cipher_ngram
        ])
        count = cipher_ngram_counts[size][cipher_ngram]
        score = score + weight * count * probabilities.get(plain_ngram, floor)

    return score


def refine_key_with_ngrams(
    ciphertext,
    starting_key,
    language_model,
    is_persian=False,
    restarts=3,
    iterations=2000,
    seed=1405
):
    """Improve a frequency key by scoring swapped keys with n-grams."""

    if restarts < 1:
        raise ValueError("ngram restarts must be positive")

    if iterations < 1:
        raise ValueError("ngram iterations must be positive")

    if is_persian:
        alphabet = PERSIAN_ALPHABET
        cleaned_ciphertext = clean_text_fa(ciphertext)
    else:
        alphabet = ENGLISH_ALPHABET
        cleaned_ciphertext = clean_text_en(ciphertext)

    if len(cleaned_ciphertext) < 3:
        return starting_key, float("-inf")

    random_generator = random.Random(seed)
    global_best_key = starting_key.copy()
    cipher_ngram_counts = {
        2: ngram_counts(cleaned_ciphertext, 2, is_persian),
        3: ngram_counts(cleaned_ciphertext, 3, is_persian)
    }
    affected = affected_ngram_items(cipher_ngram_counts, alphabet)
    global_best_score = score_cipher_ngrams(
        cipher_ngram_counts,
        global_best_key,
        language_model
    )

    for restart in range(restarts):
        current_key = starting_key.copy()
        perturbations = 2 + 2 * restart

        for unused_index in range(perturbations):
            first_character = random_generator.choice(alphabet)
            second_character = random_generator.choice(alphabet)
            current_key = swap_key_values(
                current_key,
                first_character,
                second_character
            )

        current_score = score_cipher_ngrams(
            cipher_ngram_counts,
            current_key,
            language_model
        )

        for iteration in range(iterations):
            first_character = random_generator.choice(alphabet)
            second_character = random_generator.choice(alphabet)

            if first_character == second_character:
                continue

            candidate_key = swap_key_values(
                current_key,
                first_character,
                second_character
            )
            selected_items = (
                affected[first_character]
                | affected[second_character]
            )
            old_partial_score = score_selected_ngrams(
                selected_items,
                cipher_ngram_counts,
                current_key,
                language_model
            )
            new_partial_score = score_selected_ngrams(
                selected_items,
                cipher_ngram_counts,
                candidate_key,
                language_model
            )
            difference = new_partial_score - old_partial_score
            candidate_score = current_score + difference
            progress = iteration / iterations
            temperature = 18.0 * (0.01 ** progress)
            accept = difference >= 0.0

            if not accept:
                probability = math.exp(difference / temperature)
                if random_generator.random() < probability:
                    accept = True

            if accept:
                current_key = candidate_key
                current_score = candidate_score

            if current_score > global_best_score:
                global_best_key = current_key.copy()
                global_best_score = current_score

    return global_best_key, global_best_score


def break_substitution_freq(
    ciphertext,
    reference_freq,
    is_persian=False,
    ngram_reference_text=None,
    ngram_model=None,
    ngram_restarts=3,
    ngram_iterations=2000,
    seed=1405
):
    """Guess plaintext with frequency ranks and optional n-gram refinement."""

    if is_persian:
        cleaned_cipher = clean_text_fa(ciphertext)
    else:
        cleaned_cipher = clean_text_en(ciphertext)

    cipher_freq, unused_cleaned_text = calculate_frequencies(
        cleaned_cipher,
        is_persian=is_persian
    )
    sorted_cipher_chars = list(cipher_freq.keys())
    sorted_ref_chars = list(reference_freq.keys())
    deduced_key = {}

    limit = min(len(sorted_cipher_chars), len(sorted_ref_chars))
    for index in range(limit):
        cipher_char = sorted_cipher_chars[index]
        expected_char = sorted_ref_chars[index]
        deduced_key[cipher_char] = expected_char

    if ngram_model is None and ngram_reference_text is not None:
        ngram_model = build_ngram_language_model(
            ngram_reference_text,
            is_persian
        )

    if ngram_model is not None:
        complete_key = complete_frequency_key(
            ciphertext,
            reference_freq,
            is_persian
        )
        deduced_key, unused_ngram_score = refine_key_with_ngrams(
            ciphertext,
            complete_key,
            ngram_model,
            is_persian,
            ngram_restarts,
            ngram_iterations,
            seed
        )

    guessed_plaintext = apply_deduced_key(
        ciphertext,
        deduced_key,
        is_persian
    )
    return guessed_plaintext, deduced_key


def calculate_accuracy(original_text, guessed_text):
    """Calculate character-level recovery accuracy as a percentage."""

    if len(original_text) == 0:
        return 0.0

    correct_matches = sum(
        1
        for original, guessed in zip(original_text, guessed_text)
        if original == guessed
    )
    accuracy = (correct_matches / len(original_text)) * 100
    return accuracy
