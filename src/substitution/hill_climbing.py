"""Break a substitution cipher with the Hill Climbing algorithm."""

import random

from .substitution_cipher import ENGLISH_ALPHABET
from .substitution_cipher import PERSIAN_ALPHABET
from .substitution_cipher import clean_text_en
from .substitution_cipher import clean_text_fa
from .substitution_cryptanalysis import STD_ENGLISH_FREQ
from .substitution_cryptanalysis import STD_PERSIAN_FREQ
from .substitution_cryptanalysis import apply_deduced_key
from .substitution_cryptanalysis import build_ngram_language_model
from .substitution_cryptanalysis import complete_frequency_key
from .substitution_cryptanalysis import score_with_ngrams
from .substitution_cryptanalysis import swap_key_values


def hill_climbing_attack(
    ciphertext,
    reference_text,
    is_persian=False,
    iterations=3000,
    restarts=3,
    seed=1405,
    reference_freq=None
):
    """Return guessed plaintext and key using simple Hill Climbing.

    ``reference_text`` should be a normal text in the same language as the
    ciphertext.  The key returned by this function maps cipher letters to
    plaintext letters.
    """

    if iterations < 1:
        raise ValueError("iterations must be positive")
    if restarts < 1:
        raise ValueError("restarts must be positive")

    if is_persian:
        alphabet = PERSIAN_ALPHABET
        cleaned_ciphertext = clean_text_fa(ciphertext)
        default_frequency = STD_PERSIAN_FREQ
    else:
        alphabet = ENGLISH_ALPHABET
        cleaned_ciphertext = clean_text_en(ciphertext)
        default_frequency = STD_ENGLISH_FREQ

    if reference_freq is None:
        reference_freq = default_frequency

    language_model = build_ngram_language_model(reference_text, is_persian)
    starting_key = complete_frequency_key(
        ciphertext,
        reference_freq,
        is_persian
    )

    def key_score(key):
        guessed_text = "".join(key[char] for char in cleaned_ciphertext)
        return score_with_ngrams(guessed_text, language_model)

    random_generator = random.Random(seed)
    best_key = starting_key.copy()
    best_score = key_score(best_key)

    for restart in range(restarts):
        current_key = starting_key.copy()

        # Each restart begins near the frequency-analysis key.
        for unused_index in range(restart * 2):
            first, second = random_generator.sample(alphabet, 2)
            current_key = swap_key_values(current_key, first, second)

        current_score = key_score(current_key)

        for unused_iteration in range(iterations):
            first, second = random_generator.sample(alphabet, 2)
            candidate_key = swap_key_values(current_key, first, second)
            candidate_score = key_score(candidate_key)

            # Hill Climbing only moves to a better neighbor.
            if candidate_score > current_score:
                current_key = candidate_key
                current_score = candidate_score

                if current_score > best_score:
                    best_key = current_key.copy()
                    best_score = current_score

    plaintext = apply_deduced_key(ciphertext, best_key, is_persian)
    return plaintext, best_key
