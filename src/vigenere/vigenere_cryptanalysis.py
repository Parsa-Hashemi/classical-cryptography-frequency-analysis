"""Vigenere cryptanalysis using IC, Kasiski, and frequency analysis."""

import math

from .vigenere_cipher import decrypt
from .vigenere_cipher import is_english_letter


# Approximate frequencies of A-Z in English.
ENGLISH_FREQUENCIES = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
    0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
    0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074
]

ENGLISH_IC = 0.0667
RANDOM_IC = 1.0 / 26.0

# These tables are used only to score how closely candidates resemble English.
COMMON_BIGRAMS = {
    "TH": 2.0, "HE": 2.0, "IN": 1.7, "ER": 1.7, "AN": 1.7,
    "RE": 1.6, "ON": 1.6, "AT": 1.6, "EN": 1.6, "ND": 1.5,
    "TI": 1.5, "ES": 1.5, "OR": 1.5, "TE": 1.4, "OF": 1.4,
    "ED": 1.4, "IS": 1.4, "IT": 1.4, "AL": 1.3, "AR": 1.3,
    "ST": 1.3, "TO": 1.3, "NT": 1.2, "NG": 1.2, "SE": 1.2,
    "HA": 1.2, "AS": 1.2, "OU": 1.2, "IO": 1.1, "LE": 1.1
}

COMMON_TRIGRAMS = {
    "THE": 4.5, "AND": 3.8, "ING": 3.5, "HER": 2.8, "ERE": 2.6,
    "ENT": 2.6, "THA": 2.5, "NTH": 2.4, "WAS": 2.4, "ETH": 2.3,
    "FOR": 2.3, "HES": 2.2, "VER": 2.1, "HIS": 2.1, "OFT": 2.1,
    "OTH": 2.0, "RES": 2.0, "ONT": 1.9, "REA": 1.9, "NOT": 1.9,
    "EST": 1.9, "TED": 1.8, "ERS": 1.8, "ATI": 1.8, "HAT": 1.8,
    "ALL": 1.7, "ITH": 1.7, "TIO": 1.7, "HEN": 1.7, "ION": 1.7
}

COMMON_WORDS = [
    "a", "about", "after", "all", "also", "an", "and", "any", "are",
    "as", "at", "be", "because", "been", "before", "between", "both",
    "but", "by", "can", "could", "data", "do", "each", "first", "for",
    "from", "good", "had", "has", "have", "he", "her", "his", "how",
    "if", "in", "into", "is", "it", "its", "key", "may", "message",
    "more", "most", "new", "no", "not", "of", "on", "one", "only",
    "or", "other", "our", "out", "over", "people", "same", "she",
    "should", "so", "some", "such", "system", "text", "than", "that",
    "the", "their", "them", "then", "there", "these", "they", "this",
    "time", "to", "two", "up", "use", "was", "way", "we", "well",
    "were", "what", "when", "which", "who", "will", "with", "would",
    "year", "you", "your"
]

UNLIKELY_BIGRAMS = ["JQ", "QG", "QK", "QY", "QZ", "WQ", "WZ", "ZQ", "ZX"]


def clean_ascii_letters(text):
    # Caps lock only the English alphabet

    letters = []

    for character in text:
        if is_english_letter(character):
            letters.append(character.upper())

    cleaned_text = "".join(letters)
    return cleaned_text


def count_characters(text):
    """Counts occurrences of each letter in a dictionary."""

    counts = {}

    for character in text:
        if character not in counts:
            counts[character] = 0

        counts[character] = counts[character] + 1

    return counts


def index_of_coincidence(text):
    """Calculates the index of coincidence for a text."""

    letters = clean_ascii_letters(text)
    number_of_letters = len(letters)

    if number_of_letters < 2:
        return 0.0

    counts = count_characters(letters)
    numerator = 0

    for character in counts:
        frequency = counts[character]
        numerator = numerator + frequency * (frequency - 1)

    denominator = number_of_letters * (number_of_letters - 1)
    result = numerator / denominator
    return result


def average_column_ic(ciphertext, key_length):

    if key_length < 1:
        raise ValueError("key_length must be positive")

    letters = clean_ascii_letters(ciphertext)
    columns = []

    for column_number in range(key_length):
        columns.append("")

    for index in range(len(letters)):
        column_number = index % key_length
        columns[column_number] = columns[column_number] + letters[index]

    total_ic = 0.0
    valid_column_count = 0

    for column in columns:
        if len(column) >= 2:
            total_ic = total_ic + index_of_coincidence(column)
            valid_column_count = valid_column_count + 1

    if valid_column_count == 0:
        return 0.0

    average = total_ic / valid_column_count
    return average


def kasiski_factor_counts(ciphertext, max_key_length):

    letters = clean_ascii_letters(ciphertext)
    factor_counts = {}

    for possible_length in range(1, max_key_length + 1):
        factor_counts[possible_length] = 0

    for ngram_size in [3, 4, 5]:
        positions = {}

        last_start = len(letters) - ngram_size
        for start in range(last_start + 1):
            ngram = letters[start:start + ngram_size]

            if ngram not in positions:
                positions[ngram] = []

            positions[ngram].append(start)

        for ngram in positions:
            ngram_positions = positions[ngram]

            if len(ngram_positions) >= 2:
                for index in range(len(ngram_positions) - 1):
                    left_position = ngram_positions[index]
                    right_position = ngram_positions[index + 1]
                    distance = right_position - left_position

                    for possible_length in range(2, max_key_length + 1):
                        if distance % possible_length == 0:
                            old_count = factor_counts[possible_length]
                            factor_counts[possible_length] = old_count + 1

    return factor_counts


def get_length_score(item):

    return item["combined_score"]


def rank_key_lengths(ciphertext, max_key_length=20):

    letters = clean_ascii_letters(ciphertext)

    if len(letters) < 2:
        raise ValueError("at least two English letters are required")

    if max_key_length < 1:
        raise ValueError("max_key_length must be positive")

    half_of_text_length = len(letters) // 2

    if half_of_text_length < 1:
        half_of_text_length = 1

    real_max = max_key_length
    if half_of_text_length < real_max:
        real_max = half_of_text_length

    kasiski_counts = kasiski_factor_counts(letters, real_max)

    maximum_kasiski_count = 0
    for length in kasiski_counts:
        if kasiski_counts[length] > maximum_kasiski_count:
            maximum_kasiski_count = kasiski_counts[length]

    scores = []

    for length in range(1, real_max + 1):
        average_ic = average_column_ic(letters, length)

        ic_distance = abs(average_ic - ENGLISH_IC)
        ic_range = ENGLISH_IC - RANDOM_IC
        ic_quality = 1.0 - ic_distance / ic_range

        if ic_quality < 0.0:
            ic_quality = 0.0

        if maximum_kasiski_count == 0:
            kasiski_quality = 0.0
        else:
            kasiski_quality = kasiski_counts[length] / maximum_kasiski_count

        complexity_penalty = 0.0025 * length
        combined_score = ic_quality + 0.35 * kasiski_quality - complexity_penalty

        information = {
            "length": length,
            "average_ic": average_ic,
            "ic_quality": ic_quality,
            "kasiski_hits": kasiski_counts[length],
            "combined_score": combined_score
        }
        scores.append(information)

    scores.sort(key=get_length_score, reverse=True)
    return scores


def chi_square_for_shift(column, shift):
    """Measures a column's frequency distance from standard English."""

    column_length = len(column)

    if column_length == 0:
        return float("inf")

    alphabet_counts = []
    for index in range(26):
        alphabet_counts.append(0)

    for ciphertext_character in column:
        ciphertext_number = ord(ciphertext_character) - ord("A")
        plaintext_number = (ciphertext_number - shift) % 26
        alphabet_counts[plaintext_number] = alphabet_counts[plaintext_number] + 1

    chi_square = 0.0

    for index in range(26):
        expected_count = column_length * ENGLISH_FREQUENCIES[index]
        difference = alphabet_counts[index] - expected_count
        chi_square = chi_square + difference * difference / expected_count

    return chi_square


def recover_key(ciphertext, key_length):
    """Breaks each column as a Caesar cipher when the key length is known."""

    letters = clean_ascii_letters(ciphertext)

    if key_length < 1:
        raise ValueError("key_length must be positive")

    if len(letters) < key_length:
        raise ValueError("ciphertext must contain at least key_length letters")

    key_characters = []

    for column_number in range(key_length):
        column = ""

        index = column_number
        while index < len(letters):
            column = column + letters[index]
            index = index + key_length

        best_shift = 0
        best_chi_square = chi_square_for_shift(column, 0)

        for shift in range(1, 26):
            current_chi_square = chi_square_for_shift(column, shift)

            if current_chi_square < best_chi_square:
                best_chi_square = current_chi_square
                best_shift = shift

        key_character = chr(ord("A") + best_shift)
        key_characters.append(key_character)

    key = "".join(key_characters)
    return key


def smaller_key(key):

    for period in range(1, len(key) + 1):
        if len(key) % period == 0:
            short_key = key[:period]
            repetition_count = len(key) // period
            repeated_key = short_key * repetition_count

            if repeated_key == key:
                return short_key

    return key


def extract_english_words(text):

    words = []
    current_word = ""

    for character in text.lower():
        if is_english_letter(character):
            current_word = current_word + character
        else:
            if len(current_word) > 0:
                words.append(current_word)
                current_word = ""

    if len(current_word) > 0:
        words.append(current_word)

    return words


def english_language_score(text):
    """Assigns higher scores to text that resembles English."""

    letters = clean_ascii_letters(text)

    if len(letters) == 0:
        return float("-inf")

    counts = count_characters(letters)
    monogram_score = 0.0

    for character in counts:
        frequency_index = ord(character) - ord("A")
        probability = ENGLISH_FREQUENCIES[frequency_index]
        character_count = counts[character]
        monogram_score = monogram_score + \
            character_count * math.log(probability)

    monogram_score = monogram_score / len(letters)

    bigram_score = 0.0
    for index in range(len(letters) - 1):
        bigram = letters[index:index + 2]
        if bigram in COMMON_BIGRAMS:
            bigram_score = bigram_score + COMMON_BIGRAMS[bigram]

    bigram_score = bigram_score / len(letters)-1

    trigram_score = 0.0
    for index in range(len(letters) - 2):
        trigram = letters[index:index + 3]
        if trigram in COMMON_TRIGRAMS:
            trigram_score = trigram_score + COMMON_TRIGRAMS[trigram]

    trigram_score = trigram_score / len(letters)-2

    unlikely_count = 0
    for index in range(len(letters) - 1):
        bigram = letters[index:index + 2]
        if bigram in UNLIKELY_BIGRAMS:
            unlikely_count = unlikely_count + 1

    unlikely_score = unlikely_count / len(letters)-1

    words = extract_english_words(text)
    recognized_word_count = 0

    for word in words:
        if word in COMMON_WORDS:
            recognized_word_count = recognized_word_count + 1

    if len(words) == 0:
        word_score = 0.0
    else:
        word_score = recognized_word_count / len(words)

    final_score = monogram_score
    final_score = final_score + 0.60 * bigram_score
    final_score = final_score + 1.25 * trigram_score
    final_score = final_score + 0.75 * word_score
    final_score = final_score - 2.0 * unlikely_score

    return final_score


def get_candidate_score(candidate):
    """Sorting helper for candidate results."""

    return candidate["language_score"]


def break_vigenere(ciphertext, max_key_length=20, candidate_lengths=None):
    """Estimates the key and plaintext without a supplied key."""

    ranking = rank_key_lengths(ciphertext, max_key_length)

    if candidate_lengths is None:
        ranking_to_test = ranking
    else:
        if candidate_lengths < 1:
            raise ValueError("candidate_lengths must be positive or None")
        ranking_to_test = ranking[:candidate_lengths]

    candidates = []
    seen_keys = []

    for length_information in ranking_to_test:
        tested_length = length_information["length"]
        recovered_key = recover_key(ciphertext, tested_length)
        recovered_key = smaller_key(recovered_key)

        if recovered_key not in seen_keys:
            recovered_plaintext = decrypt(ciphertext, recovered_key)
            score = english_language_score(recovered_plaintext)
            score = score - 0.001 * len(recovered_key)

            candidate = {
                "key": recovered_key,
                "tested_length": tested_length,
                "plaintext": recovered_plaintext,
                "language_score": score
            }

            candidates.append(candidate)
            seen_keys.append(recovered_key)

    candidates.sort(key=get_candidate_score, reverse=True)
    best_candidate = candidates[0]

    result = {
        "key": best_candidate["key"],
        "plaintext": best_candidate["plaintext"],
        "score": best_candidate["language_score"],
        "candidates": candidates,
        "key_length_ranking": ranking
    }

    return result
