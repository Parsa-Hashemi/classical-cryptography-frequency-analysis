"""Letter, bigram, and trigram frequency calculations."""

import json
import math
import os
import csv

from .vigenere_cryptanalysis import clean_ascii_letters
from .vigenere_cryptanalysis import index_of_coincidence


def ngram_counts(text, size):
    """Counts repeated sequences of the requested size."""

    if size < 1:
        raise ValueError("ngram size must be positive")

    letters = clean_ascii_letters(text)
    counts = {}
    last_start = len(letters) - size

    for start in range(last_start + 1):
        ngram = letters[start:start + size]

        if ngram not in counts:
            counts[ngram] = 0

        counts[ngram] = counts[ngram] + 1

    return counts


def get_count_from_pair(pair):
    """Returns the count from an (item, count) pair for sorting."""

    return pair[1]


def sort_counts_from_high_to_low(counts):
    """Sorts a count dictionary from highest to lowest count."""

    items = []

    for item in counts:
        pair = (item, counts[item])
        items.append(pair)

    items.sort(key=get_count_from_pair, reverse=True)
    return items


def relative_frequencies(counts):
    """Calculates each item's relative frequency."""

    total = 0

    for item in counts:
        total = total + counts[item]

    frequencies = {}

    if total == 0:
        return frequencies

    sorted_items = sort_counts_from_high_to_low(counts)

    for pair in sorted_items:
        item = pair[0]
        count = pair[1]
        frequency = count / total
        frequencies[item] = frequency

    return frequencies


def shannon_entropy(text):
    """Calculates Shannon entropy for the letters in a text."""

    counts = ngram_counts(text, 1)
    total = 0

    for character in counts:
        total = total + counts[character]

    if total == 0:
        return 0.0

    entropy = 0.0

    for character in counts:
        probability = counts[character] / total
        entropy = entropy - probability * math.log2(probability)

    return entropy


def compare_shannon_entropies(plaintext, ciphertext):
    """Compares the letter entropy of plaintext and ciphertext."""

    plaintext_letters = clean_ascii_letters(plaintext)
    ciphertext_letters = clean_ascii_letters(ciphertext)
    plaintext_entropy = shannon_entropy(plaintext_letters)
    ciphertext_entropy = shannon_entropy(ciphertext_letters)
    maximum_entropy = math.log2(26)

    report = {
        "plaintext": {
            "letter_count": len(plaintext_letters),
            "entropy_bits_per_letter": plaintext_entropy,
            "percent_of_maximum": 100 * plaintext_entropy / maximum_entropy
        },
        "ciphertext": {
            "letter_count": len(ciphertext_letters),
            "entropy_bits_per_letter": ciphertext_entropy,
            "percent_of_maximum": 100 * ciphertext_entropy / maximum_entropy
        },
        "maximum_entropy_bits_per_letter": maximum_entropy,
        "entropy_difference_bits_per_letter": (
            ciphertext_entropy - plaintext_entropy
        )
    }

    return report


def save_entropy_comparison(report, output_path):
    """Saves an entropy comparison report as a UTF-8 JSON file."""

    output_directory = os.path.dirname(output_path)

    if len(output_directory) > 0:
        os.makedirs(output_directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, ensure_ascii=False, indent=2)

    return output_path


def compare_cipher_entropies(plaintext, ciphertexts):
    """Compares plaintext entropy with multiple ciphertext results."""

    maximum_entropy = math.log2(26)
    plain_letters = clean_ascii_letters(plaintext)
    report = {
        "maximum_entropy_bits_per_letter": maximum_entropy,
        "plaintext": {
            "letter_count": len(plain_letters),
            "entropy_bits_per_letter": shannon_entropy(plain_letters)
        },
        "ciphers": {}
    }

    for cipher_name in ciphertexts:
        cipher_letters = clean_ascii_letters(ciphertexts[cipher_name])
        cipher_entropy = shannon_entropy(cipher_letters)
        report["ciphers"][cipher_name] = {
            "letter_count": len(cipher_letters),
            "entropy_bits_per_letter": cipher_entropy,
            "difference_from_plaintext": (
                cipher_entropy
                - report["plaintext"]["entropy_bits_per_letter"]
            )
        }

    return report


def save_cipher_entropy_report(report, output_dir):
    """Saves a multi-cipher report as JSON, CSV, and a PNG chart."""

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "cipher_entropy_comparison.json")
    csv_path = os.path.join(output_dir, "cipher_entropy_comparison.csv")
    png_path = os.path.join(output_dir, "cipher_entropy_comparison.png")

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, ensure_ascii=False, indent=2)

    labels = ["plaintext"]
    entropies = [report["plaintext"]["entropy_bits_per_letter"]]

    for cipher_name in report["ciphers"]:
        labels.append(cipher_name)
        entropies.append(
            report["ciphers"][cipher_name]["entropy_bits_per_letter"]
        )

    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["text", "entropy_bits_per_letter"])

        for index in range(len(labels)):
            writer.writerow([labels[index], entropies[index]])

    figure, axis = plt.subplots(figsize=(9, 5), constrained_layout=True)
    colors = ["#315b7d", "#cb6d51", "#5a9367", "#8b6fb3"]
    bars = axis.bar(labels, entropies, color=colors[:len(labels)])
    axis.axhline(
        report["maximum_entropy_bits_per_letter"],
        color="#333333",
        linestyle="--",
        label="Maximum log2(26)"
    )
    axis.set_ylabel("Entropy (bits per English letter)")
    axis.set_title("Shannon letter entropy: plaintext and classical ciphers")
    axis.set_ylim(0, report["maximum_entropy_bits_per_letter"] + 0.35)
    axis.grid(axis="y", alpha=0.25)
    axis.legend()

    for index in range(len(bars)):
        bar = bars[index]
        value = entropies[index]
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.04,
            str(round(value, 3)),
            ha="center"
        )

    figure.savefig(png_path, dpi=180)
    plt.close(figure)

    return json_path, csv_path, png_path


def counts_as_sorted_dictionary(counts):
    """Returns a new dictionary with the most frequent items first."""

    sorted_items = sort_counts_from_high_to_low(counts)
    result = {}

    for pair in sorted_items:
        item = pair[0]
        count = pair[1]
        result[item] = count

    return result


def analyze_text(text):
    """Collects all report statistics in one dictionary."""

    letters = clean_ascii_letters(text)
    letter_counts = ngram_counts(letters, 1)
    bigram_counts = ngram_counts(letters, 2)
    trigram_counts = ngram_counts(letters, 3)

    report = {
        "letter_count": len(letters),
        "index_of_coincidence": index_of_coincidence(letters),
        "shannon_entropy_bits_per_letter": shannon_entropy(letters),
        "letters": {
            "counts": counts_as_sorted_dictionary(letter_counts),
            "relative_frequencies": relative_frequencies(letter_counts)
        },
        "bigrams": {
            "counts": counts_as_sorted_dictionary(bigram_counts),
            "relative_frequencies": relative_frequencies(bigram_counts)
        },
        "trigrams": {
            "counts": counts_as_sorted_dictionary(trigram_counts),
            "relative_frequencies": relative_frequencies(trigram_counts)
        }
    }

    return report


def plot_counts(axis, counts, title, limit=None):
    """Draws a bar chart on the supplied axis."""

    items = sort_counts_from_high_to_low(counts)

    if limit is not None:
        items = items[:limit]

    labels = []
    values = []

    for pair in items:
        labels.append(pair[0])
        values.append(pair[1])

    axis.bar(labels, values, color="#315b7d")
    axis.set_title(title)
    axis.set_ylabel("Count")
    axis.grid(axis="y", alpha=0.25)
    axis.tick_params(axis="x", rotation=45)


def create_analysis_report(text, output_dir, label="text"):
    """Saves the JSON report and frequency-chart image."""

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    os.makedirs(output_dir, exist_ok=True)

    safe_label_characters = []
    for character in label:
        if character.isalnum() or character == "-" or character == "_":
            safe_label_characters.append(character)
        else:
            safe_label_characters.append("_")

    safe_label = "".join(safe_label_characters)
    json_filename = safe_label + "_statistics.json"
    png_filename = safe_label + "_frequencies.png"
    json_path = os.path.join(output_dir, json_filename)
    png_path = os.path.join(output_dir, png_filename)

    report = analyze_text(text)

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, ensure_ascii=False, indent=2)

    figure, axes = plt.subplots(3, 1, figsize=(12, 13), constrained_layout=True)
    plot_counts(axes[0], ngram_counts(text, 1), "Letter frequencies")
    plot_counts(axes[1], ngram_counts(text, 2), "20 most frequent bigrams", 20)
    plot_counts(axes[2], ngram_counts(text, 3), "20 most frequent trigrams", 20)
    figure.suptitle("Frequency analysis: " + label, fontsize=16)
    figure.savefig(png_path, dpi=180)
    plt.close(figure)

    return json_path, png_path
