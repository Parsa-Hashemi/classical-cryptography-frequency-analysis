"""Frequency calculations and chart/report generation."""

import json
import math
import os
from collections import Counter

from .substitution_cipher import ENGLISH_ALPHABET
from .substitution_cipher import PERSIAN_ALPHABET
from .substitution_cipher import clean_text_en
from .substitution_cipher import clean_text_fa


def clean_for_statistics(text, is_persian=False):
    """Return only the alphabet letters used in statistical calculations."""

    if is_persian:
        return clean_text_fa(text)

    return clean_text_en(text)


def ngram_counts(text, size, is_persian=False):
    """Count consecutive n-grams in the cleaned letter sequence."""

    if size < 1:
        raise ValueError("ngram size must be positive")

    cleaned_text = clean_for_statistics(text, is_persian)
    counts = {}
    last_start = len(cleaned_text) - size

    for start in range(last_start + 1):
        ngram = cleaned_text[start:start + size]

        if ngram not in counts:
            counts[ngram] = 0

        counts[ngram] = counts[ngram] + 1

    return counts


def sorted_counts(counts):
    """Return counts ordered from the most to the least frequent item."""

    items = sorted(
        counts.items(),
        key=lambda item: item[1],
        reverse=True
    )
    return dict(items)


def relative_frequencies(counts):
    """Convert a count dictionary to percentages with the same ordering."""

    total = sum(counts.values())

    if total == 0:
        return {}

    frequencies = {}
    for item in sorted_counts(counts):
        frequencies[item] = (counts[item] / total) * 100

    return frequencies


def shannon_entropy(text, is_persian=False):
    """Calculate Shannon entropy in bits per alphabet letter."""

    counts = ngram_counts(text, 1, is_persian)
    total = sum(counts.values())

    if total == 0:
        return 0.0

    entropy = 0.0

    for character in counts:
        probability = counts[character] / total
        entropy = entropy - probability * math.log2(probability)

    return entropy


def compare_shannon_entropies(plaintext, ciphertext, is_persian=False):
    """Compare plaintext and ciphertext single-letter Shannon entropy."""

    if is_persian:
        alphabet_size = len(PERSIAN_ALPHABET)
    else:
        alphabet_size = len(ENGLISH_ALPHABET)

    plaintext_letters = clean_for_statistics(plaintext, is_persian)
    ciphertext_letters = clean_for_statistics(ciphertext, is_persian)
    plaintext_entropy = shannon_entropy(plaintext_letters, is_persian)
    ciphertext_entropy = shannon_entropy(ciphertext_letters, is_persian)
    maximum_entropy = math.log2(alphabet_size)

    return {
        "language": "fa" if is_persian else "en",
        "alphabet_size": alphabet_size,
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


def save_entropy_comparison(report, output_path):
    """Save a plaintext/ciphertext entropy report as UTF-8 JSON."""

    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, ensure_ascii=False, indent=2)

    return output_path


def calculate_frequencies(text, is_persian=False):
    """Calculate character percentages, sorted from highest to lowest."""

    cleaned_text = clean_for_statistics(text, is_persian)

    total_chars = len(cleaned_text)

    if total_chars == 0:
        return {}, ""

    counts = Counter(cleaned_text)
    frequencies = {}

    for character in counts:
        frequencies[character] = (counts[character] / total_chars) * 100

    sorted_items = sorted(
        frequencies.items(),
        key=lambda item: item[1],
        reverse=True
    )
    sorted_frequencies = dict(sorted_items)
    return sorted_frequencies, cleaned_text


def plot_ngram_counts(axis, counts, title, limit=None):
    """Draw one n-gram count chart on an existing Matplotlib axis."""

    ordered_counts = sorted_counts(counts)
    items = list(ordered_counts.items())

    if limit is not None:
        items = items[:limit]

    labels = [item[0] for item in items]
    values = [item[1] for item in items]
    axis.bar(labels, values, color="#315b7d")
    axis.set_title(title)
    axis.set_ylabel("Count")
    axis.grid(axis="y", alpha=0.25)
    axis.tick_params(axis="x", rotation=45)


def plot_frequency(
    freq_dict,
    title="Letter Frequency Analysis",
    output_path=None,
    show=None
):
    """Plot frequencies, optionally saving them as a PNG file."""

    try:
        import matplotlib
        if output_path is not None:
            matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    letters = list(freq_dict.keys())
    percentages = list(freq_dict.values())
    figure, axis = plt.subplots(figsize=(12, 5), constrained_layout=True)
    axis.bar(letters, percentages, color="skyblue")
    axis.set_xlabel("Characters")
    axis.set_ylabel("Frequency (%)")
    axis.set_title(title)
    axis.grid(axis="y", linestyle="--", alpha=0.7)

    if output_path is not None:
        output_directory = os.path.dirname(output_path)
        if output_directory:
            os.makedirs(output_directory, exist_ok=True)
        figure.savefig(output_path, dpi=180)

    if show is None:
        show = output_path is None

    if show:
        plt.show()

    plt.close(figure)
    return output_path


def create_analysis_report(text, output_dir, label="text", is_persian=False):
    """Save letter, bigram, and trigram statistics as JSON and PNG."""

    os.makedirs(output_dir, exist_ok=True)
    safe_label = "".join([
        character if character.isalnum() or character in "-_" else "_"
        for character in label
    ])
    json_path = os.path.join(output_dir, safe_label + "_statistics.json")
    png_path = os.path.join(output_dir, safe_label + "_frequencies.png")
    frequencies, cleaned_text = calculate_frequencies(text, is_persian)
    letter_counts = ngram_counts(text, 1, is_persian)
    bigram_counts = ngram_counts(text, 2, is_persian)
    trigram_counts = ngram_counts(text, 3, is_persian)
    report = {
        "language": "fa" if is_persian else "en",
        "letter_count": len(cleaned_text),
        # Keep the old field so existing code can still read the report.
        "frequencies_percent": frequencies,
        "letters": {
            "counts": sorted_counts(letter_counts),
            "frequencies_percent": relative_frequencies(letter_counts)
        },
        "bigrams": {
            "counts": sorted_counts(bigram_counts),
            "frequencies_percent": relative_frequencies(bigram_counts)
        },
        "trigrams": {
            "counts": sorted_counts(trigram_counts),
            "frequencies_percent": relative_frequencies(trigram_counts)
        }
    }

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, ensure_ascii=False, indent=2)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    figure, axes = plt.subplots(3, 1, figsize=(12, 13), constrained_layout=True)
    plot_ngram_counts(axes[0], letter_counts, "Letter frequencies")
    plot_ngram_counts(axes[1], bigram_counts, "20 most frequent bigrams", 20)
    plot_ngram_counts(axes[2], trigram_counts, "20 most frequent trigrams", 20)
    figure.suptitle("Substitution frequency analysis: " + label, fontsize=16)
    figure.savefig(png_path, dpi=180)
    plt.close(figure)
    return json_path, png_path
