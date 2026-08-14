"""Performance experiments for the user's Hill cipher input."""

import csv
import math
import os
import random
import time

from .hill_cipher import clean_ascii_letters
from .hill_cipher import decrypt
from .hill_cipher import encrypt
from .hill_cipher import recover_key_from_known_plaintext
from .hill_cipher import validate_key_matrix
from .utils import is_english_letter


def count_english_letters(text):
    """Counts A-Z and a-z characters in text."""

    count = 0

    for character in text:
        if is_english_letter(character):
            count = count + 1

    return count


def shannon_letter_entropy(text):
    """Returns Shannon entropy in bits per English letter."""

    letters = clean_ascii_letters(text)

    if len(letters) == 0:
        return 0.0

    counts = {}

    for character in letters:
        counts[character] = counts.get(character, 0) + 1

    entropy = 0.0

    for count in counts.values():
        probability = count / len(letters)
        entropy = entropy - probability * math.log2(probability)

    return entropy


def prefix_with_letter_count(text, requested_letter_count):
    """Returns a text prefix containing the requested number of letters."""

    result = []
    letter_count = 0

    for character in text:
        result.append(character)

        if is_english_letter(character):
            letter_count = letter_count + 1

            if letter_count == requested_letter_count:
                break

    return "".join(result)


def choose_text_lengths(total_letters, point_count=5):
    """Chooses evenly spaced experiment lengths up to the full input size."""

    if total_letters < 1:
        raise ValueError("experiment text must contain an English letter")

    lengths = []

    for point in range(1, point_count + 1):
        length = round(total_letters * point / point_count)

        if length < 1:
            length = 1

        if length not in lengths:
            lengths.append(length)

    return lengths


def choose_experiment_lengths(total_letters, key_size):
    """Adds key-recovery threshold lengths to the regular timing lengths."""

    lengths = choose_text_lengths(total_letters)
    minimum_key_recovery_length = key_size * key_size

    for length in [
        minimum_key_recovery_length,
        2 * minimum_key_recovery_length
    ]:
        if length <= total_letters and length not in lengths:
            lengths.append(length)

    lengths.sort()
    return lengths


def run_performance_experiment(plaintext, key_matrix, trials=20, seed=1405):
    """Measures timings, round trips, and exact known-plaintext key recovery."""

    if trials < 1:
        raise ValueError("trials must be positive")

    normalized_key = validate_key_matrix(key_matrix)
    key_size = len(normalized_key)
    all_letters = clean_ascii_letters(plaintext)
    total_letters = len(all_letters)
    lengths = choose_experiment_lengths(total_letters, key_size)
    random_generator = random.Random(seed)
    rows = []

    for text_length in lengths:
        sample = prefix_with_letter_count(plaintext, text_length)
        encryption_seconds = 0.0
        decryption_seconds = 0.0
        successes = 0
        key_recovery_successes = 0

        for trial_number in range(trials):
            start = time.perf_counter()
            ciphertext = encrypt(sample, key_matrix)
            encryption_seconds = encryption_seconds + (time.perf_counter() - start)

            start = time.perf_counter()
            recovered = decrypt(ciphertext, key_matrix)
            decryption_seconds = decryption_seconds + (time.perf_counter() - start)

            if recovered == sample:
                successes = successes + 1

            last_possible_start = total_letters - text_length
            key_sample_start = random_generator.randint(0, last_possible_start)
            key_sample = all_letters[
                key_sample_start:key_sample_start + text_length
            ]
            key_sample_ciphertext = encrypt(key_sample, normalized_key)

            try:
                recovered_key = recover_key_from_known_plaintext(
                    key_sample,
                    key_sample_ciphertext,
                    key_size,
                    maximum_combinations=2000
                )

                if recovered_key == normalized_key:
                    key_recovery_successes = key_recovery_successes + 1
            except ValueError:
                pass

        rows.append({
            "text_length": text_length,
            "trials": trials,
            "key_size": key_size,
            "average_encryption_ms": 1000 * encryption_seconds / trials,
            "average_decryption_ms": 1000 * decryption_seconds / trials,
            "round_trip_success_rate": 100 * successes / trials,
            "exact_key_recovery_rate": 100 * key_recovery_successes / trials
        })

    return rows


def save_performance_report(rows, output_dir):
    """Saves experiment rows as CSV and a three-panel PNG chart."""

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    if len(rows) == 0:
        raise ValueError("at least one experiment row is required")

    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "hill_user_performance.csv")
    png_path = os.path.join(output_dir, "hill_user_performance.png")

    field_names = [
        "text_length",
        "trials",
        "key_size",
        "average_encryption_ms",
        "average_decryption_ms",
        "round_trip_success_rate",
        "exact_key_recovery_rate"
    ]

    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()
        writer.writerows(rows)

    text_lengths = []
    encryption_times = []
    decryption_times = []
    success_rates = []
    key_recovery_rates = []

    for row in rows:
        text_lengths.append(row["text_length"])
        encryption_times.append(row["average_encryption_ms"])
        decryption_times.append(row["average_decryption_ms"])
        success_rates.append(row["round_trip_success_rate"])
        key_recovery_rates.append(row["exact_key_recovery_rate"])

    figure, axes = plt.subplots(1, 3, figsize=(16, 5), constrained_layout=True)
    key_size = rows[0]["key_size"]
    figure.suptitle(
        "Hill Cipher Performance for User Input ("
        + str(key_size)
        + "x"
        + str(key_size)
        + " key)",
        fontsize=15
    )

    axes[0].plot(
        text_lengths,
        encryption_times,
        marker="o",
        color="#2767d8",
        label="Encryption"
    )
    axes[0].plot(
        text_lengths,
        decryption_times,
        marker="s",
        color="#d92d27",
        label="Decryption"
    )
    axes[0].set_title("Average Encryption and Decryption Time")
    axes[0].set_ylabel("Milliseconds")
    axes[0].legend()

    axes[1].plot(text_lengths, success_rates, marker="o", color="#338a4b")
    axes[1].set_title("Exact Round-Trip Success")
    axes[1].set_ylabel("Success Rate (%)")
    axes[1].set_ylim(-3, 103)

    axes[2].plot(text_lengths, key_recovery_rates, marker="^", color="#8b55b5")
    axes[2].set_title("Exact Known-Plaintext Key Recovery")
    axes[2].set_ylabel("Key Recovery Rate (%)")
    axes[2].set_ylim(-3, 103)

    for axis in axes:
        axis.set_xlabel("Plaintext Length (letters)")
        axis.grid(alpha=0.3)

    figure.savefig(png_path, dpi=180)
    plt.close(figure)
    return csv_path, png_path


def save_entropy_comparison(plaintext, ciphertext, output_dir):
    """Saves plaintext/ciphertext Shannon entropy as CSV and a PNG chart."""

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "hill_entropy_comparison.csv")
    png_path = os.path.join(output_dir, "hill_entropy_comparison.png")
    rows = [
        {
            "text": "plaintext",
            "letter_count": count_english_letters(plaintext),
            "entropy_bits_per_letter": shannon_letter_entropy(plaintext)
        },
        {
            "text": "ciphertext",
            "letter_count": count_english_letters(ciphertext),
            "entropy_bits_per_letter": shannon_letter_entropy(ciphertext)
        }
    ]

    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["text", "letter_count", "entropy_bits_per_letter"]
        )
        writer.writeheader()
        writer.writerows(rows)

    labels = []
    entropies = []

    for row in rows:
        labels.append(row["text"])
        entropies.append(row["entropy_bits_per_letter"])

    maximum_entropy = math.log2(26)
    figure, axis = plt.subplots(figsize=(8, 5), constrained_layout=True)
    bars = axis.bar(labels, entropies, color=["#2767d8", "#d92d27"])
    axis.axhline(
        maximum_entropy,
        color="#333333",
        linestyle="--",
        label="Maximum log2(26)"
    )
    axis.set_title("Hill Cipher Shannon Letter Entropy")
    axis.set_ylabel("Entropy (bits per English letter)")
    axis.set_ylim(0, maximum_entropy + 0.4)
    axis.grid(axis="y", alpha=0.3)
    axis.legend()

    for index in range(len(bars)):
        bar = bars[index]
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            entropies[index] + 0.05,
            str(round(entropies[index], 4)),
            ha="center"
        )

    figure.savefig(png_path, dpi=180)
    plt.close(figure)
    return csv_path, png_path


def create_performance_report(plaintext, key_matrix, output_dir="output", trials=20):
    """Saves performance and entropy reports for the user's input."""

    rows = run_performance_experiment(plaintext, key_matrix, trials)
    performance_paths = save_performance_report(rows, output_dir)
    ciphertext = encrypt(plaintext, key_matrix)
    entropy_paths = save_entropy_comparison(plaintext, ciphertext, output_dir)
    return performance_paths + entropy_paths
