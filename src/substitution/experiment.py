"""Accuracy experiment for different substitution ciphertext lengths."""

import csv
import os
import random

from .substitution_cipher import clean_text_en
from .substitution_cipher import clean_text_fa
from .substitution_cipher import encrypt_substitution
from .substitution_cipher import generate_random_key
from .substitution_cryptanalysis import break_substitution_freq
from .substitution_cryptanalysis import build_ngram_language_model
from .substitution_cryptanalysis import calculate_accuracy


DEFAULT_LENGTHS = [200, 500, 1200, 3000, 5000, 8000]


def run_accuracy_experiment(
    corpus,
    reference_freq,
    is_persian=False,
    lengths=None,
    seed=1405,
    trials=20,
    ngram_reference_text=None,
    ngram_restarts=3,
    ngram_iterations=1500
):
    """Run repeated attacks and measure accuracy for every requested length."""

    if trials < 1:
        raise ValueError("trials must be positive")

    if is_persian:
        cleaned_corpus = clean_text_fa(corpus)
        language = "fa"
    else:
        cleaned_corpus = clean_text_en(corpus)
        language = "en"

    if lengths is None:
        lengths = DEFAULT_LENGTHS

    for length in lengths:
        if length < 1:
            raise ValueError("all text lengths must be positive")

    if len(lengths) == 0:
        raise ValueError("at least one text length is required")

    largest_length = max(lengths)
    if len(cleaned_corpus) < largest_length:
        raise ValueError("corpus is shorter than the largest requested text length")

    random_generator = random.Random(seed)
    rows = []
    ngram_model = None

    if ngram_reference_text is not None:
        ngram_model = build_ngram_language_model(
            ngram_reference_text,
            is_persian
        )

    for length in lengths:
        total_accuracy = 0.0
        exact_plaintext_successes = 0
        exact_key_successes = 0

        for trial_number in range(trials):
            last_possible_start = len(cleaned_corpus) - length
            start = random_generator.randint(0, last_possible_start)
            sample_plaintext = cleaned_corpus[start:start + length]
            secret_key = generate_random_key(language, random_generator)
            ciphertext = encrypt_substitution(
                sample_plaintext,
                secret_key,
                is_persian=is_persian
            )
            cracked_plaintext, guessed_key = break_substitution_freq(
                ciphertext,
                reference_freq,
                is_persian=is_persian,
                ngram_model=ngram_model,
                ngram_restarts=ngram_restarts,
                ngram_iterations=ngram_iterations,
                seed=seed + length + trial_number
            )
            accuracy = calculate_accuracy(sample_plaintext, cracked_plaintext)
            total_accuracy = total_accuracy + accuracy

            if cracked_plaintext == sample_plaintext:
                exact_plaintext_successes = exact_plaintext_successes + 1

            true_decryption_key = {
                encrypted_character: plaintext_character
                for plaintext_character, encrypted_character in secret_key.items()
            }
            if guessed_key == true_decryption_key:
                exact_key_successes = exact_key_successes + 1

        average_accuracy = total_accuracy / trials
        exact_success_rate = exact_plaintext_successes / trials
        exact_key_success_rate = exact_key_successes / trials
        rows.append({
            "text_length": length,
            "trials": trials,
            "average_accuracy_percent": average_accuracy,
            "exact_plaintext_successes": exact_plaintext_successes,
            "exact_plaintext_success_rate": exact_success_rate,
            "exact_key_successes": exact_key_successes,
            "exact_key_success_rate": exact_key_success_rate,
            # Keep the old field name for code that used the first version.
            "accuracy_percent": average_accuracy
        })

    return rows


def save_experiment(rows, output_dir):
    """Save experiment values as CSV and the chart as PNG."""

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "accuracy_by_ciphertext_length.csv")
    png_path = os.path.join(output_dir, "accuracy_by_ciphertext_length.png")

    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "text_length",
            "trials",
            "average_accuracy_percent",
            "exact_plaintext_successes",
            "exact_plaintext_success_rate",
            "exact_key_successes",
            "exact_key_success_rate"
        ])
        for row in rows:
            writer.writerow([
                row["text_length"],
                row["trials"],
                row["average_accuracy_percent"],
                row["exact_plaintext_successes"],
                row["exact_plaintext_success_rate"],
                row["exact_key_successes"],
                row["exact_key_success_rate"]
            ])

    lengths = [row["text_length"] for row in rows]
    accuracies = [row["average_accuracy_percent"] for row in rows]
    exact_success_rates = [
        100 * row["exact_plaintext_success_rate"]
        for row in rows
    ]
    exact_key_success_rates = [
        100 * row["exact_key_success_rate"]
        for row in rows
    ]
    figure, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    axis.plot(
        lengths,
        accuracies,
        marker="o",
        linestyle="-",
        color="b",
        label="Average letter accuracy"
    )
    axis.plot(
        lengths,
        exact_success_rates,
        marker="s",
        linestyle="-",
        color="#cb6d51",
        label="Exact plaintext recovery"
    )
    axis.plot(
        lengths,
        exact_key_success_rates,
        marker="^",
        linestyle="-",
        color="#5a9367",
        label="Exact key recovery"
    )
    axis.set_title("Substitution attack accuracy versus ciphertext length")
    axis.set_xlabel("Ciphertext length (number of characters)")
    axis.set_ylabel("Accuracy (%)")
    axis.set_ylim(0, 105)
    axis.grid(True, linestyle="--", alpha=0.6)
    axis.legend()
    figure.savefig(png_path, dpi=180)
    plt.close(figure)
    return csv_path, png_path


def evaluate_and_plot_accuracy(
    large_corpus,
    reference_freq,
    is_persian=False,
    output_dir="output",
    lengths=None,
    seed=1405,
    trials=20,
    ngram_reference_text=None,
    ngram_restarts=3,
    ngram_iterations=1500
):
    """Compatibility wrapper for the original experiment function."""

    rows = run_accuracy_experiment(
        large_corpus,
        reference_freq,
        is_persian=is_persian,
        lengths=lengths,
        seed=seed,
        trials=trials,
        ngram_reference_text=ngram_reference_text,
        ngram_restarts=ngram_restarts,
        ngram_iterations=ngram_iterations
    )
    save_experiment(rows, output_dir)

    for row in rows:
        print(
            "Text Length: " + str(row["text_length"])
            + " characters | Average accuracy: "
            + format(row["average_accuracy_percent"], ".2f") + "%"
            + " | Exact recovery: "
            + format(100 * row["exact_plaintext_success_rate"], ".2f") + "%"
            + " | Exact key: "
            + format(100 * row["exact_key_success_rate"], ".2f") + "%"
        )

    return rows
