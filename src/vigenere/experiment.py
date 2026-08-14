"""Success-rate experiments for different ciphertext lengths."""

import csv
import os
import random
import string

from .vigenere_cipher import encrypt
from .vigenere_cryptanalysis import break_vigenere
from .vigenere_cryptanalysis import clean_ascii_letters
from .vigenere_cryptanalysis import smaller_key


def plaintext_letter_accuracy(original_plaintext, recovered_plaintext):
    """Returns the ratio of letters recovered in the correct positions."""

    if len(original_plaintext) == 0:
        return 0.0

    correct_characters = 0

    for original, recovered in zip(original_plaintext, recovered_plaintext):
        if original == recovered:
            correct_characters = correct_characters + 1

    return correct_characters / len(original_plaintext)


def create_random_key(random_generator, minimum_length, maximum_length):
    """Creates a random key that is not a repetition of a shorter key."""

    while True:
        key_length = random_generator.randint(minimum_length, maximum_length)
        key_characters = []

        for index in range(key_length):
            character = random_generator.choice(string.ascii_uppercase)
            key_characters.append(character)

        key = "".join(key_characters)

        if smaller_key(key) == key:
            return key


def run_success_experiment(corpus, lengths, trials=20, max_key_length=12, seed=1405):
    """Runs the attack several times and calculates its success rate."""

    if trials < 1:
        raise ValueError("trials must be positive")

    if len(lengths) == 0:
        raise ValueError("at least one text length is required")

    for text_length in lengths:
        if text_length < 2:
            raise ValueError("all text lengths must be at least 2")

    if max_key_length < 3:
        raise ValueError("max_key_length must be at least 3")

    letters = clean_ascii_letters(corpus)

    largest_length = lengths[0]
    for text_length in lengths:
        if text_length > largest_length:
            largest_length = text_length

    if len(letters) < largest_length:
        raise ValueError("corpus is shorter than the largest requested text length")

    random_generator = random.Random(seed)
    rows = []

    for text_length in lengths:
        key_successes = 0
        plaintext_successes = 0
        total_letter_accuracy = 0.0

        for trial_number in range(trials):
            last_possible_start = len(letters) - text_length
            start = random_generator.randint(0, last_possible_start)
            plaintext = letters[start:start + text_length]

            maximum_random_key_length = 8
            if max_key_length < maximum_random_key_length:
                maximum_random_key_length = max_key_length

            key = create_random_key(
                random_generator,
                3,
                maximum_random_key_length
            )

            ciphertext = encrypt(plaintext, key)
            result = break_vigenere(ciphertext, max_key_length)

            if result["key"] == key:
                key_successes = key_successes + 1

            if result["plaintext"] == plaintext:
                plaintext_successes = plaintext_successes + 1

            total_letter_accuracy = total_letter_accuracy + plaintext_letter_accuracy(
                plaintext,
                result["plaintext"]
            )

        key_success_rate = key_successes / trials
        plaintext_success_rate = plaintext_successes / trials
        average_letter_accuracy = total_letter_accuracy / trials

        row = {
            "text_length": text_length,
            "trials": trials,
            "key_successes": key_successes,
            "plaintext_successes": plaintext_successes,
            "key_success_rate": key_success_rate,
            "plaintext_success_rate": plaintext_success_rate,
            "average_letter_accuracy": average_letter_accuracy
        }
        rows.append(row)

    return rows


def save_experiment(rows, output_dir):
    """Saves experiment results as a CSV file and a PNG chart."""

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise RuntimeError("matplotlib is required for chart generation")

    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "success_by_ciphertext_length.csv")
    png_path = os.path.join(output_dir, "success_by_ciphertext_length.png")

    with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "text_length",
            "trials",
            "key_successes",
            "plaintext_successes",
            "key_success_rate",
            "plaintext_success_rate",
            "average_letter_accuracy"
        ])

        for row in rows:
            writer.writerow([
                row["text_length"],
                row["trials"],
                row["key_successes"],
                row["plaintext_successes"],
                row["key_success_rate"],
                row["plaintext_success_rate"],
                row["average_letter_accuracy"]
            ])

    text_lengths = []
    key_rates = []
    plaintext_rates = []
    letter_accuracies = []

    for row in rows:
        text_lengths.append(row["text_length"])
        key_rates.append(100 * row["key_success_rate"])
        plaintext_rates.append(100 * row["plaintext_success_rate"])
        letter_accuracies.append(100 * row["average_letter_accuracy"])

    figure, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
    axis.plot(
        text_lengths,
        letter_accuracies,
        marker="o",
        linewidth=2,
        color="b",
        label="Average letter accuracy"
    )
    axis.plot(
        text_lengths,
        plaintext_rates,
        marker="s",
        linewidth=2,
        color="#cb6d51",
        label="Exact plaintext recovery"
    )
    axis.plot(
        text_lengths,
        key_rates,
        marker="^",
        linewidth=2,
        color="#5a9367",
        label="Exact key recovery"
    )
    axis.set_xlabel("Ciphertext length (English letters)")
    axis.set_ylabel("Accuracy (%)")
    axis.set_ylim(-3, 103)
    axis.set_title("Vigenere cryptanalysis success versus ciphertext length")
    axis.grid(alpha=0.3)
    axis.legend()
    figure.savefig(png_path, dpi=180)
    plt.close(figure)

    return csv_path, png_path
