"""Command-line interface for the Vigenere cipher project."""

import argparse
import os
import sys


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from src.experiment import run_success_experiment
from src.experiment import save_experiment
from src.text_statistics import compare_shannon_entropies
from src.text_statistics import create_analysis_report
from src.text_statistics import save_entropy_comparison
from src.vigenere_cipher import decrypt
from src.vigenere_cipher import encrypt
from src.vigenere_cryptanalysis import break_vigenere


def add_text_source(parser):
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="text entered directly")
    source.add_argument("--input", help="path to a UTF-8 input file")


def read_text(arguments):
    if arguments.text is not None:
        return arguments.text

    with open(arguments.input, "r", encoding="utf-8") as input_file:
        text = input_file.read()

    return text


def read_text_value(text_value, input_path):
    """Returns direct text or reads it from a UTF-8 file."""

    if text_value is not None:
        return text_value

    with open(input_path, "r", encoding="utf-8") as input_file:
        return input_file.read()


def write_or_print(text, output_path):
    if output_path is None:
        print(text)
        return

    output_directory = os.path.dirname(output_path)

    if len(output_directory) > 0:
        os.makedirs(output_directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        output_file.write(text)

    print("Wrote: " + output_path)


def prompt_with_default(message, default_value):
    """Reads a value from the user and uses a default when Enter is pressed."""

    value = input(message + " [" + str(default_value) + "]: ").strip()

    if value == "":
        return default_value

    return value


def prompt_for_text(text_name):
    """Gets text directly from the user or reads it from a UTF-8 file."""

    print("1. Type the " + text_name)
    print("2. Read the " + text_name + " from a file")
    source_choice = input("Choose 1 or 2 [1]: ").strip()

    if source_choice == "" or source_choice == "1":
        return input("Enter the " + text_name + ": ")

    if source_choice == "2":
        input_path = input("Input file path: ").strip().strip('"')

        with open(input_path, "r", encoding="utf-8") as input_file:
            return input_file.read()

    raise ValueError("Please choose 1 or 2")


def prompt_for_output(default_path):
    """Gets an output path; a dash means print without saving."""

    value = input(
        "Output file [" + default_path + "] (type - to only print): "
    ).strip().strip('"')

    if value == "":
        return default_path

    if value == "-":
        return None

    return value


def print_break_result(result, show_candidates):
    """Prints the recovered key and a short list of candidate plaintexts."""

    print("Recovered key: " + result["key"])
    print("Top candidates:")

    candidates_to_show = result["candidates"][:show_candidates]
    for candidate in candidates_to_show:
        preview = candidate["plaintext"][:70]
        preview = preview.replace("\n", " ")
        print(
            "  key=" + candidate["key"]
            + "  score=" + str(round(candidate["language_score"], 4))
            + "  " + preview
        )


def print_entropy_comparison(report):
    """Prints the important values from an entropy comparison report."""

    print(
        "Plaintext entropy:  "
        + str(round(report["plaintext"]["entropy_bits_per_letter"], 6))
        + " bits per letter"
    )
    print(
        "Ciphertext entropy: "
        + str(round(report["ciphertext"]["entropy_bits_per_letter"], 6))
        + " bits per letter"
    )
    print(
        "Difference:         "
        + str(round(report["entropy_difference_bits_per_letter"], 6))
        + " bits per letter"
    )
    print(
        "Maximum possible:   "
        + str(round(report["maximum_entropy_bits_per_letter"], 6))
        + " bits per letter"
    )


def run_experiment_and_save(
    corpus_path,
    lengths,
    trials,
    max_key_length,
    seed,
    output_dir
):
    """Runs the success experiment, saves its files, and prints a summary."""

    with open(corpus_path, "r", encoding="utf-8") as corpus_file:
        corpus = corpus_file.read()

    rows = run_success_experiment(
        corpus,
        lengths,
        trials,
        max_key_length,
        seed
    )

    paths = save_experiment(rows, output_dir)

    for row in rows:
        print(
            "length=" + str(row["text_length"])
            + "  key=" + str(round(100 * row["key_success_rate"], 1)) + "%"
            + "  plaintext="
            + str(round(100 * row["plaintext_success_rate"], 1)) + "%"
            + "  letters="
            + str(round(100 * row["average_letter_accuracy"], 1)) + "%"
        )

    print("Wrote: " + paths[0])
    print("Wrote: " + paths[1])


def interactive_main():
    """Shows a simple English menu when main.py is run without arguments."""

    project_directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_directory)

    print("Vigenere Cipher Project")
    print("1. Encrypt text")
    print("2. Decrypt text with a key")
    print("3. Break ciphertext without a key")
    print("4. Analyze text and create charts")
    print("5. Compare plaintext and ciphertext entropy")
    print("6. Run the success-rate experiment")
    print("0. Exit")

    choice = input("Choose an option: ").strip()

    try:
        if choice == "1":
            plaintext = prompt_for_text("plaintext")
            key = input("Key: ").strip()
            output_path = prompt_for_output("output/ciphertext.txt")
            ciphertext = encrypt(plaintext, key)
            write_or_print(ciphertext, output_path)

        elif choice == "2":
            ciphertext = prompt_for_text("ciphertext")
            key = input("Key: ").strip()
            output_path = prompt_for_output("output/decrypted.txt")
            plaintext = decrypt(ciphertext, key)
            write_or_print(plaintext, output_path)

        elif choice == "3":
            ciphertext = prompt_for_text("ciphertext")
            max_key_length = int(prompt_with_default("Maximum key length", 20))
            output_path = prompt_for_output("output/recovered.txt")
            result = break_vigenere(ciphertext, max_key_length)
            print_break_result(result, 5)
            write_or_print(result["plaintext"], output_path)

        elif choice == "4":
            text = prompt_for_text("text to analyze")
            label = prompt_with_default("Output label", "ciphertext")
            output_dir = prompt_with_default("Output folder", "output")
            paths = create_analysis_report(text, output_dir, label)
            print("Wrote: " + paths[0])
            print("Wrote: " + paths[1])

        elif choice == "5":
            plaintext = prompt_for_text("plaintext")
            ciphertext = prompt_for_text("ciphertext")
            output_path = prompt_for_output(
                "output/entropy_comparison.json"
            )
            report = compare_shannon_entropies(plaintext, ciphertext)
            print_entropy_comparison(report)

            if output_path is not None:
                save_entropy_comparison(report, output_path)
                print("Wrote: " + output_path)

        elif choice == "6":
            corpus_path = prompt_with_default(
                "Corpus file",
                "data/sample_plaintext.txt"
            ).strip().strip('"')
            lengths_text = prompt_with_default(
                "Text lengths separated by spaces",
                "100 200 400 800 1200"
            )
            lengths = []
            for value in lengths_text.split():
                lengths.append(int(value))

            trials = int(prompt_with_default("Trials for each length", 20))
            max_key_length = int(prompt_with_default("Maximum key length", 12))
            seed = int(prompt_with_default("Random seed", 1405))
            output_dir = prompt_with_default("Output folder", "output")
            run_experiment_and_save(
                corpus_path,
                lengths,
                trials,
                max_key_length,
                seed,
                output_dir
            )

        elif choice == "0":
            print("Goodbye.")

        else:
            print("Invalid option. Run the program again and choose 0 to 6.")

    except (OSError, ValueError, RuntimeError) as error:
        print("Error: " + str(error))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Vigenere cipher and statistical cryptanalysis"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = commands.add_parser("encrypt", help="encrypt with a key")
    add_text_source(encrypt_parser)
    encrypt_parser.add_argument("--key", required=True)
    encrypt_parser.add_argument("--output")

    decrypt_parser = commands.add_parser("decrypt", help="decrypt with a key")
    add_text_source(decrypt_parser)
    decrypt_parser.add_argument("--key", required=True)
    decrypt_parser.add_argument("--output")

    break_parser = commands.add_parser("break", help="break ciphertext without a key")
    add_text_source(break_parser)
    break_parser.add_argument("--max-key-length", type=int, default=20)
    break_parser.add_argument("--show-candidates", type=int, default=5)
    break_parser.add_argument("--output")

    analyze_parser = commands.add_parser("analyze", help="analyze text frequencies")
    add_text_source(analyze_parser)
    analyze_parser.add_argument("--label", default="text")
    analyze_parser.add_argument("--output-dir", default="output")

    entropy_parser = commands.add_parser(
        "compare-entropy",
        help="compare plaintext and ciphertext Shannon entropy"
    )
    plaintext_source = entropy_parser.add_mutually_exclusive_group(required=True)
    plaintext_source.add_argument("--plaintext")
    plaintext_source.add_argument("--plaintext-input")
    ciphertext_source = entropy_parser.add_mutually_exclusive_group(required=True)
    ciphertext_source.add_argument("--ciphertext")
    ciphertext_source.add_argument("--ciphertext-input")
    entropy_parser.add_argument(
        "--output",
        default="output/entropy_comparison.json"
    )

    experiment_parser = commands.add_parser("experiment", help="run the success-rate experiment")
    experiment_parser.add_argument("--corpus", default="data/sample_plaintext.txt")
    experiment_parser.add_argument(
        "--lengths",
        type=int,
        nargs="+",
        default=[100, 200, 400, 800, 1200]
    )
    experiment_parser.add_argument("--trials", type=int, default=20)
    experiment_parser.add_argument("--max-key-length", type=int, default=12)
    experiment_parser.add_argument("--seed", type=int, default=1405)
    experiment_parser.add_argument("--output-dir", default="output")

    return parser


def main():
    if len(sys.argv) == 1:
        interactive_main()
        return

    parser = build_parser()
    arguments = parser.parse_args()

    if arguments.command == "encrypt":
        plaintext = read_text(arguments)
        ciphertext = encrypt(plaintext, arguments.key)
        write_or_print(ciphertext, arguments.output)

    elif arguments.command == "decrypt":
        ciphertext = read_text(arguments)
        plaintext = decrypt(ciphertext, arguments.key)
        write_or_print(plaintext, arguments.output)

    elif arguments.command == "break":
        ciphertext = read_text(arguments)
        result = break_vigenere(ciphertext, arguments.max_key_length)
        print_break_result(result, arguments.show_candidates)
        write_or_print(result["plaintext"], arguments.output)

    elif arguments.command == "analyze":
        text = read_text(arguments)
        paths = create_analysis_report(text, arguments.output_dir, arguments.label)
        print("Wrote: " + paths[0])
        print("Wrote: " + paths[1])

    elif arguments.command == "compare-entropy":
        plaintext = read_text_value(
            arguments.plaintext,
            arguments.plaintext_input
        )
        ciphertext = read_text_value(
            arguments.ciphertext,
            arguments.ciphertext_input
        )
        report = compare_shannon_entropies(plaintext, ciphertext)
        print_entropy_comparison(report)
        path = save_entropy_comparison(report, arguments.output)
        print("Wrote: " + path)

    elif arguments.command == "experiment":
        run_experiment_and_save(
            arguments.corpus,
            arguments.lengths,
            arguments.trials,
            arguments.max_key_length,
            arguments.seed,
            arguments.output_dir
        )

if __name__ == "__main__":
    main()
