"""Command-line and interactive entry point for the substitution project."""

import argparse
import os
import random
import sys

from src.experiment import run_accuracy_experiment
from src.experiment import save_experiment
from src.hill_climbing import hill_climbing_attack
from src.simulated_annealing import simulated_annealing_attack
from src.substitution_cipher import decrypt_substitution
from src.substitution_cipher import encrypt_substitution
from src.substitution_cipher import generate_random_key
from src.substitution_cipher import key_from_string
from src.substitution_cipher import key_to_string
from src.substitution_cryptanalysis import STD_ENGLISH_FREQ
from src.substitution_cryptanalysis import STD_PERSIAN_FREQ
from src.substitution_cryptanalysis import break_substitution_freq
from src.text_statistics import compare_shannon_entropies
from src.text_statistics import create_analysis_report
from src.text_statistics import save_entropy_comparison


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def add_text_source(parser):
    """Add direct-text and UTF-8 file input options."""

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="text entered directly")
    source.add_argument("--input", help="path of a UTF-8 input file")


def read_text(arguments):
    """Read text from the selected command-line source."""

    if arguments.text is not None:
        return arguments.text

    with open(arguments.input, "r", encoding="utf-8") as input_file:
        return input_file.read()


def read_text_value(text_value, input_path):
    """Return direct text or read it from a UTF-8 file."""

    if text_value is not None:
        return text_value

    with open(input_path, "r", encoding="utf-8") as input_file:
        return input_file.read()


def write_or_print(text, output_path):
    """Write text to a UTF-8 file, or print it when no path is provided."""

    if output_path is None:
        print(text)
        return

    output_directory = os.path.dirname(output_path)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        output_file.write(text)

    print("Wrote: " + output_path)


def prompt_with_default(message, default_value):
    """Read a value and use the displayed default when Enter is pressed."""

    value = input(message + " [" + str(default_value) + "]: ").strip()

    if value == "":
        return default_value

    return value


def read_interactive_file(input_path):
    """Read a UTF-8 file and accept an accidentally omitted .txt suffix."""

    input_path = input_path.strip().strip('"')
    possible_paths = [input_path]

    if not input_path.lower().endswith(".txt"):
        possible_paths.append(input_path + ".txt")

    for possible_path in possible_paths:
        if os.path.isfile(possible_path):
            print("Reading text from: " + possible_path)
            with open(possible_path, "r", encoding="utf-8") as input_file:
                return input_file.read()

    raise FileNotFoundError("Input file not found: " + input_path)


def prompt_for_text(text_name, default_file_path=None):
    """Get direct text or read a UTF-8 file with an optional default path."""

    print("1. Type the " + text_name)
    print("2. Read the " + text_name + " from a file")
    default_choice = "2" if default_file_path is not None else "1"
    source_choice = input(
        "Choose 1 or 2 [" + default_choice + "]: "
    ).strip()

    if source_choice == "":
        source_choice = default_choice

    if source_choice == "1":
        entered_value = input(
            "Enter the " + text_name + " or a file path: "
        )
        possible_path = entered_value.strip().strip('"')

        if os.path.isfile(possible_path):
            return read_interactive_file(possible_path)

        if os.path.isfile(possible_path + ".txt"):
            return read_interactive_file(possible_path)

        if "/" in possible_path or "\\" in possible_path:
            raise FileNotFoundError("Input file not found: " + possible_path)

        return entered_value

    if source_choice == "2":
        if default_file_path is None:
            input_path = input("Input file path: ")
        else:
            input_path = prompt_with_default(
                "Input file path",
                default_file_path
            )

        return read_interactive_file(input_path)

    raise ValueError("Please choose 1 or 2")


def prompt_for_output(default_path):
    """Get an output path; a dash prints the result without saving it."""

    value = input(
        "Output file [" + default_path + "] (type - to only print): "
    ).strip().strip('"')

    if value == "":
        return default_path

    if value == "-":
        return None

    return value


def language_is_persian(language):
    return language == "fa"


def reference_frequency(language):
    """Return the built-in reference table for English or Persian."""

    if language == "fa":
        return STD_PERSIAN_FREQ

    return STD_ENGLISH_FREQ


def default_sample_plaintext_path(language):
    """Return the sample plaintext that matches the selected language."""

    if language == "fa":
        return "data/sample_plaintext_fa.txt"

    return "data/sample_plaintext.txt"


def default_experiment_lengths(language):
    """Return lengths that fit the bundled sample for each language."""

    if language == "fa":
        return [200, 500, 1200, 3000, 5000]

    return [200, 500, 1200, 3000, 5000, 8000]


def default_ngram_reference_path(language):
    """Return the bundled n-gram corpus path when one is available."""

    if language == "en":
        return "data/english_reference.txt"

    if language == "fa":
        return "data/persian_reference.txt"

    return "-"


def read_ngram_reference(language, requested_path=None):
    """Read an n-gram corpus; a dash explicitly disables refinement."""

    reference_path = requested_path

    if reference_path is None:
        reference_path = default_ngram_reference_path(language)

    reference_path = reference_path.strip().strip('"')

    if reference_path == "" or reference_path == "-":
        return None

    with open(reference_path, "r", encoding="utf-8") as reference_file:
        return reference_file.read()


def break_ciphertext(
    ciphertext,
    language,
    algorithm="frequency",
    reference_corpus=None,
    restarts=3,
    iterations=2000,
    seed=1405
):
    """Break ciphertext with the algorithm selected by the user."""

    is_persian = language_is_persian(language)

    if algorithm == "frequency":
        return break_substitution_freq(
            ciphertext,
            reference_frequency(language),
            is_persian
        )

    reference_text = read_ngram_reference(language, reference_corpus)
    if reference_text is None:
        raise ValueError(
            "Hill Climbing and Simulated Annealing need a reference corpus"
        )

    if algorithm == "hill-climbing":
        return hill_climbing_attack(
            ciphertext,
            reference_text,
            is_persian=is_persian,
            iterations=iterations,
            restarts=restarts,
            seed=seed,
            reference_freq=reference_frequency(language)
        )

    if algorithm == "simulated-annealing":
        return simulated_annealing_attack(
            ciphertext,
            reference_text,
            is_persian=is_persian,
            iterations=iterations,
            restarts=restarts,
            seed=seed,
            reference_freq=reference_frequency(language)
        )

    raise ValueError("unknown breaking algorithm: " + algorithm)


def prompt_for_break_algorithm():
    """Ask which keyless breaking algorithm should be used."""

    print("Breaking algorithm:")
    print("1. Frequency analysis")
    print("2. Hill Climbing")
    print("3. Simulated Annealing")
    choice = input("Choose 1, 2, or 3 [1]: ").strip()

    algorithms = {
        "": "frequency",
        "1": "frequency",
        "2": "hill-climbing",
        "3": "simulated-annealing"
    }

    if choice not in algorithms:
        raise ValueError("Please choose 1, 2, or 3")

    return algorithms[choice]


def print_frequency_key(deduced_key):
    """Print the cipher-to-plaintext mapping guessed by frequency analysis."""

    print("Guessed cipher -> plaintext mapping:")
    for cipher_character in deduced_key:
        print(cipher_character + " -> " + deduced_key[cipher_character])


def print_entropy_comparison(report):
    """Print the main values from a Shannon entropy comparison."""

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
    language,
    lengths,
    trials,
    seed,
    output_dir,
    ngram_reference_path,
    ngram_restarts,
    ngram_iterations
):
    """Run repeated attacks, save both files, and print a short summary."""

    with open(corpus_path, "r", encoding="utf-8") as corpus_file:
        corpus = corpus_file.read()

    ngram_reference_text = read_ngram_reference(
        language,
        ngram_reference_path
    )

    rows = run_accuracy_experiment(
        corpus,
        reference_frequency(language),
        is_persian=language_is_persian(language),
        lengths=lengths,
        seed=seed,
        trials=trials,
        ngram_reference_text=ngram_reference_text,
        ngram_restarts=ngram_restarts,
        ngram_iterations=ngram_iterations
    )
    paths = save_experiment(rows, output_dir)

    for row in rows:
        print(
            "length=" + str(row["text_length"])
            + "  average_accuracy="
            + str(round(row["average_accuracy_percent"], 1)) + "%"
            + "  exact_plaintext="
            + str(round(100 * row["exact_plaintext_success_rate"], 1)) + "%"
            + "  exact_key="
            + str(round(100 * row["exact_key_success_rate"], 1)) + "%"
        )

    print("Wrote: " + paths[0])
    print("Wrote: " + paths[1])


def run_interactive():
    """Show an input flow matching the Vigenere project."""

    project_directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_directory)

    print("Substitution Cipher Project")
    print("1. Encrypt text")
    print("2. Decrypt text with a key")
    print("3. Break ciphertext without a key")
    print("4. Analyze text and create charts")
    print("5. Generate a random key")
    print("6. Run the success-rate experiment")
    print("7. Compare plaintext and ciphertext entropy")
    print("0. Exit")
    choice = input("Choose an option: ").strip()

    try:
        if choice == "1":
            language = prompt_with_default("Language (en/fa)", "en")
            plaintext = prompt_for_text(
                "plaintext",
                default_sample_plaintext_path(language)
            )
            key_text = input("Permutation key: ").strip()
            output_path = prompt_for_output("output/ciphertext.txt")
            key = key_from_string(key_text, language)
            ciphertext = encrypt_substitution(
                plaintext,
                key,
                language_is_persian(language)
            )
            write_or_print(ciphertext, output_path)

        elif choice == "2":
            language = prompt_with_default("Language (en/fa)", "en")
            ciphertext = prompt_for_text(
                "ciphertext",
                "output/ciphertext.txt"
            )
            key_text = input("Permutation key: ").strip()
            output_path = prompt_for_output("output/decrypted.txt")
            key = key_from_string(key_text, language)
            plaintext = decrypt_substitution(ciphertext, key)
            write_or_print(plaintext, output_path)

        elif choice == "3":
            language = prompt_with_default("Language (en/fa)", "en")
            ciphertext = prompt_for_text(
                "ciphertext",
                "output/ciphertext.txt"
            )
            algorithm = prompt_for_break_algorithm()
            output_path = prompt_for_output("output/recovered.txt")
            plaintext, deduced_key = break_ciphertext(
                ciphertext,
                language,
                algorithm,
                restarts=3,
                iterations=2000,
                seed=1405
            )
            print_frequency_key(deduced_key)
            write_or_print(plaintext, output_path)

        elif choice == "4":
            language = prompt_with_default("Language (en/fa)", "en")
            text = prompt_for_text(
                "text to analyze",
                default_sample_plaintext_path(language)
            )
            label = prompt_with_default("Output label", "ciphertext")
            output_dir = prompt_with_default("Output folder", "output")
            paths = create_analysis_report(
                text,
                output_dir,
                label,
                language_is_persian(language)
            )
            print("Wrote: " + paths[0])
            print("Wrote: " + paths[1])

        elif choice == "5":
            language = prompt_with_default("Language (en/fa)", "en")
            seed = int(prompt_with_default("Random seed", 1405))
            key = generate_random_key(language, random.Random(seed))
            print("Generated key: " + key_to_string(key, language))

        elif choice == "6":
            language = prompt_with_default("Language (en/fa)", "en")
            corpus_path = prompt_with_default(
                "Corpus file",
                default_sample_plaintext_path(language)
            ).strip().strip('"')
            lengths_text = prompt_with_default(
                "Text lengths separated by spaces",
                " ".join([
                    str(length)
                    for length in default_experiment_lengths(language)
                ])
            )
            lengths = []
            for value in lengths_text.split():
                lengths.append(int(value))

            trials = int(prompt_with_default("Trials for each length", 20))
            seed = int(prompt_with_default("Random seed", 1405))
            output_dir = prompt_with_default("Output folder", "output")
            run_experiment_and_save(
                corpus_path,
                language,
                lengths,
                trials,
                seed,
                output_dir,
                default_ngram_reference_path(language),
                3,
                1500
            )

        elif choice == "7":
            language = prompt_with_default("Language (en/fa)", "en")
            plaintext = prompt_for_text(
                "plaintext",
                default_sample_plaintext_path(language)
            )
            ciphertext = prompt_for_text(
                "ciphertext",
                "output/ciphertext.txt"
            )
            output_path = prompt_for_output("output/entropy_comparison.json")
            report = compare_shannon_entropies(
                plaintext,
                ciphertext,
                language_is_persian(language)
            )
            print_entropy_comparison(report)

            if output_path is not None:
                save_entropy_comparison(report, output_path)
                print("Wrote: " + output_path)

        elif choice == "0":
            print("Goodbye.")

        else:
            print("Invalid option. Run the program again and choose 0 to 7.")

    except (OSError, ValueError, RuntimeError) as error:
        print("Error: " + str(error))


def build_parser():
    """Build the direct, reproducible command-line interface."""

    parser = argparse.ArgumentParser(description="Substitution cipher project")
    commands = parser.add_subparsers(dest="command", required=True)

    key_parser = commands.add_parser("generate-key", help="generate a key")
    key_parser.add_argument("--language", choices=["en", "fa"], default="en")
    key_parser.add_argument("--seed", type=int)

    encrypt_parser = commands.add_parser("encrypt", help="encrypt with a key")
    add_text_source(encrypt_parser)
    encrypt_parser.add_argument("--key", required=True)
    encrypt_parser.add_argument("--language", choices=["en", "fa"], default="en")
    encrypt_parser.add_argument("--output")

    decrypt_parser = commands.add_parser("decrypt", help="decrypt with a key")
    add_text_source(decrypt_parser)
    decrypt_parser.add_argument("--key", required=True)
    decrypt_parser.add_argument("--language", choices=["en", "fa"], default="en")
    decrypt_parser.add_argument("--output")

    break_parser = commands.add_parser("break", help="break without a key")
    add_text_source(break_parser)
    break_parser.add_argument("--language", choices=["en", "fa"], default="en")
    break_parser.add_argument(
        "--algorithm",
        choices=["frequency", "hill-climbing", "simulated-annealing"],
        default="frequency"
    )
    break_parser.add_argument("--reference-corpus")
    break_parser.add_argument(
        "--restarts",
        "--ngram-restarts",
        dest="restarts",
        type=int,
        default=3
    )
    break_parser.add_argument(
        "--iterations",
        "--ngram-iterations",
        dest="iterations",
        type=int,
        default=2000
    )
    break_parser.add_argument("--seed", type=int, default=1405)
    break_parser.add_argument("--output")

    analyze_parser = commands.add_parser("analyze", help="frequency report")
    add_text_source(analyze_parser)
    analyze_parser.add_argument("--language", choices=["en", "fa"], default="en")
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
    entropy_parser.add_argument("--language", choices=["en", "fa"], default="en")
    entropy_parser.add_argument(
        "--output",
        default="output/entropy_comparison.json"
    )

    experiment_parser = commands.add_parser("experiment", help="accuracy chart")
    experiment_parser.add_argument("--corpus")
    experiment_parser.add_argument(
        "--lengths",
        nargs="+",
        type=int,
        default=None
    )
    experiment_parser.add_argument("--trials", type=int, default=20)
    experiment_parser.add_argument("--language", choices=["en", "fa"], default="en")
    experiment_parser.add_argument("--reference-corpus")
    experiment_parser.add_argument("--ngram-restarts", type=int, default=3)
    experiment_parser.add_argument("--ngram-iterations", type=int, default=1500)
    experiment_parser.add_argument("--seed", type=int, default=1405)
    experiment_parser.add_argument("--output-dir", default="output")
    return parser


def main():
    """Run the menu without arguments, otherwise run one direct command."""

    if len(sys.argv) == 1:
        run_interactive()
        return

    parser = build_parser()
    arguments = parser.parse_args()

    if arguments.command == "generate-key":
        random_generator = None
        if arguments.seed is not None:
            random_generator = random.Random(arguments.seed)
        key = generate_random_key(arguments.language, random_generator)
        print(key_to_string(key, arguments.language))

    elif arguments.command == "encrypt":
        key = key_from_string(arguments.key, arguments.language)
        ciphertext = encrypt_substitution(
            read_text(arguments),
            key,
            language_is_persian(arguments.language)
        )
        write_or_print(ciphertext, arguments.output)

    elif arguments.command == "decrypt":
        key = key_from_string(arguments.key, arguments.language)
        plaintext = decrypt_substitution(read_text(arguments), key)
        write_or_print(plaintext, arguments.output)

    elif arguments.command == "break":
        plaintext, deduced_key = break_ciphertext(
            read_text(arguments),
            arguments.language,
            arguments.algorithm,
            reference_corpus=arguments.reference_corpus,
            restarts=arguments.restarts,
            iterations=arguments.iterations,
            seed=arguments.seed
        )
        print_frequency_key(deduced_key)
        write_or_print(plaintext, arguments.output)

    elif arguments.command == "analyze":
        paths = create_analysis_report(
            read_text(arguments),
            arguments.output_dir,
            arguments.label,
            language_is_persian(arguments.language)
        )
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
        report = compare_shannon_entropies(
            plaintext,
            ciphertext,
            language_is_persian(arguments.language)
        )
        print_entropy_comparison(report)
        path = save_entropy_comparison(report, arguments.output)
        print("Wrote: " + path)

    elif arguments.command == "experiment":
        corpus_path = arguments.corpus
        if corpus_path is None:
            corpus_path = default_sample_plaintext_path(arguments.language)

        lengths = arguments.lengths
        if lengths is None:
            lengths = default_experiment_lengths(arguments.language)

        with open(corpus_path, "r", encoding="utf-8") as corpus_file:
            corpus = corpus_file.read()
        rows = run_accuracy_experiment(
            corpus,
            reference_frequency(arguments.language),
            is_persian=language_is_persian(arguments.language),
            lengths=lengths,
            seed=arguments.seed,
            trials=arguments.trials,
            ngram_reference_text=read_ngram_reference(
                arguments.language,
                arguments.reference_corpus
            ),
            ngram_restarts=arguments.ngram_restarts,
            ngram_iterations=arguments.ngram_iterations
        )
        for row in rows:
            print(
                "length=" + str(row["text_length"])
                + "  average_accuracy="
                + str(round(row["average_accuracy_percent"], 1)) + "%"
                + "  exact_plaintext="
                + str(round(100 * row["exact_plaintext_success_rate"], 1)) + "%"
                + "  exact_key="
                + str(round(100 * row["exact_key_success_rate"], 1)) + "%"
            )
        paths = save_experiment(rows, arguments.output_dir)
        print("Wrote: " + paths[0])
        print("Wrote: " + paths[1])


if __name__ == "__main__":
    main()
