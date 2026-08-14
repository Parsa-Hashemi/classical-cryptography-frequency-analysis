"""Command-line interface and interactive menu for the Caesar cipher project."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from src.analysis import (
    crack_by_ngram,
    crack_caesar,
    frequency_rows,
    index_of_coincidence,
    ngram_counts,
    shannon_entropy,
)
from src.caesar import brute_force, decrypt, encrypt
from src.experiment import (
    run_performance_experiments,
    save_frequency_artifacts,
    save_ngram_artifacts,
    save_statistics_artifacts,
)


PROJECT_DIRECTORY = Path(__file__).resolve().parent


def _configure_console() -> None:
    """Configure UTF-8 output for Windows consoles."""

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def _add_text_source(parser: argparse.ArgumentParser) -> None:
    """Add direct-text and file-input options to a command."""

    source = parser.add_mutually_exclusive_group()
    source.add_argument("--text", help="text entered directly")
    source.add_argument("--input", help="path to a UTF-8 input file")


def _read_text_file(input_path: str) -> str:
    """Read a UTF-8 file and accept an accidentally omitted .txt suffix."""

    cleaned_path = input_path.strip().strip('"')
    possible_paths = [Path(cleaned_path)]
    if not cleaned_path.lower().endswith(".txt"):
        possible_paths.append(Path(cleaned_path + ".txt"))

    for path in possible_paths:
        if path.is_file():
            print(f"Reading text from: {path}")
            return path.read_text(encoding="utf-8")

    raise FileNotFoundError(f"Input file not found: {cleaned_path}")


def _read_text_argument(text: str | None, input_path: str | None = None) -> str:
    """Read command text directly, from a file, or interactively."""

    if text is not None:
        return text
    if input_path is not None:
        return Path(input_path).read_text(encoding="utf-8")
    return input("Enter the text: ")


def _prompt_for_text(text_name: str) -> str:
    """Get text directly or from a UTF-8 file in the interactive menu."""

    print(f"1. Type the {text_name}")
    print(f"2. Read the {text_name} from a file")
    source_choice = input("Choose the source [1]: ").strip()

    if source_choice in ("", "1"):
        entered_value = input(f"{text_name}: ")
        possible_path = entered_value.strip().strip('"')

        if os.path.isfile(possible_path) or os.path.isfile(possible_path + ".txt"):
            return _read_text_file(possible_path)
        if "/" in possible_path or "\\" in possible_path:
            raise FileNotFoundError(f"Input file not found: {possible_path}")
        return entered_value

    if source_choice == "2":
        return _read_text_file(input("Input file path: "))

    raise ValueError("Please choose 1 or 2")


def _prompt_with_default(message: str, default_value: object) -> str:
    value = input(f"{message} [{default_value}]: ").strip()
    return str(default_value) if value == "" else value


def _prompt_for_output(default_path: str) -> str | None:
    """Get an output path; a dash means print without saving."""

    value = input(
        f"Output file [{default_path}] (type - to only print): "
    ).strip().strip('"')
    if value == "":
        return default_path
    if value == "-":
        return None
    return value


def _confirm_related_file_update(description: str) -> bool:
    """Ask whether the files related to the current operation should change."""

    choice = input(f"Update {description}? [Y/n]: ").strip().lower()
    if choice in ("", "y", "yes"):
        return True
    if choice in ("n", "no"):
        return False
    raise ValueError("Please answer y or n")


def _print_written_paths(outputs: dict[str, Path]) -> None:
    for path in outputs.values():
        print(f"Wrote: {path}")


def _write_or_print(text: str, output_path: str | None) -> None:
    """Write the result to a UTF-8 file or print it."""

    if output_path is None:
        print(text)
        return

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"Wrote: {path}")


def _format_brute_force(ciphertext: str) -> str:
    return "\n".join(
        f"Key {key:2d}: {plaintext}" for key, plaintext in brute_force(ciphertext)
    )


def _print_brute_force(ciphertext: str) -> None:
    print(_format_brute_force(ciphertext))


def _print_frequency(text: str) -> None:
    print("Letter | Count | Percent")
    print("----+-------+------")
    for row in frequency_rows(text):
        print(f"{row['letter']:>4} | {row['count']:>5} | {float(row['percentage']):>5.2f}%")


def _format_frequency_csv(text: str) -> str:
    """Format a complete letter-frequency report as CSV text."""

    lines = ["letter,count,frequency,percentage"]
    for row in frequency_rows(text):
        lines.append(
            f"{row['letter']},{row['count']},"
            f"{float(row['frequency']):.8f},"
            f"{float(row['percentage']):.6f}"
        )
    return "\n".join(lines) + "\n"


def _print_ngram(text: str) -> None:
    print("Bigrams:")
    for gram, count in sorted(
        ngram_counts(text, 2).items(), key=lambda item: (-item[1], item[0])
    )[:15]:
        print(f"{gram}: {count}")
    print("\nTrigrams:")
    for gram, count in sorted(
        ngram_counts(text, 3).items(), key=lambda item: (-item[1], item[0])
    )[:15]:
        print(f"{gram}: {count}")


def _print_statistics(text: str) -> None:
    letter_count = sum("A" <= character <= "Z" for character in text.upper())
    print(f"English letter count: {letter_count}")
    print(f"Index of Coincidence: {index_of_coincidence(text):.6f}")
    print(f"Shannon Entropy: {shannon_entropy(text):.6f} bits")


def _choose_crack_method() -> str:
    print("Key recovery method:")
    print("1. Chi-Square (recommended)")
    print("2. Bigrams and trigrams")
    choice = input("Choose a method [1]: ").strip()
    if choice in ("", "1"):
        return "chi-square"
    if choice == "2":
        return "ngram"
    raise ValueError("Please choose 1 or 2")


def _crack(ciphertext: str, method: str) -> dict[str, int | float | str]:
    if method == "chi-square":
        return crack_caesar(ciphertext)
    if method == "ngram":
        return crack_by_ngram(ciphertext)
    raise ValueError("The cracking method must be chi-square or ngram")


def _format_crack_result(result: dict[str, int | float | str]) -> str:
    method_label = "Chi-Square" if result["method"] == "chi-square" else "n-gram"
    return (
        f"Method: {method_label}\n"
        f"Likely key: {result['key']}\n"
        f"Score: {float(result['score']):.4f}\n"
        f"Suggested plaintext:\n{result['plaintext']}"
    )


def _prompt_for_experiment_corpus() -> str:
    """Select direct text, the bundled sample, or another UTF-8 file."""

    print("Experiment input:")
    print("1. Type text in the terminal")
    print("2. Use data/input/english_sample.txt")
    print("3. Read text from another file")
    choice = input("Choose the input source [2]: ").strip()

    if choice == "1":
        return input("Enter the experiment text: ")
    if choice in ("", "2"):
        return _read_text_file("data/input/english_sample.txt")
    if choice == "3":
        return _read_text_file(input("Input file path: "))
    raise ValueError("Please choose 1, 2, or 3")


def _run_interactive_experiments() -> None:
    corpus_text = _prompt_for_experiment_corpus()
    lengths_text = _prompt_with_default(
        "Text lengths (separated by spaces)", "10 20 50 100 200"
    )
    lengths = tuple(int(value) for value in lengths_text.replace(",", " ").split())
    trials = int(_prompt_with_default("Trials for each length", 20))
    runtime_repeats = int(_prompt_with_default("Runtime measurement repeats", 3))
    seed = int(_prompt_with_default("Random seed", 42))
    compare_methods = input("Also compare with the n-gram method? [y/N]: ").strip().lower()

    outputs = run_performance_experiments(
        lengths=lengths,
        trials=trials,
        runtime_repeats=runtime_repeats,
        seed=seed,
        compare_methods=compare_methods in ("y", "yes"),
        corpus_text=corpus_text,
    )
    print("Experiments completed:")
    for name, path in outputs.items():
        if isinstance(path, list):
            for image_path in path:
                print(f"Chart: {image_path}")
        else:
            print(f"{name}: {path}")


def interactive_menu() -> None:
    """Display the interactive menu until the user chooses to exit."""

    os.chdir(PROJECT_DIRECTORY)
    while True:
        print(
            "\n===== Caesar Cipher Project =====\n"
            "1. Encrypt text\n"
            "2. Decrypt with a known key\n"
            "3. Show all 26 possibilities (Brute Force)\n"
            "4. Break the cipher and recover the key\n"
            "5. Analyze letter frequencies\n"
            "6. Analyze bigrams and trigrams\n"
            "7. Calculate IC and Shannon Entropy\n"
            "8. Run success-rate and runtime experiments\n"
            "0. Exit"
        )
        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                plaintext = _prompt_for_text("plaintext")
                key = int(input("Numeric key: "))
                output_path = _prompt_for_output("data/output/ciphertext.txt")
                _write_or_print(encrypt(plaintext, key), output_path)

            elif choice == "2":
                ciphertext = _prompt_for_text("ciphertext")
                key = int(input("Numeric key: "))
                output_path = _prompt_for_output("data/output/decrypted.txt")
                _write_or_print(decrypt(ciphertext, key), output_path)

            elif choice == "3":
                ciphertext = _prompt_for_text("ciphertext")
                output_path = _prompt_for_output("data/output/brute_force.txt")
                _write_or_print(_format_brute_force(ciphertext), output_path)

            elif choice == "4":
                ciphertext = _prompt_for_text("ciphertext")
                result = _crack(ciphertext, _choose_crack_method())
                formatted_result = _format_crack_result(result)
                print(formatted_result)
                output_path = _prompt_for_output("data/output/recovered.txt")
                if output_path is not None:
                    _write_or_print(str(result["plaintext"]), output_path)

            elif choice == "5":
                text = _prompt_for_text("text to analyze")
                _print_frequency(text)
                if _confirm_related_file_update(
                    "letter_frequency.csv and letter_frequency.png"
                ):
                    _print_written_paths(save_frequency_artifacts(text))

            elif choice == "6":
                text = _prompt_for_text("text to analyze")
                _print_ngram(text)
                if _confirm_related_file_update(
                    "bigram_frequency.csv and trigram_frequency.csv"
                ):
                    _print_written_paths(save_ngram_artifacts(text))

            elif choice == "7":
                text = _prompt_for_text("text to analyze")
                _print_statistics(text)
                if _confirm_related_file_update(
                    "statistics.csv and entropy_results.csv"
                ):
                    _print_written_paths(save_statistics_artifacts(text))

            elif choice == "8":
                _run_interactive_experiments()

            elif choice == "0":
                print("Goodbye.")
                return

            else:
                print("Invalid option; enter a number from 0 to 8.")

        except (OSError, TypeError, ValueError, RuntimeError) as error:
            print(f"Error: {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Educational Caesar cipher tool")
    subparsers = parser.add_subparsers(dest="command")

    for command in ("encrypt", "decrypt"):
        command_parser = subparsers.add_parser(command)
        _add_text_source(command_parser)
        command_parser.add_argument("--key", type=int, required=True)
        command_parser.add_argument("--output")

    brute_force_parser = subparsers.add_parser("brute-force")
    _add_text_source(brute_force_parser)
    brute_force_parser.add_argument("--output")

    crack_parser = subparsers.add_parser("crack")
    _add_text_source(crack_parser)
    crack_parser.add_argument(
        "--method", choices=("chi-square", "ngram"), default="chi-square"
    )
    crack_parser.add_argument("--output")

    frequency_parser = subparsers.add_parser("frequency")
    _add_text_source(frequency_parser)
    frequency_parser.add_argument("--output")

    for command in ("ngram", "statistics"):
        command_parser = subparsers.add_parser(command)
        _add_text_source(command_parser)

    experiment_parser = subparsers.add_parser("experiment")
    experiment_parser.add_argument("--lengths", default="10,20,50,100,200,500,1000")
    experiment_parser.add_argument("--trials", type=int, default=100)
    experiment_parser.add_argument("--runtime-repeats", type=int, default=5)
    experiment_parser.add_argument("--seed", type=int, default=42)
    experiment_source = experiment_parser.add_mutually_exclusive_group()
    experiment_source.add_argument(
        "--text", help="experiment text entered directly"
    )
    experiment_source.add_argument(
        "--corpus", type=Path, default=None, help="UTF-8 experiment corpus file"
    )
    experiment_parser.add_argument("--compare-methods", action="store_true")
    return parser


def command_line(argv: list[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        interactive_menu()
        return

    if args.command == "encrypt":
        result = encrypt(_read_text_argument(args.text, args.input), args.key)
        _write_or_print(result, args.output)
    elif args.command == "decrypt":
        result = decrypt(_read_text_argument(args.text, args.input), args.key)
        _write_or_print(result, args.output)
    elif args.command == "brute-force":
        result = _format_brute_force(_read_text_argument(args.text, args.input))
        _write_or_print(result, args.output)
    elif args.command == "crack":
        result = _crack(_read_text_argument(args.text, args.input), args.method)
        print(_format_crack_result(result))
        if args.output is not None:
            _write_or_print(str(result["plaintext"]), args.output)
    elif args.command == "frequency":
        text = _read_text_argument(args.text, args.input)
        if args.output is None:
            _print_frequency(text)
        else:
            _write_or_print(_format_frequency_csv(text), args.output)
    elif args.command == "ngram":
        _print_ngram(_read_text_argument(args.text, args.input))
    elif args.command == "statistics":
        _print_statistics(_read_text_argument(args.text, args.input))
    elif args.command == "experiment":
        try:
            lengths = tuple(
                int(value.strip()) for value in args.lengths.split(",") if value.strip()
            )
            outputs = run_performance_experiments(
                lengths=lengths,
                trials=args.trials,
                runtime_repeats=args.runtime_repeats,
                seed=args.seed,
                corpus_path=args.corpus,
                compare_methods=args.compare_methods,
                corpus_text=args.text,
            )
        except (TypeError, ValueError) as error:
            parser.error(str(error))
        for name, path in outputs.items():
            print(f"{name}: {path}")


if __name__ == "__main__":
    _configure_console()
    command_line(sys.argv[1:])
