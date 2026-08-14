"""Command-line interface for the Hill cipher project."""

import argparse
import os
import sys


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from src.hill_cipher import decrypt as hill_decrypt
from src.hill_cipher import encrypt as hill_encrypt
from src.hill_cipher import recover_key_and_block_size
from src.hill_cipher import recover_key_from_known_plaintext
from src.experiment import create_performance_report


def add_text_source(parser):
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="text entered directly")
    source.add_argument("--input", help="path to a UTF-8 input file")


def read_text(arguments):
    if arguments.text is not None:
        return arguments.text

    with open(arguments.input, "r", encoding="utf-8") as input_file:
        return input_file.read()


def read_text_value(text, input_path):
    if text is not None:
        return text

    with open(input_path, "r", encoding="utf-8") as input_file:
        return input_file.read()


def write_or_print(text, output_path):
    if output_path is None:
        print(text)
        return

    directory = os.path.dirname(output_path)

    if len(directory) > 0:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        output_file.write(text)

    print("Wrote: " + output_path)


def parse_matrix(text):
    """Converts text such as 3,3;2,5 to a matrix."""

    matrix = []

    for row_text in text.split(";"):
        row = []

        for value in row_text.split(","):
            row.append(int(value.strip()))

        matrix.append(row)

    return matrix


def format_matrix(matrix):
    rows = []

    for row in matrix:
        values = []

        for value in row:
            values.append(str(value))

        rows.append(",".join(values))

    return ";".join(rows)


def prompt_text(name):
    print("1. Type " + name)
    print("2. Read " + name + " from a file")
    choice = input("Choose 1 or 2 [1]: ").strip()

    if choice == "" or choice == "1":
        return input("Enter " + name + ": ")

    if choice == "2":
        default_path = os.path.join("data", "sample_plaintext.txt")

        if "ciphertext" in name.lower():
            default_path = os.path.join("data", "ciphertext.txt")

        path = input("File path [" + default_path + "]: ").strip().strip('"')

        if path == "":
            path = default_path

        with open(path, "r", encoding="utf-8") as input_file:
            return input_file.read()

    raise ValueError("please choose 1 or 2")


def prompt_default(message, default):
    value = input(message + " [" + str(default) + "]: ").strip()

    if value == "":
        return default

    return value


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


def prompt_for_performance_report(plaintext, matrix):
    """Optionally creates CSV and PNG performance reports for this input."""

    choice = input("Generate performance CSV and chart? [y/N]: ").strip().lower()

    if choice == "y" or choice == "yes":
        output_dir = prompt_default("Performance output folder", "output")
        paths = create_performance_report(
            plaintext,
            matrix,
            output_dir
        )

        for path in paths:
            print("Wrote: " + path)


def interactive_main():
    project_directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_directory)

    print("Hill Cipher Project")
    print("1. Hill encrypt")
    print("2. Hill decrypt")
    print("3. Recover Hill key (known plaintext)")
    print("0. Exit")
    choice = input("Choose an option: ").strip()

    try:
        if choice == "1":
            plaintext = prompt_text("plaintext")
            matrix = parse_matrix(prompt_default("Key matrix", "3,3;2,5"))
            output_path = prompt_for_output("data/ciphertext.txt")
            ciphertext = hill_encrypt(plaintext, matrix)
            write_or_print(ciphertext, output_path)
            prompt_for_performance_report(plaintext, matrix)

        elif choice == "2":
            ciphertext = prompt_text("ciphertext")
            matrix = parse_matrix(prompt_default("Key matrix", "3,3;2,5"))
            output_path = prompt_for_output("output/decrypted.txt")
            plaintext = hill_decrypt(ciphertext, matrix)
            write_or_print(plaintext, output_path)
            prompt_for_performance_report(plaintext, matrix)

        elif choice == "3":
            plaintext = prompt_text("known plaintext")
            ciphertext = prompt_text("matching ciphertext")
            block_size, key = recover_key_and_block_size(
                plaintext,
                ciphertext
            )
            print("Detected block size: " + str(block_size) + "x" + str(block_size))
            print("Recovered key matrix: " + format_matrix(key))

        elif choice == "0":
            print("Goodbye.")

        else:
            print("Invalid option.")

    except (OSError, ValueError, RuntimeError) as error:
        print("Error: " + str(error))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Hill cipher and known-plaintext attack"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    hill_encrypt_parser = commands.add_parser("hill-encrypt")
    add_text_source(hill_encrypt_parser)
    hill_encrypt_parser.add_argument("--key-matrix", required=True)
    hill_encrypt_parser.add_argument(
        "--padding",
        choices=["length", "none"],
        default="length"
    )
    hill_encrypt_parser.add_argument("--output")

    hill_decrypt_parser = commands.add_parser("hill-decrypt")
    add_text_source(hill_decrypt_parser)
    hill_decrypt_parser.add_argument("--key-matrix", required=True)
    hill_decrypt_parser.add_argument(
        "--padding",
        choices=["length", "none"],
        default="length"
    )
    hill_decrypt_parser.add_argument("--output")

    hill_attack_parser = commands.add_parser("hill-attack")
    plain_source = hill_attack_parser.add_mutually_exclusive_group(required=True)
    plain_source.add_argument("--plaintext")
    plain_source.add_argument("--plaintext-input")
    cipher_source = hill_attack_parser.add_mutually_exclusive_group(required=True)
    cipher_source.add_argument("--ciphertext")
    cipher_source.add_argument("--ciphertext-input")
    hill_attack_parser.add_argument("--block-size", type=int)

    return parser


def main():
    if len(sys.argv) == 1:
        interactive_main()
        return

    arguments = build_parser().parse_args()

    if arguments.command == "hill-encrypt":
        result = hill_encrypt(
            read_text(arguments),
            parse_matrix(arguments.key_matrix),
            arguments.padding
        )
        write_or_print(result, arguments.output)

    elif arguments.command == "hill-decrypt":
        result = hill_decrypt(
            read_text(arguments),
            parse_matrix(arguments.key_matrix),
            arguments.padding
        )
        write_or_print(result, arguments.output)

    elif arguments.command == "hill-attack":
        plaintext = read_text_value(arguments.plaintext, arguments.plaintext_input)
        ciphertext = read_text_value(
            arguments.ciphertext,
            arguments.ciphertext_input
        )

        if arguments.block_size is None:
            block_size, key = recover_key_and_block_size(
                plaintext,
                ciphertext
            )
            print(
                "Detected block size: "
                + str(block_size)
                + "x"
                + str(block_size)
            )
        else:
            key = recover_key_from_known_plaintext(
                plaintext,
                ciphertext,
                arguments.block_size
            )

        print("Recovered key matrix: " + format_matrix(key))

if __name__ == "__main__":
    main()
