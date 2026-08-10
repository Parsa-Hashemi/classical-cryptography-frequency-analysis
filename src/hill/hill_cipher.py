"""Hill cipher and known-plaintext attack using modular arithmetic."""

import itertools
import math

from .utils import is_english_letter


MODULUS = 26


def clean_ascii_letters(text):
    """Returns only English letters in uppercase."""

    letters = []

    for character in text:
        if is_english_letter(character):
            letters.append(character.upper())

    return "".join(letters)


def add_length_padding(text, block_size):
    """Adds self-describing padding; A means 1, B means 2, and so on."""

    if block_size < 1 or block_size > 26:
        raise ValueError("length padding requires a block size from 1 to 26")

    remainder = len(text) % block_size
    padding_count = block_size - remainder
    padding_character = chr(ord("A") + padding_count - 1)
    return text + padding_character * padding_count


def remove_length_padding(text, block_size):
    """Reads the padding length from the last letter, validates it, and removes it."""

    if block_size < 1 or block_size > 26:
        raise ValueError("length padding requires a block size from 1 to 26")

    if len(text) == 0 or len(text) % block_size != 0:
        raise ValueError("padded text must contain complete non-empty blocks")

    padding_count = ord(text[-1]) - ord("A") + 1

    if padding_count < 1 or padding_count > block_size:
        raise ValueError("invalid length padding")

    padding_character = chr(ord("A") + padding_count - 1)
    expected_padding = padding_character * padding_count

    if not text.endswith(expected_padding):
        raise ValueError("invalid length padding")

    return text[:-padding_count]


def extended_gcd(first, second):
    """Computes Bezout coefficients and the greatest common divisor."""

    old_remainder = first
    remainder = second
    old_coefficient = 1
    coefficient = 0

    while remainder != 0:
        quotient = old_remainder // remainder
        old_remainder, remainder = (
            remainder,
            old_remainder - quotient * remainder
        )
        old_coefficient, coefficient = (
            coefficient,
            old_coefficient - quotient * coefficient
        )

    return old_remainder, old_coefficient


def modular_inverse(number, modulus=MODULUS):
    """Finds the multiplicative inverse of number for the given modulus."""

    number = number % modulus
    greatest_common_divisor, coefficient = extended_gcd(number, modulus)

    if greatest_common_divisor != 1:
        raise ValueError(
            str(number) + " has no multiplicative inverse modulo "
            + str(modulus)
        )

    return coefficient % modulus


def matrix_minor(matrix, removed_row, removed_column):
    """Builds the minor matrix by removing one row and one column."""

    result = []

    for row_index in range(len(matrix)):
        if row_index != removed_row:
            row = []

            for column_index in range(len(matrix)):
                if column_index != removed_column:
                    row.append(matrix[row_index][column_index])

            result.append(row)

    return result


def determinant(matrix):
    """Computes the determinant of a square matrix using Laplace expansion."""

    size = len(matrix)

    if size == 1:
        return matrix[0][0]

    if size == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

    value = 0

    for column in range(size):
        sign = 1
        if column % 2 == 1:
            sign = -1

        cofactor = determinant(matrix_minor(matrix, 0, column))
        value = value + sign * matrix[0][column] * cofactor

    return value


def validate_key_matrix(key_matrix):
    """Checks that the key matrix is square and invertible modulo 26."""

    if not isinstance(key_matrix, list) or len(key_matrix) == 0:
        raise ValueError("key matrix must be a non-empty square matrix")

    size = len(key_matrix)
    normalized = []

    for row in key_matrix:
        if not isinstance(row, list) or len(row) != size:
            raise ValueError("key matrix must be square")

        normalized_row = []
        for value in row:
            if not isinstance(value, int):
                raise ValueError("every key matrix entry must be an integer")
            normalized_row.append(value % MODULUS)

        normalized.append(normalized_row)

    determinant_value = determinant(normalized)

    if math.gcd(determinant_value, MODULUS) != 1:
        raise ValueError(
            "key matrix is not invertible modulo 26; "
            "gcd(det(K), 26) must be 1"
        )

    return normalized


def inverse_matrix_mod(key_matrix):
    """Computes the inverse matrix K^(-1) modulo 26."""

    matrix = validate_key_matrix(key_matrix)
    size = len(matrix)

    if size == 1:
        return [[modular_inverse(matrix[0][0])]]

    determinant_inverse = modular_inverse(determinant(matrix))
    inverse = []

    for row in range(size):
        inverse_row = []

        for column in range(size):
            # Swapping row and column transposes the cofactor matrix.
            sign = 1
            if (row + column) % 2 == 1:
                sign = -1

            minor = matrix_minor(matrix, column, row)
            cofactor = sign * determinant(minor)
            value = determinant_inverse * cofactor
            inverse_row.append(value % MODULUS)

        inverse.append(inverse_row)

    return inverse


def multiply_matrix_vector(matrix, vector):
    """Multiplies a matrix by a column vector modulo 26."""

    result = []

    for row in matrix:
        total = 0

        for index in range(len(vector)):
            total = total + row[index] * vector[index]

        result.append(total % MODULUS)

    return result


def multiply_matrices(left, right):
    """Multiplies two compatible matrices modulo 26."""

    size = len(left)
    result = []

    for row in range(size):
        result_row = []

        for column in range(size):
            total = 0

            for index in range(size):
                total = total + left[row][index] * right[index][column]

            result_row.append(total % MODULUS)

        result.append(result_row)

    return result


def transform_blocks(text, matrix):
    """Multiplies letter blocks by the matrix."""

    size = len(matrix)
    transformed = []

    for start in range(0, len(text), size):
        block = text[start:start + size]
        vector = []

        for character in block:
            vector.append(ord(character) - ord("A"))

        result_vector = multiply_matrix_vector(matrix, vector)

        for value in result_vector:
            transformed.append(chr(ord("A") + value))

    return "".join(transformed)


def encrypt(plaintext, key_matrix, padding_mode="length"):
    """Encrypts text with length padding or without padding."""

    matrix = validate_key_matrix(key_matrix)
    letters = clean_ascii_letters(plaintext)

    if padding_mode == "length":
        letters = add_length_padding(letters, len(matrix))
    elif padding_mode == "none":
        if len(letters) % len(matrix) != 0:
            raise ValueError(
                "plaintext length must be a multiple of the block size "
                "when padding_mode is none"
            )
    else:
        raise ValueError("padding_mode must be length or none")

    return transform_blocks(letters, matrix)


def decrypt(ciphertext, key_matrix, padding_mode="length"):
    """Decrypts Hill ciphertext and removes padding in length mode."""

    matrix = validate_key_matrix(key_matrix)
    letters = clean_ascii_letters(ciphertext)

    if len(letters) % len(matrix) != 0:
        raise ValueError("ciphertext length must be a multiple of the block size")

    inverse = inverse_matrix_mod(matrix)
    plaintext = transform_blocks(letters, inverse)

    if padding_mode == "length":
        plaintext = remove_length_padding(plaintext, len(matrix))
    elif padding_mode != "none":
        raise ValueError("padding_mode must be length or none")

    return plaintext


def blocks_as_column_matrix(blocks, selected_indexes, block_size):
    """Places each selected block as a matrix column."""

    matrix = []

    for row in range(block_size):
        matrix_row = []

        for block_index in selected_indexes:
            character = blocks[block_index][row]
            matrix_row.append(ord(character) - ord("A"))

        matrix.append(matrix_row)

    return matrix


def recover_key_from_known_plaintext(plaintext, ciphertext, block_size):
    """Recovers a Hill key from matching plaintext and ciphertext blocks."""

    if block_size < 1:
        raise ValueError("block_size must be positive")

    plain_letters = clean_ascii_letters(plaintext)
    cipher_letters = clean_ascii_letters(ciphertext)
    usable_length = min(len(plain_letters), len(cipher_letters))
    usable_length = usable_length - usable_length % block_size
    plain_letters = plain_letters[:usable_length]
    cipher_letters = cipher_letters[:usable_length]

    block_count = usable_length // block_size

    if block_count < block_size:
        raise ValueError(
            "known plaintext attack needs at least block_size aligned blocks"
        )

    plain_blocks = []
    cipher_blocks = []

    for start in range(0, usable_length, block_size):
        plain_blocks.append(plain_letters[start:start + block_size])
        cipher_blocks.append(cipher_letters[start:start + block_size])

    indexes = range(block_count)

    for selected_indexes in itertools.combinations(indexes, block_size):
        plain_matrix = blocks_as_column_matrix(
            plain_blocks,
            selected_indexes,
            block_size
        )

        if math.gcd(determinant(plain_matrix), MODULUS) != 1:
            continue

        cipher_matrix = blocks_as_column_matrix(
            cipher_blocks,
            selected_indexes,
            block_size
        )
        plain_inverse = inverse_matrix_mod(plain_matrix)
        candidate_key = multiply_matrices(cipher_matrix, plain_inverse)

        candidate_ciphertext = encrypt(
            plain_letters,
            candidate_key,
            padding_mode="none"
        )

        if candidate_ciphertext[:usable_length] == cipher_letters:
            return candidate_key

    raise ValueError(
        "no invertible set of plaintext blocks was found; "
        "provide more aligned known plaintext"
    )
