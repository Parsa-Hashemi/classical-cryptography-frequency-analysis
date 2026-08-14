import unittest

from src.experiment import plaintext_letter_accuracy
from src.text_statistics import compare_shannon_entropies
from src.text_statistics import shannon_entropy
from src.vigenere_cipher import decrypt
from src.vigenere_cipher import encrypt
from src.vigenere_cryptanalysis import break_vigenere
from src.vigenere_cryptanalysis import index_of_coincidence
from src.vigenere_cryptanalysis import rank_key_lengths
from src.vigenere_cryptanalysis import recover_key


LONG_PLAINTEXT = """
Cryptanalysis uses mathematical patterns in language to recover information
about a hidden message. The Vigenere cipher repeats a short key, so letters at
the same position in every key period are encrypted by the same Caesar shift.
If enough ciphertext is available, each column has a frequency distribution
similar to ordinary English. The index of coincidence estimates the period and
a chi square test identifies the most likely shift in every column. Reliable
experiments use several message lengths and report both successful and failed
trials. Clear code, reproducible tests, and careful statistical explanations
make the result easier to verify and understand. This paragraph is repeated to
provide enough natural language for a stable demonstration of the attack.
""" * 8


class VigenereCipherTests(unittest.TestCase):
    def test_plaintext_letter_accuracy_supports_partial_recovery(self):
        self.assertEqual(plaintext_letter_accuracy("ABCD", "ABXY"), 0.5)
        self.assertEqual(plaintext_letter_accuracy("", ""), 0.0)

    def test_shannon_entropy_is_zero_for_one_repeated_letter(self):
        self.assertEqual(shannon_entropy("AAAAAAAAAA"), 0.0)

    def test_entropy_comparison_reports_both_texts_and_difference(self):
        plaintext = "A" * 26
        ciphertext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        report = compare_shannon_entropies(plaintext, ciphertext)

        self.assertEqual(report["plaintext"]["entropy_bits_per_letter"], 0.0)
        self.assertAlmostEqual(
            report["ciphertext"]["entropy_bits_per_letter"],
            report["maximum_entropy_bits_per_letter"]
        )
        self.assertAlmostEqual(
            report["entropy_difference_bits_per_letter"],
            report["ciphertext"]["entropy_bits_per_letter"]
        )

    def test_standard_example(self):
        encrypted = encrypt("ATTACKATDAWN", "LEMON")
        self.assertEqual(encrypted, "LXFOPVEFRNHR")

        decrypted = decrypt("LXFOPVEFRNHR", "LEMON")
        self.assertEqual(decrypted, "ATTACKATDAWN")

    def test_preserves_case_spaces_punctuation_and_non_ascii_text(self):
        plaintext = "Attack at dawn! 世界 1405"
        ciphertext = encrypt(plaintext, "LEMON")
        decrypted = decrypt(ciphertext, "LEMON")

        self.assertEqual(decrypted, plaintext)
        self.assertIn("世界 1405", ciphertext)

    def test_rejects_invalid_keys(self):
        invalid_keys = ["", "A B", "KEY2", "KÉY"]

        for key in invalid_keys:
            with self.assertRaises(ValueError):
                encrypt("hello", key)

    def test_ic_is_higher_for_english_than_uniform_alphabet(self):
        english = "THISISALONGERENGLISHTEXTWITHREPEATEDLETTERFREQUENCIES" * 10
        uniform = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 20

        english_ic = index_of_coincidence(english)
        uniform_ic = index_of_coincidence(uniform)
        self.assertGreater(english_ic, uniform_ic)

    def test_known_length_key_recovery(self):
        ciphertext = encrypt(LONG_PLAINTEXT, "MATH")
        recovered_key = recover_key(ciphertext, 4)
        self.assertEqual(recovered_key, "MATH")

    def test_unknown_key_attack(self):
        ciphertext = encrypt(LONG_PLAINTEXT, "LOGIC")
        result = break_vigenere(ciphertext, 12)

        self.assertEqual(result["key"], "LOGIC")
        self.assertEqual(result["plaintext"], LONG_PLAINTEXT)

    def test_true_length_is_among_top_ic_candidates(self):
        ciphertext = encrypt(LONG_PLAINTEXT, "GRAPH")
        ranking = rank_key_lengths(ciphertext, 12)
        top_lengths = []

        for item in ranking[:4]:
            top_lengths.append(item["length"])

        self.assertIn(5, top_lengths)


if __name__ == "__main__":
    unittest.main()
