import os
import random
import unittest
from unittest.mock import patch

from main import break_ciphertext
from main import default_experiment_lengths
from main import default_ngram_reference_path
from main import default_sample_plaintext_path
from main import prompt_for_text
from main import read_ngram_reference
from src.hill_climbing import hill_climbing_attack
from src.simulated_annealing import simulated_annealing_attack
from src.substitution_cipher import ENGLISH_ALPHABET
from src.substitution_cipher import encrypt_substitution
from src.substitution_cipher import generate_random_key


class SearchAttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_directory = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        reference_path = os.path.join(
            project_directory,
            "data",
            "english_reference.txt"
        )

        with open(reference_path, "r", encoding="utf-8") as reference_file:
            cls.reference_text = reference_file.read()

        cls.ciphertext = encrypt_substitution(
            "A short, readable example for testing substitution attacks!",
            generate_random_key("en", random.Random(1405))
        )

    def check_result(self, attack):
        plaintext, key = attack(
            self.ciphertext,
            self.reference_text,
            iterations=10,
            restarts=1,
            seed=1405
        )

        self.assertEqual(len(plaintext), len(self.ciphertext))
        self.assertEqual(plaintext[-1], "!")
        self.assertEqual(set(key.keys()), set(ENGLISH_ALPHABET))
        self.assertEqual(set(key.values()), set(ENGLISH_ALPHABET))

    def test_hill_climbing_returns_complete_result(self):
        self.check_result(hill_climbing_attack)

    def test_simulated_annealing_returns_complete_result(self):
        self.check_result(simulated_annealing_attack)

    def test_persian_ngram_corpus_is_available_by_default(self):
        self.assertEqual(
            default_ngram_reference_path("fa"),
            "data/persian_reference.txt"
        )
        self.assertGreater(len(read_ngram_reference("fa")), 100)

    def test_persian_sample_and_lengths_are_selected_by_default(self):
        self.assertEqual(
            default_sample_plaintext_path("fa"),
            "data/sample_plaintext_fa.txt"
        )
        self.assertEqual(
            default_experiment_lengths("fa"),
            [200, 500, 1200, 3000, 5000]
        )

    def test_main_dispatches_all_three_breaking_algorithms(self):
        for algorithm in [
            "frequency",
            "hill-climbing",
            "simulated-annealing"
        ]:
            plaintext, key = break_ciphertext(
                self.ciphertext,
                "en",
                algorithm,
                restarts=1,
                iterations=10,
                seed=1405
            )
            self.assertEqual(len(plaintext), len(self.ciphertext))
            self.assertGreater(len(key), 0)

    def test_main_rejects_unknown_breaking_algorithm(self):
        with self.assertRaises(ValueError):
            break_ciphertext(self.ciphertext, "en", "unknown")

    def test_typed_file_path_is_read_as_file_content(self):
        with patch(
            "builtins.input",
            side_effect=["", "data/sample_plaintext.txt"]
        ):
            text = prompt_for_text("plaintext")

        self.assertIn("Learning mathematics", text)
        self.assertGreater(len(text), 1000)

    def test_missing_txt_suffix_is_completed_automatically(self):
        with patch(
            "builtins.input",
            side_effect=["1", "data/sample_plaintext"]
        ):
            text = prompt_for_text("plaintext")

        self.assertIn("Learning mathematics", text)

    def test_english_sample_is_the_default_encryption_input(self):
        with patch("builtins.input", side_effect=["", ""]):
            text = prompt_for_text(
                "plaintext",
                "data/sample_plaintext.txt"
            )

        self.assertEqual(len(text), 11568)


if __name__ == "__main__":
    unittest.main()
