import json
import os
import random
import tempfile
import unittest

from src.experiment import run_accuracy_experiment
from src.experiment import save_experiment
from src.substitution_cipher import ENGLISH_ALPHABET
from src.substitution_cipher import PERSIAN_ALPHABET
from src.substitution_cipher import clean_text_en
from src.substitution_cipher import clean_text_fa
from src.substitution_cipher import decrypt_substitution
from src.substitution_cipher import encrypt_substitution
from src.substitution_cipher import generate_random_key
from src.substitution_cipher import key_from_string
from src.substitution_cipher import key_to_string
from src.substitution_cryptanalysis import STD_ENGLISH_FREQ
from src.substitution_cryptanalysis import STD_PERSIAN_FREQ
from src.substitution_cryptanalysis import break_substitution_freq
from src.substitution_cryptanalysis import build_ngram_language_model
from src.substitution_cryptanalysis import calculate_accuracy
from src.text_statistics import calculate_frequencies
from src.text_statistics import compare_shannon_entropies
from src.text_statistics import create_analysis_report
from src.text_statistics import ngram_counts
from src.text_statistics import relative_frequencies
from src.text_statistics import save_entropy_comparison
from src.text_statistics import shannon_entropy


class SubstitutionCipherTests(unittest.TestCase):
    def test_clean_english_text(self):
        self.assertEqual(clean_text_en("Hello, WORLD! 1405"), "helloworld")

    def test_clean_persian_text_standardizes_arabic_letters(self):
        self.assertEqual(clean_text_fa("كتاب ي! ۱۴۰۵"), "کتابی")

    def test_clean_persian_text_merges_alef_forms(self):
        self.assertEqual(clean_text_fa("آ أ إ ا"), "اااا")

    def test_frequency_percentages_and_order(self):
        frequencies, cleaned = calculate_frequencies("Aaa bb c!")
        self.assertEqual(cleaned, "aaabbc")
        self.assertEqual(list(frequencies.keys()), ["a", "b", "c"])
        self.assertAlmostEqual(frequencies["a"], 50.0)
        self.assertAlmostEqual(frequencies["b"], 100 / 3)

    def test_empty_frequency_input(self):
        self.assertEqual(calculate_frequencies("123 !"), ({}, ""))

    def test_english_bigram_and_trigram_counts(self):
        self.assertEqual(
            ngram_counts("Ab, ab!", 2),
            {"ab": 2, "ba": 1}
        )
        self.assertEqual(
            ngram_counts("Ab, ab!", 3),
            {"aba": 1, "bab": 1}
        )

    def test_persian_ngram_counts_use_cleaned_letters(self):
        counts = ngram_counts("سلام، سلام!", 2, is_persian=True)
        self.assertEqual(counts["سل"], 2)
        self.assertEqual(counts["مس"], 1)

    def test_ngram_size_must_be_positive(self):
        with self.assertRaises(ValueError):
            ngram_counts("example", 0)

    def test_ngram_relative_frequencies_sum_to_one_hundred(self):
        frequencies = relative_frequencies({"th": 3, "he": 1})
        self.assertAlmostEqual(sum(frequencies.values()), 100.0)
        self.assertEqual(list(frequencies.keys()), ["th", "he"])

    def test_shannon_entropy_zero_and_maximum_examples(self):
        self.assertEqual(shannon_entropy("aaaaaaaaaa"), 0.0)
        report = compare_shannon_entropies(
            "a" * 26,
            ENGLISH_ALPHABET
        )
        self.assertAlmostEqual(
            report["ciphertext"]["entropy_bits_per_letter"],
            report["maximum_entropy_bits_per_letter"]
        )

    def test_substitution_preserves_shannon_letter_entropy(self):
        key = generate_random_key("en", random.Random(1405))
        plaintext = "A formatted substitution example, with repeated letters!"
        ciphertext = encrypt_substitution(plaintext, key)
        report = compare_shannon_entropies(plaintext, ciphertext)

        self.assertAlmostEqual(
            report["plaintext"]["entropy_bits_per_letter"],
            report["ciphertext"]["entropy_bits_per_letter"]
        )
        self.assertAlmostEqual(report["entropy_difference_bits_per_letter"], 0.0)

    def test_persian_alef_variants_preserve_normalized_entropy(self):
        key = generate_random_key("fa", random.Random(1405))
        plaintext = "آغاز آموزش آسان است، اما ادامه آن تلاش می‌خواهد."
        ciphertext = encrypt_substitution(
            plaintext,
            key,
            is_persian=True
        )
        report = compare_shannon_entropies(
            plaintext,
            ciphertext,
            is_persian=True
        )

        self.assertAlmostEqual(report["entropy_difference_bits_per_letter"], 0.0)

    def test_persian_entropy_uses_thirty_two_letter_alphabet(self):
        report = compare_shannon_entropies(
            PERSIAN_ALPHABET,
            PERSIAN_ALPHABET,
            is_persian=True
        )
        self.assertEqual(report["alphabet_size"], 32)
        self.assertAlmostEqual(report["maximum_entropy_bits_per_letter"], 5.0)

    def test_generated_keys_are_reproducible_permutations(self):
        first = generate_random_key("en", random.Random(1405))
        second = generate_random_key("en", random.Random(1405))
        self.assertEqual(first, second)
        self.assertEqual(set(first.keys()), set(ENGLISH_ALPHABET))
        self.assertEqual(set(first.values()), set(ENGLISH_ALPHABET))

    def test_key_string_round_trip_for_both_languages(self):
        for language, alphabet in [
            ("en", ENGLISH_ALPHABET),
            ("fa", PERSIAN_ALPHABET)
        ]:
            key_text = alphabet[::-1]
            key = key_from_string(key_text, language)
            self.assertEqual(key_to_string(key, language), key_text)

    def test_rejects_invalid_language_and_permutation(self):
        with self.assertRaises(ValueError):
            generate_random_key("de")
        with self.assertRaises(ValueError):
            key_from_string("a" * 26, "en")

    def test_english_encrypt_decrypt_round_trip(self):
        key = key_from_string(ENGLISH_ALPHABET[::-1], "en")
        ciphertext = encrypt_substitution("Hello, World!", key)
        self.assertEqual(ciphertext, "Svool, Dliow!")
        self.assertEqual(decrypt_substitution(ciphertext, key), "Hello, World!")

    def test_preserves_exact_punctuation_positions_and_letter_case(self):
        key = generate_random_key("en", random.Random(1405))
        plaintext = "bgsdfghd.dfgfdhDF"
        ciphertext = encrypt_substitution(plaintext, key)
        decrypted = decrypt_substitution(ciphertext, key)

        self.assertEqual(ciphertext[8], ".")
        self.assertTrue(ciphertext[-1].isupper())
        self.assertTrue(ciphertext[-2].isupper())
        self.assertEqual(decrypted, plaintext)

    def test_persian_encrypt_decrypt_round_trip(self):
        key = key_from_string(PERSIAN_ALPHABET[::-1], "fa")
        plaintext = "سلام دنیا!"
        ciphertext = encrypt_substitution(plaintext, key, is_persian=True)
        self.assertEqual(decrypt_substitution(ciphertext, key), plaintext)

    def test_frequency_attack_on_controlled_distribution(self):
        key = key_from_string(ENGLISH_ALPHABET[::-1], "en")
        plaintext = "e" * 60 + "t" * 50 + "a" * 40 + "o" * 30
        ciphertext = encrypt_substitution(plaintext, key)
        guessed, deduced_key = break_substitution_freq(
            ciphertext,
            STD_ENGLISH_FREQ
        )
        self.assertEqual(guessed, plaintext)
        self.assertEqual(calculate_accuracy(plaintext, guessed), 100.0)
        self.assertEqual(len(deduced_key), 4)

    def test_frequency_attack_preserves_english_formatting(self):
        key = key_from_string(ENGLISH_ALPHABET[::-1], "en")
        plaintext = "E" * 60 + "." + "t" * 50 + "!" + "a" * 40
        ciphertext = encrypt_substitution(plaintext, key)
        guessed, unused_key = break_substitution_freq(
            ciphertext,
            STD_ENGLISH_FREQ
        )
        self.assertEqual(guessed, plaintext)

    def test_ngram_refinement_improves_long_english_attack(self):
        project_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        plaintext_path = os.path.join(
            project_directory,
            "data",
            "sample_plaintext.txt"
        )
        reference_path = os.path.join(
            project_directory,
            "data",
            "english_reference.txt"
        )

        with open(plaintext_path, "r", encoding="utf-8") as plaintext_file:
            plaintext = clean_text_en(plaintext_file.read())[:1200]

        with open(reference_path, "r", encoding="utf-8") as reference_file:
            reference_text = reference_file.read()

        key = generate_random_key("en", random.Random(1405))
        ciphertext = encrypt_substitution(plaintext, key)
        frequency_plaintext, unused_frequency_key = break_substitution_freq(
            ciphertext,
            STD_ENGLISH_FREQ
        )
        ngram_plaintext, unused_ngram_key = break_substitution_freq(
            ciphertext,
            STD_ENGLISH_FREQ,
            ngram_reference_text=reference_text,
            ngram_restarts=2,
            ngram_iterations=1000,
            seed=1405
        )

        frequency_accuracy = calculate_accuracy(plaintext, frequency_plaintext)
        ngram_accuracy = calculate_accuracy(plaintext, ngram_plaintext)
        self.assertGreater(ngram_accuracy, frequency_accuracy)
        self.assertGreaterEqual(ngram_accuracy, 95.0)
        expected_decryption_key = {
            encrypted_character: plaintext_character
            for plaintext_character, encrypted_character in key.items()
        }
        self.assertEqual(unused_ngram_key, expected_decryption_key)

    def test_ngram_model_rejects_short_reference_corpus(self):
        with self.assertRaises(ValueError):
            build_ngram_language_model("too short")

    def test_persian_frequency_attack_without_key(self):
        key = key_from_string(PERSIAN_ALPHABET[::-1], "fa")
        plaintext = "ا" * 60 + "، " + "ی" * 50 + "." + "ر" * 40 + "د" * 30
        ciphertext = encrypt_substitution(plaintext, key, is_persian=True)
        guessed, deduced_key = break_substitution_freq(
            ciphertext,
            STD_PERSIAN_FREQ,
            is_persian=True
        )

        self.assertEqual(guessed, plaintext)
        self.assertEqual(calculate_accuracy(plaintext, guessed), 100.0)
        self.assertEqual(len(deduced_key), 4)

    def test_accuracy_handles_empty_and_partial_results(self):
        self.assertEqual(calculate_accuracy("", ""), 0.0)
        self.assertEqual(calculate_accuracy("abcd", "abxy"), 50.0)

    def test_experiment_is_reproducible(self):
        corpus = ("this is a simple english corpus for frequency analysis " * 20)
        first = run_accuracy_experiment(
            corpus,
            STD_ENGLISH_FREQ,
            lengths=[20, 50],
            seed=1405,
            trials=3
        )
        second = run_accuracy_experiment(
            corpus,
            STD_ENGLISH_FREQ,
            lengths=[20, 50],
            seed=1405,
            trials=3
        )
        self.assertEqual(first, second)
        self.assertEqual([row["text_length"] for row in first], [20, 50])
        self.assertEqual([row["trials"] for row in first], [3, 3])

    def test_experiment_rejects_non_positive_trial_count(self):
        with self.assertRaises(ValueError):
            run_accuracy_experiment(
                "a sufficiently long english corpus" * 10,
                STD_ENGLISH_FREQ,
                lengths=[20],
                trials=0
            )

    def test_reports_and_charts_are_saved_separately(self):
        with tempfile.TemporaryDirectory() as output_dir:
            json_path, frequency_png = create_analysis_report(
                "aaaa bbb cc d",
                output_dir,
                "sample"
            )
            rows = [{
                "text_length": 10,
                "trials": 4,
                "average_accuracy_percent": 25.0,
                "exact_plaintext_successes": 1,
                "exact_plaintext_success_rate": 0.25,
                "exact_key_successes": 1,
                "exact_key_success_rate": 0.25,
                "accuracy_percent": 25.0
            }]
            csv_path, accuracy_png = save_experiment(rows, output_dir)
            entropy_path = save_entropy_comparison(
                compare_shannon_entropies("aaaa", "abcd"),
                os.path.join(output_dir, "entropy.json")
            )

            for path in [
                json_path,
                frequency_png,
                csv_path,
                accuracy_png,
                entropy_path
            ]:
                self.assertTrue(os.path.isfile(path))

            with open(json_path, "r", encoding="utf-8") as json_file:
                report = json.load(json_file)
            self.assertEqual(report["letter_count"], 10)
            self.assertIn("letters", report)
            self.assertIn("bigrams", report)
            self.assertIn("trigrams", report)
            self.assertEqual(report["bigrams"]["counts"]["aa"], 3)


if __name__ == "__main__":
    unittest.main()
