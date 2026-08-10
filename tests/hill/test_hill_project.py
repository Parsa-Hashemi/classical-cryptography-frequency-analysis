import unittest

from src.hill_cipher import decrypt as hill_decrypt
from src.hill_cipher import encrypt as hill_encrypt
from src.hill_cipher import add_length_padding
from src.hill_cipher import inverse_matrix_mod
from src.hill_cipher import remove_length_padding
from src.hill_cipher import recover_key_from_known_plaintext


class HillCipherTests(unittest.TestCase):
    def test_standard_two_by_two_example(self):
        key = [[3, 3], [2, 5]]
        ciphertext = hill_encrypt("HELP", key, padding_mode="none")

        self.assertEqual(ciphertext, "HIAT")
        self.assertEqual(
            hill_decrypt(ciphertext, key, padding_mode="none"),
            "HELP"
        )
        self.assertEqual(inverse_matrix_mod(key), [[15, 17], [20, 9]])

    def test_standard_three_by_three_example(self):
        key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]

        self.assertEqual(
            hill_encrypt("ACT", key, padding_mode="none"),
            "POH"
        )
        self.assertEqual(
            hill_decrypt("POH", key, padding_mode="none"),
            "ACT"
        )

    def test_padding_and_cleaning(self):
        key = [[3, 3], [2, 5]]
        ciphertext = hill_encrypt("Meet at 9!", key)

        self.assertEqual(hill_decrypt(ciphertext, key), "MEETAT")

    def test_length_padding_distinguishes_cat_from_catx(self):
        key = [[3, 3], [2, 5]]
        cat_ciphertext = hill_encrypt("CAT", key)
        catx_ciphertext = hill_encrypt("CATX", key)

        self.assertEqual(add_length_padding("CAT", 2), "CATA")
        self.assertEqual(add_length_padding("CATX", 2), "CATXBB")
        self.assertNotEqual(cat_ciphertext, catx_ciphertext)
        self.assertEqual(hill_decrypt(cat_ciphertext, key), "CAT")
        self.assertEqual(hill_decrypt(catx_ciphertext, key), "CATX")

    def test_invalid_length_padding_is_rejected(self):
        self.assertEqual(remove_length_padding("CATA", 2), "CAT")

        with self.assertRaises(ValueError):
            remove_length_padding("CATB", 2)

    def test_none_mode_rejects_incomplete_plaintext_block(self):
        key = [[3, 3], [2, 5]]

        with self.assertRaises(ValueError):
            hill_encrypt("CAT", key, padding_mode="none")

    def test_invalid_matrix_is_rejected(self):
        with self.assertRaises(ValueError):
            hill_encrypt("TEST", [[2, 4], [2, 4]])

    def test_known_plaintext_attack_recovers_key(self):
        key = [[3, 3], [2, 5]]
        ciphertext = hill_encrypt("HELP", key, padding_mode="none")

        self.assertEqual(
            recover_key_from_known_plaintext("HELP", ciphertext, 2),
            key
        )
if __name__ == "__main__":
    unittest.main()
