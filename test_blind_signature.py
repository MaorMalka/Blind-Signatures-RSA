import unittest
from blind_signature_implementation import SchnorrBlindSignature, RSABlindSignature

MASSAGE = [
    "Short",
    "A bit longer message",
    "Very long message " * 100
]

class TestSchnorrBlindSignature(unittest.TestCase):
    def setUp(self):
        self.schnorr = SchnorrBlindSignature()
        self.message = "Hello, Schnorr!"

    def test_signature_flow(self):
        # שלב 1: יצירת k
        R_x, R_y = self.schnorr.generate_k()
        self.assertIsNotNone(R_x)
        self.assertIsNotNone(R_y)
        # שלב 2: עיוורון ההודעה
        e_prime = self.schnorr.blind_message(self.message)
        self.assertIsInstance(e_prime, int)
        # שלב 3: חתימה על ההודעה המעורפלת
        s_prime = self.schnorr.sign_blinded()
        self.assertIsInstance(s_prime, int)
        # שלב 4: הסרת העיוורון
        final_sig = self.schnorr.unblind()
        self.assertIsInstance(final_sig, int)
        # שלב 5: אימות החתימה
        verified = self.schnorr.verify(self.message)
        self.assertTrue(verified)

    def test_blind_message_without_generate_k(self):
        # קריאה לעיוורון ללא יצירת k – אמורה לזרוק ValueError
        with self.assertRaises(ValueError):
            self.schnorr.blind_message(self.message)

    def test_sign_blinded_without_blinding(self):
        # לאחר יצירת k, אם לא מעווררים את ההודעה – sign_blinded אמורה לזרוק ValueError
        self.schnorr.generate_k()
        with self.assertRaises(ValueError):
            self.schnorr.sign_blinded()

    def test_unblind_without_sign(self):
        # קריאה ל-unblind ללא חתימה – אמורה לזרוק ValueError
        self.schnorr.generate_k()
        self.schnorr.blind_message(self.message)
        with self.assertRaises(ValueError):
            self.schnorr.unblind()

    def test_performance_with_various_message_sizes(self):
        # בדיקה עבור הודעות בגדלים שונים
        for msg in MASSAGE:
            schnorr = SchnorrBlindSignature()
            schnorr.generate_k()
            e_prime = schnorr.blind_message(msg)
            self.assertIsInstance(e_prime, int, f"Failed blinding for message: {msg[:30]}")
            s_prime = schnorr.sign_blinded()
            self.assertIsInstance(s_prime, int, f"Failed signing for message: {msg[:30]}")
            final_sig = schnorr.unblind()
            self.assertIsInstance(final_sig, int, f"Failed unblinding for message: {msg[:30]}")
            verified = schnorr.verify(msg)
            self.assertTrue(verified, f"Verification failed for message: {msg[:30]}")

    def test_verify_with_wrong_signature(self):
        # שינוי קטן בחתימה – האימות אמור להיכשל
        self.schnorr.generate_k()
        self.schnorr.blind_message(self.message)
        self.schnorr.sign_blinded()
        final_sig = self.schnorr.unblind()
        wrong_sig = (final_sig + 1) % self.schnorr.order
        self.schnorr.final_signature = wrong_sig
        verified = self.schnorr.verify(self.message)
        self.assertFalse(verified)


class TestRSABlindSignature(unittest.TestCase):
    def setUp(self):
        self.rsa_scheme = RSABlindSignature()
        self.message = "Hello, RSA!"

    def test_performance_with_various_message_sizes(self):
        for msg in MASSAGE:
            blinded_message = self.rsa_scheme.blind_message(msg)
            self.assertIsInstance(blinded_message, int)
            s_prime = self.rsa_scheme.sign_blinded()
            self.assertIsInstance(s_prime, int)
            final_sig = self.rsa_scheme.unblind()
            self.assertIsInstance(final_sig, int)
            verified = self.rsa_scheme.verify(msg, final_sig)
            self.assertTrue(verified)

    def test_signature_flow(self):
        blinded_message = self.rsa_scheme.blind_message(self.message)
        self.assertIsInstance(blinded_message, int)
        s_prime = self.rsa_scheme.sign_blinded()
        self.assertIsInstance(s_prime, int)
        final_sig = self.rsa_scheme.unblind()
        self.assertIsInstance(final_sig, int)
        verified = self.rsa_scheme.verify(self.message, final_sig)
        self.assertTrue(verified)

    def test_sign_without_blind_message(self):
        with self.assertRaises(ValueError):
            self.rsa_scheme.sign_blinded()

    def test_unblind_without_signature(self):
        self.rsa_scheme.blind_message(self.message)
        with self.assertRaises(ValueError):
            self.rsa_scheme.unblind()

    def test_verify_with_wrong_signature(self):
        self.rsa_scheme.blind_message(self.message)
        self.rsa_scheme.sign_blinded()
        final_sig = self.rsa_scheme.unblind()
        wrong_sig = final_sig + 1
        verified = self.rsa_scheme.verify(self.message, wrong_sig)
        self.assertFalse(verified)

if __name__ == '__main__':
    unittest.main()
