import unittest
from blind_signature_implementation import BlindSignature

class TestBlindSignature(unittest.TestCase):
    def setUp(self):
        self.bs = BlindSignature()
        self.message = "Hello World"
    
    def test_blind_message(self):
        blinded_message = self.bs.blind_message(self.message)
        self.assertIsNotNone(blinded_message, "Blinded message should not be None")
    
    def test_sign_blinded(self):
        self.bs.blind_message(self.message)
        blind_signature = self.bs.sign_blinded()
        self.assertIsNotNone(blind_signature, "Blind signature should not be None")
    
    def test_unblind(self):
        self.bs.blind_message(self.message)
        self.bs.sign_blinded()
        final_signature = self.bs.unblind()
        self.assertIsNotNone(final_signature, "Final signature should not be None")
    
    def test_verify(self):
        self.bs.blind_message(self.message)
        self.bs.sign_blinded()
        final_signature = self.bs.unblind()
        self.assertTrue(self.bs.verify(self.message, final_signature), "Verification should succeed")

if __name__ == "__main__":
    unittest.main()
