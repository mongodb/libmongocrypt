# payloads_test.py is a self-test of payloads.py.
import unittest
import fle2_aead

class TestFLE2AEAD (unittest.TestCase):
    def test_fle2_aead_encrypt (self):
        AD = bytes.fromhex ("99f05406f40d1af74cc737a96c1932fdec90")
        IV = bytes.fromhex ("918ab83c8966995dfb528a0020d9bb10")
        Ke = bytes.fromhex ("c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e")
        Km = bytes.fromhex ("50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a")
        M = bytes.fromhex ("74657374310a")
        expect_C = bytes.fromhex ("918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b998387c")
        got_C = fle2_aead.encrypt (M=M, Ke=Ke, IV=IV, Km=Km, AD=AD)
        self.assertEqual (expect_C, got_C)

    def test_fle2_aead_decrypt (self):
        AD = bytes.fromhex ("99f05406f40d1af74cc737a96c1932fdec90")
        Ke = bytes.fromhex ("c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e")
        Km = bytes.fromhex ("50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a")
        expect_M = bytes.fromhex ("74657374310a")
        C = bytes.fromhex ("918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b998387c")
        got_M = fle2_aead.decrypt (C=C, Km=Km, AD=AD, Ke=Ke)
        self.assertEqual (expect_M, got_M)

        # Test an incorrect HMAC tag.
        C = bytes.fromhex ("918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b9983800")
        with self.assertRaises (Exception, msg="decryption error"):
            fle2_aead.decrypt (C=C, Km=Km, AD=AD, Ke=Ke)

if __name__ == "__main__":
    unittest.main()