import unittest
import fle2_crypto

class TestCrypto (unittest.TestCase):
    def test_ServerDataEncryptionLevel1Token (self):
        rootKey = bytes.fromhex("6eda88c8496ec990f5d5518dd2ad6f3d9c33b6055904b120f12de82911fbd933")
        expect = bytes.fromhex("d915ccc1eb81687fb5fc5b799f48c99fbe17e7a011a46a48901b9ae3d790656b")
        self.assertEqual (fle2_crypto.ServerDataEncryptionLevel1Token (rootKey), expect)

    def test_fle2_encrypt_decrypt (self):
        IV = bytes.fromhex("918ab83c8966995dfb528a0020d9bb10")
        Ke = bytes.fromhex(
            "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e")
        got_C = fle2_crypto.fle2_encrypt (b"foobar", Ke, IV)
        got_M = fle2_crypto.fle2_decrypt (got_C, Ke)
        self.assertEqual (got_M, b"foobar")


    def test_fle2_aead_encrypt(self):
        AD = bytes.fromhex("99f05406f40d1af74cc737a96c1932fdec90")
        IV = bytes.fromhex("918ab83c8966995dfb528a0020d9bb10")
        Ke = bytes.fromhex(
            "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e")
        Km = bytes.fromhex(
            "50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a")
        M = bytes.fromhex("74657374310a")
        expect_C = bytes.fromhex(
            "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b998387c")
        got_C = fle2_crypto.fle2aead_encrypt(M=M, Ke=Ke, IV=IV, Km=Km, AD=AD)
        self.assertEqual(expect_C, got_C)

    def test_fle2_aead_decrypt(self):
        AD = bytes.fromhex("99f05406f40d1af74cc737a96c1932fdec90")
        Ke = bytes.fromhex(
            "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e")
        Km = bytes.fromhex(
            "50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a")
        expect_M = bytes.fromhex("74657374310a")
        C = bytes.fromhex(
            "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b998387c")
        got_M = fle2_crypto.fle2aead_decrypt(C=C, Km=Km, AD=AD, Ke=Ke)
        self.assertEqual(expect_M, got_M)

        # Test an incorrect HMAC tag.
        C = bytes.fromhex(
            "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b9983800")
        with self.assertRaises(Exception, msg="decryption error"):
            fle2_crypto.fle2aead_decrypt(C=C, Km=Km, AD=AD, Ke=Ke)


if __name__ == "__main__":
    unittest.main()
