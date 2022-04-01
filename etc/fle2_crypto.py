from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import struct

ENCRYPTION_KEY_LENGTH = 32
MAC_KEY_LENGTH = 32
HMAC_SHA256_TAG_LENGTH = 32
IV_LENGTH = 16
DEK_LENGTH = 96

def _hmacsha256 (Km, input):
    assert (len(Km) == MAC_KEY_LENGTH)
    hm = hmac.HMAC(Km, hashes.SHA256())
    hm.update (input)
    return hm.finalize()

class DEK ():
    """
    Class representing a Data Encryption Key (DEK)
    """
    def __init__ (self, bytesIn):
        assert (len(bytesIn) == DEK_LENGTH)
        self.Ke = bytesIn[0:32]
        self.Km = bytesIn[32:64]
        self.TokenKey = bytesIn[64:96]

def fle2_encrypt (M, Ke, IV):
    """
    Compute 
    S = AES-CTR.Enc(Ke, IV, M)

    Output 
    C = IV || S
    """
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)
    assert (len(IV) == IV_LENGTH)

    # S = AES-CTR.Enc(Ke, IV, M)
    cipher = Cipher(algorithms.AES(Ke), modes.CTR(IV))
    encryptor = cipher.encryptor()
    S = encryptor.update(M) + encryptor.finalize()

    C = IV + S
    return C

def fle2_decrypt (C, Ke):
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)
    assert (len(C) > IV_LENGTH)

    IV = C[0:IV_LENGTH]
    # S = AES-CTR.Enc(Ke, IV, M)
    cipher = Cipher(algorithms.AES(Ke), modes.CTR(IV))
    encryptor = cipher.decryptor()
    M = encryptor.update(C[IV_LENGTH:]) + encryptor.finalize()
    return M

def fle2aead_encrypt(M, Ke, IV, Km, AD):
    """
    Do FLE 2 AEAD encryption.
    See [AEAD with CTR](https://docs.google.com/document/d/1eCU7R8Kjr-mdyz6eKvhNIDVmhyYQcAaLtTfHeK7a_vE/edit#heading=h.35kjadvlcbty)
    See [aead_encryption_fle2_test_vectors.sh](https://github.com/mongodb/mongo/blob/ecc66915ac757cbeaa7c40eb443d7ec7bffcb80a/src/mongo/crypto/scripts/aead_encryption_fle2_test_vectors.sh#L15) for how server team is generating this.
    """
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)
    assert (len(IV) == IV_LENGTH)
    assert (len(Km) == MAC_KEY_LENGTH)

    # S = AES-CTR.Enc(Ke, IV, M)
    cipher = Cipher(algorithms.AES(Ke), modes.CTR(IV))
    encryptor = cipher.encryptor()
    S = encryptor.update(M) + encryptor.finalize()

    # T = HMAC-SHA256(Km, AD || IV || S)
    T = _hmacsha256 (Km, AD + IV + S)

    # C = IV || S || T
    C = IV + S + T
    return C


def fle2aead_decrypt(C, Km, AD, Ke):
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)
    assert (len(C) > HMAC_SHA256_TAG_LENGTH + IV_LENGTH)
    assert (len(Km) == MAC_KEY_LENGTH)

    # Parse C as IV || S || T
    IV = C[0:IV_LENGTH]
    S = C[IV_LENGTH:-HMAC_SHA256_TAG_LENGTH]
    T = C[-HMAC_SHA256_TAG_LENGTH:]

    # Compute T' = HMAC-SHA256(Km, AD || IV || S)
    Tp = _hmacsha256 (Km, AD + IV + S)
    if Tp != T:
        raise Exception("decryption error")

    # Else compute and output M = AES-CTR.Dec(Ke, S)
    cipher = Cipher(algorithms.AES(Ke), modes.CTR(IV))
    decryptor = cipher.decryptor()
    M = decryptor.update(S) + decryptor.finalize()

    return M


def ServerDataEncryptionLevel1Token (rootKey):
    return _hmacsha256 (rootKey, struct.pack("<Q", 3))