# fle2_aead.py implements the Encrypt and Decrypt primitives in [AEAD with CTR](https://docs.google.com/document/d/1eCU7R8Kjr-mdyz6eKvhNIDVmhyYQcAaLtTfHeK7a_vE/edit#)
# It is only meant for generating test data.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC

ENCRYPTION_KEY_LENGTH = 32
MAC_KEY_LENGTH = 32
HMAC_SHA256_TAG_LENGTH = 32
IV_LENGTH = 16


def encrypt(M, Ke, IV, Km, AD):
    """
    Do FLE 2 AEAD encryption.
    See [AEAD with CTR](https://docs.google.com/document/d/1eCU7R8Kjr-mdyz6eKvhNIDVmhyYQcAaLtTfHeK7a_vE/edit#heading=h.35kjadvlcbty)
    See [aead_encryption_fle2_test_vectors.sh](https://github.com/mongodb/mongo/blob/ecc66915ac757cbeaa7c40eb443d7ec7bffcb80a/src/mongo/crypto/scripts/aead_encryption_fle2_test_vectors.sh#L15) for how server team is generating this.
    """
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)
    assert (len(IV) == IV_LENGTH)
    assert (len(Km) == MAC_KEY_LENGTH)

    # S = AES-CTR.Enc(Ke, IV, M)
    cipher = Cipher(algorithms.AES(Ke), modes.CTR(IV), default_backend())
    encryptor = cipher.encryptor()
    S = encryptor.update(M) + encryptor.finalize()

    # T = HMAC-SHA256(Km, AD || IV || S)
    hmac = HMAC(Km, SHA256(), default_backend())
    hmac.update(AD + IV + S)
    T = hmac.finalize()

    # C = IV || S || T
    C = IV + S + T
    return C


def decrypt(C, Km, AD, Ke):
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)
    assert (len(C) > HMAC_SHA256_TAG_LENGTH + IV_LENGTH)
    assert (len(Km) == MAC_KEY_LENGTH)

    # Parse C as IV || S || T
    IV = C[0:IV_LENGTH]
    S = C[IV_LENGTH:-HMAC_SHA256_TAG_LENGTH]
    T = C[-HMAC_SHA256_TAG_LENGTH:]

    # Compute T' = HMAC-SHA256(Km, AD || IV || S)
    hmac = HMAC(Km, SHA256(), default_backend())
    hmac.update(AD + IV + S)
    Tp = hmac.finalize()
    if Tp != T:
        raise Exception("decryption error")

    # Else compute and output M = AES-CTR.Dec(Ke, S)
    cipher = Cipher(algorithms.AES(Ke), modes.CTR(IV), default_backend())
    decryptor = cipher.decryptor()
    M = decryptor.update(S) + decryptor.finalize()

    return M
