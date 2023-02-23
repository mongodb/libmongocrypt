from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import struct

ENCRYPTION_KEY_LENGTH = 32
MAC_KEY_LENGTH = 32
HMAC_SHA256_TAG_LENGTH = 32
IV_LENGTH = 16
DEK_LENGTH = 96
BLOCK_LENGTH = 16

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

def _fle2_encrypt (IV, Ke, M, mode, Km = None, AD = None):
    """
    Generalized encrypt vector create.
    S = AES-{mode}.Enc(Ke, IV, M)
    if Km is not None:
        T = HMAC/SHA-256(Km, AD || IV || S)
    C = IV || S || T
    """
    assert len(Ke) == ENCRYPTION_KEY_LENGTH
    assert len(IV) == IV_LENGTH
    assert (mode == 'CTR') or (mode == 'CBC')
    modeObj = modes.CTR(IV) if mode == 'CTR' else modes.CBC(IV)

    # S = AES-{mode}.Env(Ke, IV, M)
    cipher = Cipher(algorithms.AES(Ke), modeObj)
    encryptor = cipher.encryptor()
    if mode == 'CBC':
        # PKCS#7
        padding_len = BLOCK_LENGTH - (len(M) % BLOCK_LENGTH)
        M = M + (padding_len.to_bytes(1, 'big') * padding_len)
    S = encryptor.update(M) + encryptor.finalize()

    if Km is not None:
        assert AD is not None
        assert len(Km) == MAC_KEY_LENGTH
        # T = HMAC-SHA256(Km, AD || IV || S)
        T = _hmacsha256 (Km, AD + IV + S)
    else:
        assert AD is None
        T = b''

    # C = IV + S + T
    C = IV + S + T
    return C


def fle2_encrypt (M, Ke, IV):
    """ AES-256-CTR/NONE """
    return _fle2_encrypt (IV, Ke, M, 'CTR')

def fle2aead_encrypt(M, Ke, IV, Km, AD):
    """ AES-256-CTR/SHA-256 """
    return _fle2_encrypt (IV, Ke, M, 'CTR', Km, AD)

def fle2v2_encrypt(M, Ke, IV, Km, AD):
    """ AES-256-CBC/SHA-256 """
    return _fle2_encrypt (IV, Ke, M, 'CBC', Km, AD)

def _fle2_decypt (C, Ke, mode, Km = None, AD = None):
    assert (len(Ke) == ENCRYPTION_KEY_LENGTH)

    Tlen = 0 if Km is None else HMAC_SHA256_TAG_LENGTH;
    assert (len(C) > (IV_LENGTH + Tlen))
    # C = IV || S || T
    IV = C[0:IV_LENGTH]
    S = C[IV_LENGTH:-Tlen]

    if Km is not None:
        T = C[-Tlen:]
        assert T == _hmacsha256 (Km, AD + IV + S)

    assert (mode == 'CTR') or (mode == 'CBC')
    modeObj = modes.CTR(IV) if mode == 'CTR' else modes.CBC(IV)

    # M = AES-{mode}.Dec(Ke, IV, S)
    cipher = Cipher(algorithms.AES(Ke), modeObj)
    encryptor = cipher.decryptor()
    if mode == 'CBC':
        # PKCS#7
        padding_len = ord(S[-1:])
        S = S[-padding_len:]
    M = encryptor.update(S) + encryptor.finalize()

    return M

def fle2_decrypt (C, Ke):
    """AES-256-CTR/NONE"""
    return _fle2_decrypt (C, Ke, 'CTR')

def fle2aead_decrypt(C, Km, AD, Ke):
    """AES-256-CTR/SHA-256"""
    return _fle2_decrypt (C, Ke, 'CTR', Km, AD)

def fle2v2_decrypt(C, Km, AD, Ke):
    """AES-256-CBC/SHA-256"""
    return _fle2_decrypt (C, Ke, 'CBC', Km, AD)

def ServerDataEncryptionLevel1Token (rootKey):
    return _hmacsha256 (rootKey, struct.pack("<Q", 3))
