# fle2_aead_generate_tests.py is used to generate the test file: ./test/data/roundtrip/fle2aead-generated.json
import json
import os
import itertools
import fle2_crypto

# Generate test cases by taking the cross-product of AD (associated data) and plaintext (M) lengths.
AD_lens = [5, 10, 20]
M_lens = [1, 16, 64, 100]
out = []
for (AD_len, M_len) in itertools.product(AD_lens, M_lens):
    M = os.urandom(M_len)
    AD = os.urandom(AD_len)
    IV = os.urandom(16)
    Ke = os.urandom(32)
    Km = os.urandom(32)
    C = fle2_crypto.fle2aead_encrypt(M=M, Ke=Ke, IV=IV, Km=Km, AD=AD)

    # Create the 96 byte data encryption key. The last 32 are unused.
    key = Ke + Km + (b"\x00" * 32)
    out.append({
      'name': "generated test. AD length={}, M length={}".format(AD_len, M_len),
      'origin': "etc/fle2_aead_generate_tests.py",
      'algo': 'AES-256-CTR/SHA-256',
      'iv': IV.hex(),
      'aad': AD.hex(),
      'key': key.hex(),
      'plaintext': M.hex(),
      'ciphertext': C.hex()
   })

print(json.JSONEncoder(indent=3).encode(out))
