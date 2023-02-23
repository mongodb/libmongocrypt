# fle2_generate_tests.py is used to generate the test file: ./test/data/roundtrip/fle2-generated.json
import json
import os
import fle2_crypto

# Generate test cases of various and plaintext (M) lengths.
M_lens = [1, 16, 64, 100]
out = []
for M_len in M_lens:
    M = os.urandom(M_len)
    IV = os.urandom(16)
    Ke = os.urandom(32)
    C = fle2_crypto.fle2_encrypt(M=M, Ke=Ke, IV=IV)

    out.append({
      'name': "generated test. M length={}".format (M_len),
      'origin': "etc/fle2_generate_tests.py",
      'algo': 'AES-256-CTR/NONE',
      'iv': IV.hex(),
      'key': Ke.hex(),
      'plaintext': M.hex(),
      'ciphertext': C.hex()
   })

print(json.JSONEncoder(indent=3).encode(out))
