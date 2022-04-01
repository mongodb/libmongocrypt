# fle2_generate_tests.py is used to generate the test file: ./test/data/fle2.cstructs
import os
import fle2_crypto

# Generate test cases of various and plaintext (M) lengths.
M_lens = [1, 16, 64, 100]

tmpl = """{{
    .testname = "{testname}",
    .iv = "{iv}",
    .key = "{key}",
    .plaintext = "{plaintext}",
    .ciphertext = "{ciphertext}",
    .bytes_written_expected = {bytes_written_expected}
}},"""

for M_len in M_lens:
    M = os.urandom(M_len)
    IV = os.urandom(16)
    Ke = os.urandom(32)
    C = fle2_crypto.fle2_encrypt(M=M, Ke=Ke, IV=IV)

    key = Ke
    args = {
        "testname": "generated test. M length={}".format (M_len),
        "iv": IV.hex(),
        "key": key.hex(),
        "plaintext": M.hex(),
        "ciphertext": C.hex(),
        "bytes_written_expected": len(C)
    }
    testcase = tmpl.format(**args)
    print(testcase)
