# Used to generate the test file ./test/data/fle2-aead.cstructs
import os
import itertools
import payloads

AD_lens = [5, 10, 20]
M_lens = [1, 16, 64, 100]

tmpl = """{{
    .testname = "{testname}",
    .iv = "{iv}",
    .associated_data = "{associated_data}",
    .key = "{key}",
    .plaintext = "{plaintext}",
    .ciphertext = "{ciphertext}",
    .bytes_written_expected = {bytes_written_expected}
}},"""

for (AD_len, M_len) in itertools.product (AD_lens, M_lens):
    M = os.urandom (M_len)
    AD = os.urandom (AD_len)
    IV = os.urandom (16)
    Ke = os.urandom (32)
    Km = os.urandom (32)
    C = payloads.fle2_aead_encrypt (M=M, Ke=Ke, IV=IV, Km=Km, AD=AD)

    # Create the 96 byte data encryption key. The last 32 are unused.
    key = Ke + Km + (b"\x00" * 32)
    args = {
        "testname": "generated test. AD length={}, M length={}".format(AD_len, M_len),
        "iv": IV.hex(),
        "associated_data": AD.hex(),
        "key": key.hex(),
        "plaintext": M.hex(),
        "ciphertext": C.hex(),
        "bytes_written_expected": len(C)
    }
    testcase = tmpl.format(**args)
    print (testcase)

    