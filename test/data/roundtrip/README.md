# Roundtrip crypto test cases

Each file is a JSON array containing a set of documents with the following fields:

* `name` (required): This is a symbolic field used for identifying a failing test case in logs.
* `algo` (required): The name of the cipher and hmac to use during crypto operations. One of:
   * `AES-256-CBC/SHA-512-256` aka `FLE1`
   * `AES-256-CTR/SHA-256` aka `FLE2` with AEAD
   * `AES-256-CTR/NONE` aka `FLE2` with no MAC
* `key` (required): Either 32 or 96 octets of key material expressed as hexits
* `iv` (required): 16 octets of inintialization vector expressed as hexits
* `aad` (optional if MAC is NONE, otherwise required): Associated Data as hexits
* `plaintext` (required): Hexits representing data to encrypt.
* `ciphertext` (required): The expected ciphertext as hexits produced by the operation.
* `ignore_ciphertext_mismatch_on_encrypt` (optional): True if the encryption operation is expected to produce something other than the contents of `ciphertext`.  This is useful when focusing on the decrypt operation, such as in [`fle2aead-decrypt.json`](fle2aead-decrypt.json).
* `encrypt_error` (optional): An error message to expect when attempting to encrypt.
* `decrypt_error` (optional): An error message to expect when attempting to decrypt.
