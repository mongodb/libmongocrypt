# Parameter passing #
Ownership, modifiability, and allocation.

Caller allocates.
    Caller owns, callee only reads.
    - pass a const _mongocrypt_buffer_t*.
    

Callee allocates.
1. Caller wants to pass read-only binary.
2. Caller wants to pass modifiable binary.
3. Caller wants callee to allocate binary on their behalf.
4. Callee wants to return binary.


# Major work #
- Update to latest API specified in driver's spec.
- Add evergreen, and publish built library as artifacts.
- Key requests must batch keys by alias (instead of one filer per key).
- IDL for parsing.
- A real key cache.
- Support keyAltName.

# Minor work #
- Pass custom KMS URL through to kms-message.
- Be more consistent about style (lines between methods, comments, order of function declarations and definitions). Helps readability.
- Add block comments on complex internal functions.