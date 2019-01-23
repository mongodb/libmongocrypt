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