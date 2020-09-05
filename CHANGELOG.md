# ChangeLog
## [Unreleased]
### Added
- Introduces a CLI utility `csfle` to test the context state machine against live KMS, mongocryptd, and mongod. See ./test/util/README.md.
- Introduces two new functions to the libmongocrypt API.
    - mongocrypt_setopt_kms_providers
        To set the KMS providers.
    - mongocrypt_ctx_setopt_key_encryption_key
        To set the key encryption key.