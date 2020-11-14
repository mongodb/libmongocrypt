# ChangeLog
## [Unreleased]
### Added
- Add ENABLE_PIC cmake option, set to ON by default, so static libraries build with -fPIC by default on relevant systems.

## 1.1.0-beta1
### Deprecated
- mongocrypt_setopt_kms_provider_aws and mongocrypt_setopt_kms_provider_local are deprecated in favor of the more flexible mongocrypt_setopt_kms_providers, which supports configuration of all KMS providers.
- mongocrypt_ctx_setopt_masterkey_aws, mongocrypt_ctx_setopt_masterkey_aws_endpoint, and mongocrypt_ctx_setopt_masterkey_local are deprecated in favor of the more flexible mongocrypt_ctx_setopt_key_encryption_key, which supports configuration for all KMS providers.
### Added
- Introduces a new crypto hook for signing the JSON Web Token (JWT) for Google Cloud Platform (GCP) requests:
    - mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5
- Introduces a CLI utility `csfle` to test the context state machine against live KMS, mongocryptd, and mongod. See ./test/util/README.md.
- Introduces two new functions to the libmongocrypt API.
    - mongocrypt_setopt_kms_providers
        To set the KMS providers.
    - mongocrypt_ctx_setopt_key_encryption_key
        To set the key encryption key.
- Adds support for Azure and GCP KMS providers.