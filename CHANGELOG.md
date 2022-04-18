# ChangeLog
## 1.4.0
### New Features
- Support on-demand credentials with `MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` state and `mongocrypt_ctx_provide_kms_providers`.

## 1.4.0-alpha0
### New Features
- Support on-demand AWS credentials with `MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` state and `mongocrypt_ctx_provide_kms_providers`.
### Fixed
- Resolve 32 bit Windows compile errors.

## 1.3.1

### New Features
- Support custom key material through `mongocrypt_ctx_setopt_key_material`.
### Fixed
- Fix deprecation warnings with OpenSSL 3.0.
- Resolve possible symbol conflicts with OpenSSL.

## 1.3.0
- Support "kmip" KMS provider.
- Add mongocrypt_kms_ctx_get_kms_provider.
- Apply default port to endpoints returned in mongocrypt_kms_ctx_endpoint
## 1.2.2
- Fix pkg-config and PPA build dependency on libbson.
- Fix JSON schema caching behavior when server reports no JSON schema.

## 1.2.1
### Fixed
- Fix possible crash when oauth credentials expire.

## 1.2.0
### Added
- Support AWS temporary credentials via session token.

### Fixed
- Add "=" padding to base64url encoding.
## 1.1.0
### Added
- Add ENABLE_PIC cmake option, set to ON by default, so static libraries build with -fPIC by default on relevant systems.

### Fixed
- Errors produced in all crypto callbacks are propagated to user.

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