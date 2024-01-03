# ChangeLog
## 1.8.4
### Fixed
- Fix `aarch64` packages for RHEL 8, RHEL 9, Amazon 2023, and Amazon 2
## 1.8.3
### Improvements
- Include packages for RHEL 8, RHEL 9, and Amazon 2023
## 1.8.2
### Fixed
- Fix possible leaks in Queryable Encryption in errors on malformed data.
## 1.8.1
- Bypass search index management commands in automatic encryption
## 1.8.0
This release adds stable support of the Queryable Encryption (QE) feature for the "Indexed" and "Unindexed" algorithms.
## 1.8.0-alpha1
This release makes backwards breaking changes to Queryable Encryption (QE) behavior added in the 1.8.0-alpha0 release:
- Do not apply default to min/max values for int/long/date.
- Enable the QEv2 protocol by default. Remove function to enable QEv2.
## 1.8.0-alpha0
### Improvements
- Support Queryable Encryption v2 protocol.
## 1.7.2
### Improvements
- Add toggle for Decimal128 Range Support.
### Fixed
- Fix i686 (32-bit) build.
- Fix 32-bit ARM build.
## 1.7.1
### Improvements
- Vendor Intel DFP library and allow using system DFP.
### Fixed
- Fix possible abort on base64 decode error of KMS messages.
- Fix ILP32-target builds.
- Fix LTO build.
- Fix IntelDFP to not require Git.
## 1.7.0
### New Features
- Add encryptExpression helper
- Support for range index. NOTE: The Range algorithm is experimental only. It is not intended for public use.
## 1.7.0-alpha2
### New Features
- Support range index for decimal128. NOTE: The Range algorithm is experimental only. It is not intended for public use.
## 1.7.0-alpha1
### New Features
- Add encryptExpression helper
## 1.7.0-alpha0
### New Features
- Support range index for int32, int64, double, and date. NOTE: The Range algorithm is experimental only. It is not intended for public use.

## 1.6.2
## Fixed
- Fix build on FreeBSD.
- Set context error state during KMS provider validation.
## 1.6.1
## Fixed
- Fix libbson dependency in pkg-config for PPA.
## 1.6.0
## New Features
- Support accessToken to authenticate with Azure.
## Fixed
- Use correct schema when `collMod` command includes `validator.$jsonSchema`.
## 1.6.0-alpha0
### New Features
- Support accessToken to authenticate with GCP.
### Improvements
- Use CRLF, not LF, for HTTP request newlines.
- Include full body of HTTP errors in `mongocrypt_status_t`.
## 1.5.2
### Fixed
- Fix datakey decryption requiring multiple rounds of KMS requests.
## 1.5.1
## Warnings
- This release has a severe bug in the context returned by `mongocrypt_ctx_rewrap_many_datakey_init` that may result in data corruption. Please upgrade to 1.5.2 before using `mongocrypt_ctx_rewrap_many_datakey_init`.
### New Features
- Update Java bindings to support remaining 1.5.0 API.

## 1.5.0
## Warnings
- This release has a severe bug in the context returned by `mongocrypt_ctx_rewrap_many_datakey_init` that may result in data corruption. Please upgrade to 1.5.2 before using `mongocrypt_ctx_rewrap_many_datakey_init`.
## Fixed
- Update to use new payload for FLE 2.0 find. 
- Require contention factor.
## 1.5.0-rc2
### Fixed
- Fix handling of create command with $jsonSchema.
- Fix leak on encrypt or decrypt error.
## Improved
- Accept string values for QueryType and IndexType.

## 1.4.1
### Fixed
- Add missing MONGOCRYPT_EXPORT to mongocrypt_ctx_provide_kms_providers
## 1.5.0-rc1
## Fixed
- Revert new payload for FLE 2.0 find.
- Do not send "create" and "createIndexes" to mongocryptd when bypassing query analysis.

## 1.5.0-rc0
## Fixed
- Account for shared library rename.
- Update to use new payload for FLE 2.0 find. 

## 1.5.0-alpha2
## New Features
- Fix explain when using csfle shared library.
- Do not bypass "create" or "createIndexes" commands. Support "collMod".
- Bypass "hello", "buildInfo", "getCmdLineOpts", and "getLog" commands.
## Fixed
- Preserve $db in output command.
- Add missing MONGOCRYPT_EXPORT to mongocrypt_ctx_provide_kms_providers
## 1.5.0-alpha1
### Fixed
- Pick a random contention factor on FLE 2.0 insert.

## 1.5.0-alpha0
### New Features
- Support FLE 2.0.
- Support FLE 1.0 Shared Library.
- Support Key Management API.

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
