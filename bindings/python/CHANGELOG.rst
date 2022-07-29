Changelog
=========

Changes in Version 1.3.1
------------------------

1.3.1 is a recommended upgrade for all users of 1.3.0.

- Fix a potential data corruption bug in RewrapManyDataKey
  (ClientEncryption.rewrap_many_data_key) when rotating
  encrypted data encryption keys backed by GCP or Azure key services.

  The following conditions will trigger this bug:

  - A GCP-backed or Azure-backed data encryption key being rewrapped requires
    fetching an access token for decryption of the data encryption key.

  The result of this bug is that the key material for all data encryption keys
  being rewrapped is replaced by new randomly generated material, destroying
  the original key material.

  To mitigate potential data corruption, upgrade to this version or higher
  before using RewrapManyDataKey to rotate Azure-backed or GCP-backed data
  encryption keys. A backup of the key vault collection should always be
  taken before key rotation.
- Bundle libmongocrypt 1.5.2 in release wheels.
- **Remove support for libmongocrypt <=1.5.1, libmongocrypt >=1.5.2 is now
  required.** Note this is only relevant for users that install from
  source or use the ``PYMONGOCRYPT_LIB`` environment variable.

Changes in Version 1.3.0
------------------------

- Bundle libmongocrypt 1.5.0 in release wheels.
- Add support for Queryable Encryption with MongoDB 6.0.
- Add support for the crypt_shared library which can be used instead
  of mongocryptd.
- **Remove support for libmongocrypt 1.3, libmongocrypt >=1.5 is now
  required.** Note this is only relevant for users that install from
  source or use the ``PYMONGOCRYPT_LIB`` environment variable.

Changes in Version 1.2.0
------------------------

- Add support for the "kmip" KMS provider.
- Add MongoCryptKmsContext.kms_provider property.
- Bundle libmongocrypt 1.3.0 in release wheels.
- **Remove support for libmongocrypt 1.2, libmongocrypt >=1.3 is now
  required.** Note this is only relevant for users that install from
  source or use the ``PYMONGOCRYPT_LIB`` environment variable.

Changes in Version 1.1.2
------------------------

- Fix a bug where decrypting from a memoryview was not supported.
- Bundle libmongocrypt 1.2.2 in release wheels.

Changes in Version 1.1.1
------------------------

- Bundle libmongocrypt 1.2.1 in release wheels.

Changes in Version 1.1.0
------------------------

- Add support for Azure and GCP KMS providers.
- Add support for temporary AWS credentials via the "sessionToken" option.
- Bundle libmongocrypt 1.2.0 in release wheels.
- **Remove support for libmongocrypt 1.0 and 1.1, libmongocrypt >=1.2
  is now required.** Note this is only relevant for users that install from
  source or use the ``PYMONGOCRYPT_LIB`` environment variable.

Changes in Version 1.0.1
------------------------

- Bundle libmongocrypt 1.0.4 in release wheels.

Changes in Version 1.0.0
------------------------

- The first stable version.
- Bundle libmongocrypt 1.0.0 in release wheels.

Changes in Version 0.1b3
------------------------

- Add support for custom KMS endpoints with the AWS masterkey provider.
- Bundle libmongocrypt 1.0.0 in release wheels.

Changes in Version 0.1b2
------------------------

- Document that pip 19 is required for manylinux2010 wheel installation.
- Bundle libmongocrypt 1.0.0-beta5 in release wheels.

Changes in Version 0.1b1
------------------------

- Make pymongocrypt compatible with manylinux2010 releases.
- Bundle libmongocrypt 1.0.0-beta4 in release wheels.

Changes in Version 0.1b0
------------------------

- Initial Python binding for libmongocrypt.
- Bundle libmongocrypt 1.0.0-beta4 in release wheels.
