Changelog
=========

Changes in Version 1.2.0
------------------------

- Add MongoCryptKmsContext.kms_provider property.

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
  source or use the ``PYMONGOCRYPT_LIB`` envirnoment variable.

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
