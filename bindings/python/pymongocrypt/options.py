from pymongocrypt.compat import unicode_type


class MongoCryptOptions(object):
    def __init__(self, kms_providers, schema_map=None, encrypted_fields_map=None,
                 bypass_query_analysis=False, crypt_shared_lib_path=None,
                 crypt_shared_lib_required=False, bypass_encryption=False):
        """Options for :class:`MongoCrypt`.

        :Parameters:
          - `kms_providers`: Map of KMS provider options. The kms_providers
            map values differ by provider:
              - `aws`: Map with "accessKeyId" and "secretAccessKey" as strings,
                 and optionally a "sessionToken" for temporary credentials.
              - `azure`: Map with "clientId" and "clientSecret" as strings.
              - `gcp`: Map with "email" as a string and "privateKey" as
                a byte array or a base64-encoded string.
              - `kmip`: Map with "endpoint" as a string.
              - `local`: Map with "key" as a 96-byte array or the equivalent
                base64-encoded string.

            KMS providers may be specified with an optional name suffix
            separated by a colon, for example "kmip:name". Named KMS providers
            do not support automatic credential lookup.
          - `schema_map`: Optional map of collection namespace ("db.coll") to
            JSON Schema.  By default, a collection's JSONSchema is periodically
            polled with the listCollections command. But a JSONSchema may be
            specified locally with the schemaMap option.

            Supplying a `schema_map` provides more security than relying on
            JSON Schemas obtained from the server. It protects against a
            malicious server advertising a false JSON Schema, which could trick
            the client into sending unencrypted data that should be encrypted.

            Schemas supplied in the schemaMap only apply to configuring
            automatic encryption for client side encryption. Other validation
            rules in the JSON schema will not be enforced by the driver and
            will result in an error.
          - `encrypted_fields_map`: Optional map encoded to BSON `bytes`.
          - `bypass_query_analysis`: If ``True``, disable automatic analysis of
            outgoing commands. Set `bypass_query_analysis` to use explicit
            encryption on indexed fields without the MongoDB Enterprise Advanced
            licensed crypt_shared library.
          - `crypt_shared_lib_path`: Optional string path to the crypt_shared
            library.
          - `crypt_shared_lib_required`: Whether to require a crypt_shared
            library.
          - `bypass_encryption`: Whether to bypass encryption.

        .. versionadded:: 1.3
           ``crypt_shared_lib_path``, ``crypt_shared_lib_path``,
           ``bypass_encryption`` parameters.

        .. versionadded:: 1.1
           Support for "azure" and "gcp" kms_providers.
           Support for temporary AWS credentials via "sessionToken".

        .. versionchanged:: 1.1
           For kmsProvider "local", the "key" field can now be specified
           as either a 96-byte array or the equivalent base64-encoded string.
        """
        if not isinstance(kms_providers, dict):
            raise ValueError('kms_providers must be a dict')
        if not kms_providers:
            raise ValueError('at least one KMS provider must be configured')

        for name, provider in kms_providers.items():
            # Account for provider names like "local:myname".
            provider_type = name.split(":")[0]
            if provider_type in ('aws', 'gcp', 'azure', 'kmip', 'local'):
                if not isinstance(provider, dict):
                    raise ValueError(f"kms_providers[{name!r}] must be a dict")
            if provider_type == 'aws':
                if len(provider):
                    if "accessKeyId" not in provider or "secretAccessKey" not in provider:
                        raise ValueError(f"kms_providers[{name!r}] must contain "
                                         "'accessKeyId' and 'secretAccessKey'")
            elif provider_type == 'azure':
                if len(provider):
                    if 'clientId' not in provider or 'clientSecret' not in provider:
                        raise ValueError(f"kms_providers[{name!r}] must contain "
                                         "'clientId' and 'clientSecret'")
            elif provider_type == 'gcp':
                if len(provider):
                    if 'email' not in provider or 'privateKey' not in provider:
                        raise ValueError(f"kms_providers[{name!r}] must contain "
                                         "'email' and 'privateKey'")
                    if not isinstance(provider['privateKey'], (bytes, unicode_type)):
                        raise TypeError(f"kms_providers[{name!r}]['privateKey'] must "
                                        "be an instance of bytes or str")
            elif provider_type == 'kmip':
                if 'endpoint' not in provider:
                    raise ValueError(f"kms_providers[{name!r}] must contain 'endpoint'")
                if not isinstance(provider['endpoint'], (str, unicode_type)):
                    raise TypeError(f"kms_providers[{name!r}]['endpoint'] must "
                                    "be an instance of str")
            elif provider_type == 'local':
                if 'key' not in provider:
                    raise ValueError(f"kms_providers[{name!r}] must contain 'key'")
                if not isinstance(provider['key'], (bytes, unicode_type)):
                    raise TypeError(f"kms_providers[{name!r}]['key'] must be an "
                                    "instance of bytes or str")

        if schema_map is not None and not isinstance(schema_map, bytes):
            raise TypeError("schema_map must be bytes or None")

        if encrypted_fields_map is not None and not isinstance(encrypted_fields_map, bytes):
            raise TypeError("encrypted_fields_map must be bytes or None")

        self.kms_providers = kms_providers
        self.schema_map = schema_map
        self.encrypted_fields_map = encrypted_fields_map
        self.bypass_query_analysis = bypass_query_analysis
        self.crypt_shared_lib_path = crypt_shared_lib_path
        self.crypt_shared_lib_required = crypt_shared_lib_required
        self.bypass_encryption = bypass_encryption
