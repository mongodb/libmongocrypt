from pymongocrypt.compat import unicode_type


class MongoCryptOptions:
    def __init__(
        self,
        kms_providers,
        schema_map=None,
        encrypted_fields_map=None,
        bypass_query_analysis=False,
        crypt_shared_lib_path=None,
        crypt_shared_lib_required=False,
        bypass_encryption=False,
        key_expiration_ms=None,
        enable_multiple_collinfo=False,
    ):
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
          - `key_expiration_ms` (int): The cache expiration time for data
            encryption keys. Defaults to 60000. 0 means keys never expire.

        .. versionadded:: 1.13
           Added the ``key_expiration_ms`` parameter.

        .. versionremoved:: 1.11
           Removed the ``enable_range_v2`` parameter.

        .. versionadded:: 1.10
           Added the ``enable_range_v2`` parameter.

        .. versionadded:: 1.3
           Added the ``crypt_shared_lib_path``, ``crypt_shared_lib_path``, and
           ``bypass_encryption`` parameters.

        .. versionadded:: 1.1
           Support for "azure" and "gcp" kms_providers.
           Support for temporary AWS credentials via "sessionToken".

        .. versionchanged:: 1.1
           For kmsProvider "local", the "key" field can now be specified
           as either a 96-byte array or the equivalent base64-encoded string.
        """
        if not isinstance(kms_providers, dict):
            raise ValueError("kms_providers must be a dict")
        if not kms_providers:
            raise ValueError("at least one KMS provider must be configured")

        for name, provider in kms_providers.items():
            # Account for provider names like "local:myname".
            provider_type = name.split(":")[0]
            if provider_type in ("aws", "gcp", "azure", "kmip", "local"):
                if not isinstance(provider, dict):
                    raise ValueError(f"kms_providers[{name!r}] must be a dict")
            if provider_type == "aws":
                if len(provider):
                    if (
                        "accessKeyId" not in provider
                        or "secretAccessKey" not in provider
                    ):
                        raise ValueError(
                            f"kms_providers[{name!r}] must contain "
                            "'accessKeyId' and 'secretAccessKey'"
                        )
            elif provider_type == "azure":
                if len(provider):
                    if "clientId" not in provider or "clientSecret" not in provider:
                        raise ValueError(
                            f"kms_providers[{name!r}] must contain "
                            "'clientId' and 'clientSecret'"
                        )
            elif provider_type == "gcp":
                if len(provider):
                    if "email" not in provider or "privateKey" not in provider:
                        raise ValueError(
                            f"kms_providers[{name!r}] must contain "
                            "'email' and 'privateKey'"
                        )
                    if not isinstance(provider["privateKey"], (bytes, unicode_type)):
                        raise TypeError(
                            f"kms_providers[{name!r}]['privateKey'] must "
                            "be an instance of bytes or str"
                        )
            elif provider_type == "kmip":
                if "endpoint" not in provider:
                    raise ValueError(f"kms_providers[{name!r}] must contain 'endpoint'")
                if not isinstance(provider["endpoint"], (str, unicode_type)):
                    raise TypeError(
                        f"kms_providers[{name!r}]['endpoint'] must "
                        "be an instance of str"
                    )
            elif provider_type == "local":
                if "key" not in provider:
                    raise ValueError(f"kms_providers[{name!r}] must contain 'key'")
                if not isinstance(provider["key"], (bytes, unicode_type)):
                    raise TypeError(
                        f"kms_providers[{name!r}]['key'] must be an "
                        "instance of bytes or str"
                    )

        if schema_map is not None and not isinstance(schema_map, bytes):
            raise TypeError("schema_map must be bytes or None")

        if encrypted_fields_map is not None and not isinstance(
            encrypted_fields_map, bytes
        ):
            raise TypeError("encrypted_fields_map must be bytes or None")
        if key_expiration_ms is not None:
            if not isinstance(key_expiration_ms, int):
                raise TypeError("key_expiration_ms must be int or None")
            if key_expiration_ms < 0:
                raise ValueError("key_expiration_ms must be >=0 or None")

        self.kms_providers = kms_providers
        self.schema_map = schema_map
        self.encrypted_fields_map = encrypted_fields_map
        self.bypass_query_analysis = bypass_query_analysis
        self.crypt_shared_lib_path = crypt_shared_lib_path
        self.crypt_shared_lib_required = crypt_shared_lib_required
        self.bypass_encryption = bypass_encryption
        self.key_expiration_ms = key_expiration_ms
        self.enable_multiple_collinfo = enable_multiple_collinfo


class ExplicitEncryptOpts:
    def __init__(
        self,
        algorithm,
        key_id=None,
        key_alt_name=None,
        query_type=None,
        contention_factor=None,
        range_opts=None,
        is_expression=False,
    ):
        """Options for explicit encryption.

        :Parameters:
          - `algorithm` (str): The algorithm to use.
          - `key_id`: The data key _id.
          - `key_alt_name` (bytes): Identifies a key vault document by
            'keyAltName'. Must be BSON encoded document in the form:
            { "keyAltName" : (BSON UTF8 value) }
          - `query_type` (str): The query type to execute.
          - `contention_factor` (int): The contention factor to use
            when the algorithm is "Indexed".
          - `range_opts` (bytes): Options for explicit encryption
            with the "range" algorithm encoded as a BSON document.
          - `is_expression` (boolean): True if this is an encryptExpression()
            context. Defaults to False.

        .. versionchanged:: 1.3
           Added the `query_type` and `contention_factor` parameters.
        .. versionchanged:: 1.5
           Added the `range_opts` and `is_expression` parameters.
        """
        self.algorithm = algorithm
        self.key_id = key_id
        self.key_alt_name = key_alt_name
        if query_type is not None:
            if not isinstance(query_type, str):
                raise TypeError(
                    f"query_type must be str or None, not: {type(query_type)}"
                )
        self.query_type = query_type
        if contention_factor is not None and not isinstance(contention_factor, int):
            raise TypeError(
                f"contention_factor must be an int or None, not: {type(contention_factor)}"
            )
        self.contention_factor = contention_factor
        if range_opts is not None and not isinstance(range_opts, bytes):
            raise TypeError(
                f"range_opts must be an bytes or None, not: {type(range_opts)}"
            )
        self.range_opts = range_opts
        self.is_expression = is_expression


class DataKeyOpts:
    def __init__(self, master_key=None, key_alt_names=None, key_material=None):
        """Options for creating encryption keys.

        :Parameters:
          - `master_key`: Identifies a KMS-specific key used to encrypt the
            new data key. If the kmsProvider is "local" the `master_key` is
            not applicable and may be omitted.

            If the `kms_provider` is "aws" it is required and has the
            following fields::

              - `region` (string): Required. The AWS region, e.g. "us-east-1".
              - `key` (string): Required. The Amazon Resource Name (ARN) to
                 the AWS customer.
              - `endpoint` (string): Optional. An alternate host to send KMS
                requests to. May include port number, e.g.
                "kms.us-east-1.amazonaws.com:443".

            If the `kms_provider` is "azure" it is required and has the
            following fields::

              - `keyVaultEndpoint` (string): Required. Host with optional
                 port, e.g. "example.vault.azure.net".
              - `keyName` (string): Required. Key name in the key vault.
              - `keyVersion` (string): Optional. Version of the key to use.

            If the `kms_provider` is "gcp" it is required and has the
            following fields::

              - `projectId` (string): Required. The Google cloud project ID.
              - `location` (string): Required. The GCP location, e.g. "us-east1".
              - `keyRing` (string): Required. Name of the key ring that contains
                the key to use.
              - `keyName` (string): Required. Name of the key to use.
              - `keyVersion` (string): Optional. Version of the key to use.
              - `endpoint` (string): Optional. Host with optional port.
                Defaults to "cloudkms.googleapis.com".

            If the `kms_provider` is "kmip" it is optional and has the
            following fields::

              - `keyId` (string): Optional. `keyId` is the KMIP Unique
                Identifier to a 96 byte KMIP Secret Data managed object. If
                keyId is omitted, the driver creates a random 96 byte KMIP
                Secret Data managed object.
              - `endpoint` (string): Optional. Host with optional
                 port, e.g. "example.vault.azure.net:".

          - `key_alt_names`: An optional list of bytes suitable to be passed to
            mongocrypt_ctx_setopt_key_alt_name. Each element must be BSON
            encoded document in the form: { "keyAltName" : (BSON UTF8 value) }

          - `key_material`: An optional binary value of 96 bytes to use as
            custom key material for the data key being created. If
            ``key_material`` is given, the custom key material is used for
            encrypting and decrypting data. Otherwise, the key material for the
            new data key is generated from a cryptographically secure random
            device.
        """
        self.master_key = master_key
        self.key_alt_names = key_alt_names
        self.key_material = key_material
