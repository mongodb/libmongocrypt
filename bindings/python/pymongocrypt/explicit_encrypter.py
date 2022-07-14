# Copyright 2019-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pymongocrypt.mongocrypt import MongoCrypt
from pymongocrypt.state_machine import run_state_machine


class ExplicitEncryptOpts(object):
    def __init__(self, algorithm, key_id=None, key_alt_name=None,
                 query_type=None, contention_factor=None):
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

        .. versionchanged:: 1.3
           Added the `query_type` and `contention_factor` parameters.
        """
        self.algorithm = algorithm
        self.key_id = key_id
        self.key_alt_name = key_alt_name
        if query_type is not None:
            if not isinstance(query_type, str):
                raise TypeError(
                    'query_type must be str or None, not: %r' % (type(query_type),))
        self.query_type = query_type
        if contention_factor is not None and not isinstance(contention_factor, int):
            raise TypeError(
                'contention_factor must be an int or None, not: %r' % (type(contention_factor),))
        self.contention_factor = contention_factor


class DataKeyOpts(object):
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


class ExplicitEncrypter(object):
    def __init__(self, callback, mongo_crypt_opts):
        """Encrypts and decrypts BSON values.

        This class is used by a driver to support explicit encryption and
        decryption of individual fields in a BSON document.

        :Parameters:
          - `callback`: A :class:`MongoCryptCallback`.
          - `mongo_crypt_opts`: A :class:`MongoCryptOptions`.
        """
        self.callback = callback
        if mongo_crypt_opts.schema_map is not None:
            raise ValueError("mongo_crypt_opts.schema_map must be None")
        self.mongocrypt = MongoCrypt(mongo_crypt_opts, callback)

    def create_data_key(self, kms_provider, master_key=None,
                        key_alt_names=None, key_material=None):
        """Creates a data key used for explicit encryption.

        :Parameters:
          - `kms_provider`: The KMS provider to use. Supported values are
            "aws", "azure", "gcp", "kmip", and "local".
          - `master_key`: See class:`DataKeyOpts`.
          - `key_alt_names` (optional): An optional list of string alternate
            names used to reference a key. If a key is created with alternate
            names, then encryption may refer to the key by the unique
            alternate name instead of by ``_id``.
          - `key_material`: (optional) See class:`DataKeyOpts`.

        :Returns:
          The _id of the created data key document.
        """
        # CDRIVER-3275 each key_alt_name needs to be wrapped in a bson
        # document.
        encoded_names = []
        if key_alt_names is not None:
            for name in key_alt_names:
                encoded_names.append(
                    self.callback.bson_encode({'keyAltName': name}))

        if key_material is not None:
            key_material = self.callback.bson_encode({'keyMaterial': key_material})

        opts = DataKeyOpts(master_key, encoded_names, key_material)
        with self.mongocrypt.data_key_context(kms_provider, opts) as ctx:
            key = run_state_machine(ctx, self.callback)
        return self.callback.insert_data_key(key)

    def rewrap_many_data_key(self, filter, provider=None, master_key=None):
        """Decrypts and encrypts all matching data keys with a possibly new `master_key` value.

        :Parameters:
          - `filter`: A document used to filter the data keys.
          - `provider`: (optional) The name of a different kms provider.
          - `master_key`: Optional document for the given provider.

        :Returns:
          A binary document with the rewrap data.
        """
        with self.mongocrypt.rewrap_many_data_key_context(filter, provider, master_key) as ctx:
            return run_state_machine(ctx, self.callback)

    def encrypt(self, value, algorithm, key_id=None, key_alt_name=None,
                query_type=None, contention_factor=None):
        """Encrypts a BSON value.

        Note that exactly one of ``key_id`` or  ``key_alt_name`` must be
        provided.

        :Parameters:
          - `value` (bytes): The BSON value to encrypt.
          - `algorithm` (string): The encryption algorithm to use. See
            :class:`Algorithm` for some valid options.
          - `key_id` (bytes): The bytes of the binary subtype 4 ``_id`` data
            key. For example, ``uuid.bytes`` or ``bytes(bson_binary)``.
          - `key_alt_name` (string): Identifies a key vault document by
            'keyAltName'.
          - `query_type` (str): The query type to execute.
          - `contention_factor` (int): The contention factor to use
            when the algorithm is "Indexed".

        :Returns:
          The encrypted BSON value.

        .. versionchanged:: 1.3
           Added the `query_type` and `contention_factor` parameters.
        """
        # CDRIVER-3275 key_alt_name needs to be wrapped in a bson document.
        if key_alt_name is not None:
            key_alt_name = self.callback.bson_encode(
                {'keyAltName': key_alt_name})
        opts = ExplicitEncryptOpts(
            algorithm, key_id, key_alt_name, query_type, contention_factor)
        with self.mongocrypt.explicit_encryption_context(value, opts) as ctx:
            return run_state_machine(ctx, self.callback)

    def decrypt(self, value):
        """Decrypts a BSON value.

        :Parameters:
          - `value`: The encoded document to decrypt, which must be in the
            form { "v" : encrypted BSON value }}.

        :Returns:
          The decrypted BSON value.
        """
        with self.mongocrypt.explicit_decryption_context(value) as ctx:
            return run_state_machine(ctx, self.callback)

    def close(self):
        """Cleanup resources."""
        self.mongocrypt.close()
