# Copyright 2024-present MongoDB, Inc.
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

from pymongocrypt.asynchronous.state_machine import run_state_machine
from pymongocrypt.mongocrypt import MongoCrypt
from pymongocrypt.options import DataKeyOpts, ExplicitEncryptOpts


class AsyncExplicitEncrypter:
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

    async def create_data_key(
        self, kms_provider, master_key=None, key_alt_names=None, key_material=None
    ):
        """Creates a data key used for explicit encryption.

        :Parameters:
          - `kms_provider`: The KMS provider to use. Supported values are
            "aws", "azure", "gcp", "kmip", "local", or a named provider like
            "kmip:name".
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
                encoded_names.append(self.callback.bson_encode({"keyAltName": name}))

        if key_material is not None:
            key_material = self.callback.bson_encode({"keyMaterial": key_material})

        opts = DataKeyOpts(master_key, encoded_names, key_material)
        with self.mongocrypt.data_key_context(kms_provider, opts) as ctx:
            key = await run_state_machine(ctx, self.callback)
        return await self.callback.insert_data_key(key)

    async def rewrap_many_data_key(self, filter, provider=None, master_key=None):
        """Decrypts and encrypts all matching data keys with a possibly new `master_key` value.

        :Parameters:
          - `filter`: A document used to filter the data keys.
          - `provider`: (optional) The name of a different kms provider.
          - `master_key`: Optional document for the given provider.

        :Returns:
          A binary document with the rewrap data.
        """
        with self.mongocrypt.rewrap_many_data_key_context(
            filter, provider, master_key
        ) as ctx:
            return await run_state_machine(ctx, self.callback)

    async def encrypt(
        self,
        value,
        algorithm,
        key_id=None,
        key_alt_name=None,
        query_type=None,
        contention_factor=None,
        range_opts=None,
        is_expression=False,
    ):
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
          - `range_opts` (bytes): Options for explicit encryption
            with the "range" algorithm encoded as a BSON document.
          - `is_expression` (boolean): True if this is an encryptExpression()
            context. Defaults to False.

        :Returns:
          The encrypted BSON value.

        .. versionchanged:: 1.3
           Added the `query_type` and `contention_factor` parameters.
        .. versionchanged:: 1.5
           Added the `range_opts` and `is_expression` parameters.
        """
        # CDRIVER-3275 key_alt_name needs to be wrapped in a bson document.
        if key_alt_name is not None:
            key_alt_name = self.callback.bson_encode({"keyAltName": key_alt_name})
        opts = ExplicitEncryptOpts(
            algorithm,
            key_id,
            key_alt_name,
            query_type,
            contention_factor,
            range_opts,
            is_expression,
        )
        with self.mongocrypt.explicit_encryption_context(value, opts) as ctx:
            return await run_state_machine(ctx, self.callback)

    async def decrypt(self, value):
        """Decrypts a BSON value.

        :Parameters:
          - `value`: The encoded document to decrypt, which must be in the
            form { "v" : encrypted BSON value }}.

        :Returns:
          The decrypted BSON value.
        """
        with self.mongocrypt.explicit_decryption_context(value) as ctx:
            return await run_state_machine(ctx, self.callback)

    def close(self):
        """Cleanup resources."""
        self.mongocrypt.close()
