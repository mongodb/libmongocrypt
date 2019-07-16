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

from pymongocrypt.compat import PY3
from pymongocrypt.mongocrypt import MongoCrypt
from pymongocrypt.state_machine import run_state_machine


class ExplicitEncryptOpts(object):
    def __init__(self, algorithm, key_id=None, key_alt_name=None):
        """Options for explicit encryption.

        :Parameters:
          - `algorithm`: The algorithm to use.
          - `key_id`: The data key _id.
          - `key_alt_name`: Identifies a key vault document by 'keyAltName'.
        """
        self.algorithm = algorithm
        self.key_id = key_id
        self.key_alt_name = key_alt_name
        if PY3:
            self.algorithm = algorithm.encode()
            if key_alt_name is not None:
                self.key_alt_name = key_alt_name.encode()


class DataKeyOpts(object):
    def __init__(self, master_key=None, key_alt_names=None):
        """Options for creating encryption keys.

        :Parameters:
          - `master_key`: Identifies a KMS-specific key used to encrypt the
            new data key. If the kmsProvider is "aws" it is required and must
            have the following fields:
            {
               region: String,
               key: String // The Amazon Resource Name (ARN) to the AWS
                           // customer master key (CMK).
            }
            If the kmsProvider is "local" the masterKey is not applicable.
          - `key_alt_name`: An optional list of string alternate names used to
            reference a key. If a key is created with alternate names, then
            encryption may refer to the key by the unique alternate name
            instead of by _id
        """
        self.master_key = master_key
        self.key_alt_names = key_alt_names


class ExplicitEncrypter(object):
    def __init__(self, callback, mongo_crypt_opts):
        """Encrypts and decrypts BSON values.

        This class is used by a driver to support for explicit encryption and
        decryption of individual fields in a BSON document.

        :Parameters:
          - `callback`: A :class:`MongoCryptCallback`.
          - `mongo_crypt_opts`: A :class:`MongoCryptOptions`.
        """
        self.callback = callback
        if mongo_crypt_opts.schema_map is not None:
            raise ValueError("mongo_crypt_opts.schema_map must be None")
        self.mongocrypt = MongoCrypt(mongo_crypt_opts)

    def create_data_key(self, kms_provider, master_key=None,
                        key_alt_names=None):
        """Creates a data key used for explicit encryption.


        :Parameters:
          - `kms_provider`: The KMS provider to use. Supported values are
            "aws" and "local".
          - `master_key`: The `master_key` identifies a KMS-specific key used
            to encrypt the new data key. If the kmsProvider is "local" the
            `master_key` is not applicable and may be omitted.
            If the `kms_provider` is "aws", `master_key` is required and must
            have the following fields:

              - `region` (string): The AWS region as a string.
              - `key` (string): The Amazon Resource Name (ARN) to the AWS
                customer master key (CMK).

          - `key_alt_names` (optional): An optional list of string alternate
            names used to reference a key.

        :Returns:
          The _id of the created data key document.
        """
        opts = DataKeyOpts(master_key, key_alt_names)
        with self.mongocrypt.data_key_context(kms_provider, opts) as ctx:
            key = run_state_machine(ctx, self.callback)
        return self.callback.insert_data_key(key)

    def encrypt(self, value, algorithm, key_id=None, key_alt_name=None):
        """Encrypts a BSON value.

        Note that exactly one of ``key_id`` or  ``key_alt_name`` must be
        provided.

        :Parameters:
          - `value`: The BSON value to encrypt.
          - `algorithm` (string): The encryption algorithm to use. See
            :class:`Algorithm` for some valid options.
          - `key_id`: Identifies a data key by ``_id`` which must be a UUID
            or a :class:`~bson.binary.Binary` with subtype 4.
          - `key_alt_name`: Identifies a key vault document by 'keyAltName'.

        :Returns:
          The encrypted BSON value.
        """
        opts = ExplicitEncryptOpts(algorithm, key_id, key_alt_name)
        with self.mongocrypt.explicit_encryption_context(value, opts) as ctx:
            return run_state_machine(ctx, self.callback)

    def decrypt(self, value):
        """Decrypts a BSON value.

        :Parameters:
          - `value`: The BSON value to encrypt in the form {'v': value}.

        :Returns:
          The decrypted BSON value.
        """
        with self.mongocrypt.explicit_decryption_context(value) as ctx:
            return run_state_machine(ctx, self.callback)

    def close(self):
        """Cleanup resources."""
        self.mongocrypt.close()
