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


class AutoEncrypter(object):
    def __init__(self, callback, mongo_crypt_opts):
        """Encrypts and decrypts MongoDB commands.

        This class is used by a driver to support automatic encryption and
        decryption of MongoDB commands.

        :Parameters:
          - `callback`: A :class:`MongoCryptCallback`.
          - `mongo_crypt_opts`: A :class:`MongoCryptOptions`.
        """
        self.callback = callback
        self.mongocrypt = MongoCrypt(mongo_crypt_opts, callback)

    def encrypt(self, database, cmd):
        """Encrypt a MongoDB command.

        :Parameters:
          - `database`: The database for this command.
          - `cmd`: A MongoDB command as BSON.

        :Returns:
          The encrypted command.
        """
        with self.mongocrypt.encryption_context(database, cmd) as ctx:
            return run_state_machine(ctx, self.callback)

    def decrypt(self, response):
        """Decrypt a MongoDB command response.

        :Parameters:
          - `response`: A MongoDB command response as BSON.

        :Returns:
          The decrypted command response.
        """
        with self.mongocrypt.decryption_context(response) as ctx:
            return run_state_machine(ctx, self.callback)

    def close(self):
        """Cleanup resources."""
        self.mongocrypt.close()
        self.callback.close()
