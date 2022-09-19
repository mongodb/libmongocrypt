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

from abc import abstractmethod

from pymongocrypt.binding import lib
from pymongocrypt.compat import ABC
from pymongocrypt.errors import MongoCryptError


class MongoCryptCallback(ABC):
    """Callback ABC to perform I/O on behalf of libbmongocrypt."""

    @abstractmethod
    def kms_request(self, kms_context):
        """Complete a KMS request.

        :Parameters:
          - `kms_context`: A :class:`MongoCryptKmsContext`.

        :Returns:
          None
        """
        pass

    @abstractmethod
    def collection_info(self, database, filter):
        """Get the collection info for a namespace.

        The returned collection info is passed to libmongocrypt which reads
        the JSON schema.

        :Parameters:
          - `database`: The database on which to run listCollections.
          - `filter`: The filter to pass to listCollections.

        :Returns:
          The first document from the listCollections command response as BSON.
        """
        pass

    @abstractmethod
    def mark_command(self, database, cmd):
        """Mark a command for encryption.

        :Parameters:
          - `database`: The database on which to run this command.
          - `cmd`: The BSON command to run.

        :Returns:
          The marked command response from mongocryptd.
        """
        pass

    @abstractmethod
    def fetch_keys(self, filter):
        """Yields one or more keys from the key vault.

        :Parameters:
          - `filter`: The filter to pass to find.

        :Returns:
          A generator which yields the requested keys from the key vault.
        """
        pass

    @abstractmethod
    def insert_data_key(self, data_key):
        """Insert a data key into the key vault.

        :Parameters:
          - `data_key`: The data key document to insert.

        :Returns:
          The _id of the inserted data key document.
        """
        pass

    @abstractmethod
    def bson_encode(self, doc):
        """Encode a document to BSON.

        A document can be any mapping type (like :class:`dict`).

        :Parameters:
          - `doc`: mapping type representing a document

        :Returns:
          The encoded BSON bytes.
        """
        pass

    @abstractmethod
    def close(self):
        """Release resources."""
        pass


def run_state_machine(ctx, callback):
    """Run the libmongocrypt state machine until completion.

    :Parameters:
      - `ctx`: A :class:`MongoCryptContext`.
      - `callback`: A :class:`MongoCryptCallback`.

    :Returns:
      The completed libmongocrypt operation.
    """
    while True:
        state = ctx.state
        # Check for terminal states first.
        if state == lib.MONGOCRYPT_CTX_ERROR:
            ctx._raise_from_status()
        elif state == lib.MONGOCRYPT_CTX_READY:
            return ctx.finish()
        elif state == lib.MONGOCRYPT_CTX_DONE:
            return None

        if state == lib.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
            list_colls_filter = ctx.mongo_operation()
            coll_info = callback.collection_info(
                ctx.database, list_colls_filter)
            if coll_info:
                ctx.add_mongo_operation_result(coll_info)
            ctx.complete_mongo_operation()
        elif state == lib.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
            mongocryptd_cmd = ctx.mongo_operation()
            result = callback.mark_command(ctx.database, mongocryptd_cmd)
            ctx.add_mongo_operation_result(result)
            ctx.complete_mongo_operation()
        elif state == lib.MONGOCRYPT_CTX_NEED_MONGO_KEYS:
            key_filter = ctx.mongo_operation()
            for key in callback.fetch_keys(key_filter):
                ctx.add_mongo_operation_result(key)
            ctx.complete_mongo_operation()
        elif state == lib.MONGOCRYPT_CTX_NEED_KMS:
            for kms_ctx in ctx.kms_contexts():
                with kms_ctx:
                    callback.kms_request(kms_ctx)
            ctx.complete_kms()
        elif state == lib.MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS:
            creds = ctx.ask_for_kms_credentials()
            ctx.provide_kms_providers(callback.bson_encode(creds))
        else:
            raise MongoCryptError('unknown state: %r' % (state,))
