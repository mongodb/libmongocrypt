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

from pymongocrypt.binding import ffi, lib, _to_string
from pymongocrypt.compat import PY3
from pymongocrypt.errors import MongoCryptError


class _MongoCryptBinary(object):
    __slots__ = ("bin",)

    def __init__(self, binary):
        """Wraps a mongocrypt_binary_t."""
        self.bin = binary
        if binary == ffi.NULL:
            raise MongoCryptError(
                "unable to create new mongocrypt_binary object")

    def _close(self):
        """Cleanup resources."""
        if self.bin is None:
            return
        lib.mongocrypt_binary_destroy(self.bin)
        self.bin = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    def to_bytes(self):
        """Returns this mongocrypt_binary_t as bytes."""
        data = lib.mongocrypt_binary_data(self.bin)
        if data == ffi.NULL:
            return b''
        data_len = lib.mongocrypt_binary_len(self.bin)
        return ffi.unpack(ffi.cast("char*", data), data_len)


class MongoCryptBinaryOut(_MongoCryptBinary):
    __slots__ = ()

    def __init__(self):
        """Wraps a mongocrypt_binary_t."""
        super(MongoCryptBinaryOut, self).__init__(lib.mongocrypt_binary_new())


class MongoCryptBinaryIn(_MongoCryptBinary):
    __slots__ = ("__copy",)

    def __init__(self, data):
        """Creates a mongocrypt_binary_t from binary data."""
        # mongocrypt_binary_t does not own the data it is passed so we need to
        # create a copy to keep the data alive.
        self.__copy = ffi.new("uint8_t[]", data)
        super(MongoCryptBinaryIn, self).__init__(
            lib.mongocrypt_binary_new_from_data(self.__copy, len(data)))

    def _close(self):
        """Cleanup resources."""
        super(MongoCryptBinaryIn, self)._close()
        if self.__copy is None:
            return
        ffi.release(self.__copy)
        self.__copy = None


class MongoCryptOptions(object):
    def __init__(self, kms_providers, schema_map=None):
        """Options for :class:`MongoCrypt`.

        :Parameters:
          - `kms_providers`: Map of KMS provider options. Two KMS providers
            are supported: "aws" and "local". The kmsProviders map values
            differ by provider:
              - `aws`: Map with "accessKeyId" and "secretAccessKey" as strings.
              - `local`: Map with "key" as a 96-byte array or string.
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
        """
        if not isinstance(kms_providers, dict):
            raise ValueError('kms_providers must be a dict')
        if not kms_providers:
            raise ValueError('at least one KMS provider must be configured')

        if 'aws' in kms_providers:
            aws = kms_providers["aws"]
            if not isinstance(aws, dict):
                raise ValueError("kms_providers['aws'] must be a dict")
            if "accessKeyId" not in aws or "secretAccessKey" not in aws:
                raise ValueError("kms_providers['aws'] must contain "
                                 "'accessKeyId' and 'secretAccessKey'")

        if 'local' in kms_providers:
            local = kms_providers['local']
            if not isinstance(local, dict):
                raise ValueError("kms_providers['local'] must be a dict")
            if 'key' not in local:
                raise ValueError("kms_providers['local'] must contain 'key'")

            key = kms_providers['local']['key']
            if not isinstance(key, bytes):
                raise TypeError("kms_providers['local']['key'] must be a "
                                "bytes (or str in Python 2)")

        if schema_map is not None and not isinstance(schema_map, bytes):
            raise TypeError("schema_map must be bytes or None")

        self.kms_providers = kms_providers
        self.schema_map = schema_map


class MongoCrypt(object):
    def __init__(self, options):
        """Abstracts libmongocrypt's mongocrypt_t type.

        :Parameters:
          - `options`: A :class:`MongoCryptOptions`.
        """
        self.__opts = options
        self.__crypt = None

        if not isinstance(options, MongoCryptOptions):
            raise TypeError("options must be a MongoCryptOptions")

        self.__crypt = lib.mongocrypt_new()
        if self.__crypt == ffi.NULL:
            raise MongoCryptError("unable to create new mongocrypt object")

        kms_providers = self.__opts.kms_providers
        if 'aws' in kms_providers:
            access_key_id = kms_providers['aws']['accessKeyId']
            secret_access_key = kms_providers['aws']['secretAccessKey']
            if PY3:
                access_key_id = access_key_id.encode()
                secret_access_key = secret_access_key.encode()
            if not lib.mongocrypt_setopt_kms_provider_aws(
                    self.__crypt,
                    access_key_id, len(access_key_id),
                    secret_access_key, len(secret_access_key)):
                self.__raise_from_status()
        if 'local' in kms_providers:
            key = kms_providers['local']['key']
            with MongoCryptBinaryIn(key) as binary_key:
                if not lib.mongocrypt_setopt_kms_provider_local(
                        self.__crypt, binary_key.bin):
                    self.__raise_from_status()

        schema_map = self.__opts.schema_map
        if schema_map is not None:
            with MongoCryptBinaryIn(schema_map) as binary_schema_map:
                if not lib.mongocrypt_setopt_schema_map(
                        self.__crypt, binary_schema_map.bin):
                    self.__raise_from_status()

        if not lib.mongocrypt_init(self.__crypt):
            self.__raise_from_status()

    def __raise_from_status(self):
        status = lib.mongocrypt_status_new()
        try:
            lib.mongocrypt_status(self.__crypt, status)
            exc = MongoCryptError.from_status(status)
        finally:
            lib.mongocrypt_status_destroy(status)
        raise exc

    def close(self):
        """Cleanup resources."""
        if self.__crypt is None:
            return
        lib.mongocrypt_destroy(self.__crypt)
        self.__crypt = None

    def __del__(self):
        self.close()

    def _create_context(self):
        """Returns a new mongocrypt_ctx_t"""
        ctx = lib.mongocrypt_ctx_new(self.__crypt)
        if ctx == ffi.NULL:
            self.__raise_from_status()
        return ctx

    def encryption_context(self, database, command):
        """Creates a context to use for encryption.

        :Parameters:
          - `database`: The database name.
          - `command`: The encoded BSON command to encrypt.

        :Returns:
          A :class:`EncryptionContext`.
        """
        return EncryptionContext(self._create_context(), database, command)

    def decryption_context(self, command):
        """Creates a context to use for decryption.

        :Parameters:
          - `command`: The encoded BSON command to decrypt.

        :Returns:
          A :class:`DecryptionContext`.
        """
        return DecryptionContext(self._create_context(), command)

    def explicit_encryption_context(self, value, opts):
        """Creates a context to use for explicit encryption.

        :Parameters:
          - `value`: The encoded document to encrypt, which must be in the
            form { "v" : BSON value to encrypt }}.
          - `opts`: A ExplicitEncryptOpts.

        :Returns:
          A :class:`ExplicitEncryptionContext`.
        """
        return ExplicitEncryptionContext(self._create_context(), value, opts)

    def explicit_decryption_context(self, value):
        """Creates a context to use for explicit decryption.

        :Parameters:
          - `document`: The encoded document to decrypt, which must be in the
            form { "v" : encrypted BSON value }}.

        :Returns:
          A :class:`ExplicitDecryptionContext`.
        """
        return ExplicitDecryptionContext(self._create_context(), value)

    def data_key_context(self, kms_provider, opts=None):
        """Creates a context to use for key generation.

        :Parameters:
          - `kms_provider`: The KMS provider.
          - `opts`: An optional class:`DataKeyOpts`.

        :Returns:
          A :class:`DataKeyContext`.
        """
        return DataKeyContext(self._create_context(), kms_provider, opts)


class MongoCryptContext(object):
    __slots__ = ("__ctx",)

    def __init__(self, ctx):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `database`: Optional, the name of the database.
        """
        self.__ctx = ctx

    def _close(self):
        """Cleanup resources."""
        if self.__ctx is None:
            return
        lib.mongocrypt_ctx_destroy(self.__ctx)
        self.__ctx = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    @property
    def state(self):
        """The current state of the mongocrypt_ctx_t."""
        return lib.mongocrypt_ctx_state(self.__ctx)

    def _raise_from_status(self):
        status = lib.mongocrypt_status_new()
        try:
            lib.mongocrypt_ctx_status(self.__ctx, status)
            exc = MongoCryptError.from_status(status)
        finally:
            lib.mongocrypt_status_destroy(status)
        raise exc

    def mongo_operation(self):
        """Returns the mongo operation to execute as bson bytes."""
        with MongoCryptBinaryOut() as binary:
            if not lib.mongocrypt_ctx_mongo_op(self.__ctx, binary.bin):
                self._raise_from_status()
            return binary.to_bytes()

    def add_mongo_operation_result(self, document):
        """Adds the mongo operation's command response.

        :Parameters:
          - `document`: A raw BSON command response document.
        """
        with MongoCryptBinaryIn(document) as binary:
            if not lib.mongocrypt_ctx_mongo_feed(self.__ctx, binary.bin):
                self._raise_from_status()

    def complete_mongo_operation(self):
        """Completes the mongo operation."""
        if not lib.mongocrypt_ctx_mongo_done(self.__ctx):
            self._raise_from_status()

    def kms_contexts(self):
        """Yields the MongoCryptKmsContexts."""
        ctx = lib.mongocrypt_ctx_next_kms_ctx(self.__ctx)
        while ctx != ffi.NULL:
            yield MongoCryptKmsContext(ctx)
            ctx = lib.mongocrypt_ctx_next_kms_ctx(self.__ctx)

    def complete_kms(self):
        """Indicates that all MongoCryptKmsContexts have been completed"""
        if not lib.mongocrypt_ctx_kms_done(self.__ctx):
            self._raise_from_status()

    def finish(self):
        """Returns the finished mongo operation as bson bytes."""
        with MongoCryptBinaryOut() as binary:
            if not lib.mongocrypt_ctx_finalize(self.__ctx, binary.bin):
                self._raise_from_status()
            return binary.to_bytes()


class EncryptionContext(MongoCryptContext):
    __slots__ = ("database",)

    def __init__(self, ctx, database, command):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `database`: Optional, the name of the database.
          - `command`: The BSON command to encrypt.
        """
        super(EncryptionContext, self).__init__(ctx)
        self.database = database
        try:
            with MongoCryptBinaryIn(command) as binary:
                if PY3:
                    database = database.encode()
                if not lib.mongocrypt_ctx_encrypt_init(
                       ctx, database, len(database), binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class DecryptionContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, command):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `command`: The encoded BSON command to decrypt.
        """
        super(DecryptionContext, self).__init__(ctx)
        try:
            with MongoCryptBinaryIn(command) as binary:
                if not lib.mongocrypt_ctx_decrypt_init(ctx, binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class ExplicitEncryptionContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, value, opts):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `database`: Optional, the name of the database.
          - `command`: The BSON command to encrypt.
        """
        super(ExplicitEncryptionContext, self).__init__(ctx)
        try:
            if not lib.mongocrypt_ctx_setopt_algorithm(
                    ctx, opts.algorithm, -1):
                self._raise_from_status()

            if opts.key_id is not None:
                with MongoCryptBinaryIn(opts.key_id) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_id(ctx, binary.bin):
                        self._raise_from_status()

            if opts.key_alt_name is not None:
                with MongoCryptBinaryIn(opts.key_alt_name) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_alt_name(ctx,
                                                                  binary.bin):
                        self._raise_from_status()

            with MongoCryptBinaryIn(value) as binary:
                if not lib.mongocrypt_ctx_explicit_encrypt_init(ctx,
                                                                binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class ExplicitDecryptionContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, value):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `value`: The encoded BSON value to decrypt.
        """
        super(ExplicitDecryptionContext, self).__init__(ctx)

        try:
            with MongoCryptBinaryIn(value) as binary:
                if not lib.mongocrypt_ctx_explicit_decrypt_init(ctx,
                                                                binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class DataKeyContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, kms_provider, opts):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_provider`: The KMS provider.
          - `opts`: An optional class:`DataKeyOpts`.
        """
        super(DataKeyContext, self).__init__(ctx)
        try:
            if kms_provider == 'aws':
                if opts is None or opts.master_key is None:
                    raise ValueError('opts.master_key is required for '
                                     'kms_provider: "aws"')
                if 'region' not in opts.master_key or 'key' not in \
                        opts.master_key:
                    raise ValueError(
                        'opts.master_key must include "region" and '
                        '"key" for kms_provider: "aws"')
                region = opts.master_key['region']
                key = opts.master_key['key']
                if PY3:
                    region = region.encode()
                    key = key.encode()
                if not lib.mongocrypt_ctx_setopt_masterkey_aws(
                        ctx, region, len(region), key, len(key)):
                    self._raise_from_status()
            elif kms_provider == 'local':
                if not lib.mongocrypt_ctx_setopt_masterkey_local(ctx):
                    self._raise_from_status()
            else:
                raise ValueError('unknown kms_provider')
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class MongoCryptKmsContext(object):
    __slots__ = ("__ctx",)

    def __init__(self, ctx):
        """Abstracts libmongocrypt's mongocrypt_kms_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_kms_ctx_t.
        """
        self.__ctx = ctx

    def _close(self):
        """Clear the mongocrypt_kms_ctx_t."""
        self.__ctx = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    @property
    def endpoint(self):
        """The kms hostname to connect over TLS."""
        p = ffi.new("char *[]", 1)
        try:
            if not lib.mongocrypt_kms_ctx_endpoint(self.__ctx, p):
                self.__raise_from_status()
            return _to_string(p[0])
        finally:
            ffi.release(p)

    @property
    def message(self):
        """The HTTP request message to send to the given endpoint."""
        with MongoCryptBinaryOut() as binary:
            if not lib.mongocrypt_kms_ctx_message(self.__ctx, binary.bin):
                self.__raise_from_status()
            return binary.to_bytes()

    @property
    def bytes_needed(self):
        """Indicates how many bytes to send to :meth:`feed`."""
        return lib.mongocrypt_kms_ctx_bytes_needed(self.__ctx)

    def feed(self, data):
        """Feed bytes from the HTTP response.

        :Parameters:
          - `data`: The bytes of the HTTP response. Must not exceed
            :attr:`bytes_needed`.
        """
        with MongoCryptBinaryIn(data) as binary:
            if not lib.mongocrypt_kms_ctx_feed(self.__ctx, binary.bin):
                self.__raise_from_status()

    def __raise_from_status(self):
        status = lib.mongocrypt_status_new()
        try:
            lib.mongocrypt_kms_ctx_status(self.__ctx, status)
            exc = MongoCryptError.from_status(status)
        finally:
            lib.mongocrypt_status_destroy(status)
        raise exc
