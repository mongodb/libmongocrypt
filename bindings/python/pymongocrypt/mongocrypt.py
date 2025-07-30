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

import platform
import sys

from packaging.version import Version

from pymongocrypt.asynchronous.state_machine import AsyncMongoCryptCallback
from pymongocrypt.binary import MongoCryptBinaryIn, MongoCryptBinaryOut
from pymongocrypt.binding import _to_string, ffi, lib
from pymongocrypt.compat import str_to_bytes
from pymongocrypt.crypto import (
    aes_256_cbc_decrypt,
    aes_256_cbc_encrypt,
    aes_256_ctr_decrypt,
    aes_256_ctr_encrypt,
    hmac_sha_256,
    hmac_sha_512,
    secure_random,
    sha_256,
    sign_rsaes_pkcs1_v1_5,
)
from pymongocrypt.errors import MongoCryptError
from pymongocrypt.options import MongoCryptOptions
from pymongocrypt.synchronous.state_machine import MongoCryptCallback


class MongoCrypt:
    def __init__(self, options, callback):
        """Abstracts libmongocrypt's mongocrypt_t type.

        :Parameters:
          - `options`: A :class:`MongoCryptOptions`.
          - `callback`: A :class:`MongoCryptCallback`.
        """
        self.__opts = options  # type: MongoCryptOptions
        self.__callback = callback
        self.__crypt = None

        if not isinstance(options, MongoCryptOptions):
            raise TypeError("options must be a MongoCryptOptions")

        if not isinstance(callback, (AsyncMongoCryptCallback, MongoCryptCallback)):
            raise TypeError(
                "callback must be a MongoCryptCallback or AsyncMongoCryptCallback"
            )

        self.__crypt = lib.mongocrypt_new()
        if self.__crypt == ffi.NULL:
            raise MongoCryptError("unable to create new mongocrypt object")

        try:
            self.__init()
        except Exception:
            # Destroy the mongocrypt object on error.
            self.close()
            raise

    def __init(self):
        """Internal init helper."""
        kms_providers = self.__opts.kms_providers
        with MongoCryptBinaryIn(self.__callback.bson_encode(kms_providers)) as kmsopt:
            if not lib.mongocrypt_setopt_kms_providers(self.__crypt, kmsopt.bin):
                self.__raise_from_status()

        schema_map = self.__opts.schema_map
        if schema_map is not None:
            with MongoCryptBinaryIn(schema_map) as binary_schema_map:
                if not lib.mongocrypt_setopt_schema_map(
                    self.__crypt, binary_schema_map.bin
                ):
                    self.__raise_from_status()

        encrypted_fields_map = self.__opts.encrypted_fields_map
        if encrypted_fields_map is not None:
            with MongoCryptBinaryIn(
                encrypted_fields_map
            ) as binary_encrypted_fields_map:
                if not lib.mongocrypt_setopt_encrypted_field_config_map(
                    self.__crypt, binary_encrypted_fields_map.bin
                ):
                    self.__raise_from_status()

        if self.__opts.bypass_query_analysis:
            lib.mongocrypt_setopt_bypass_query_analysis(self.__crypt)

        if self.__opts.enable_multiple_collinfo:
            lib.mongocrypt_setopt_enable_multiple_collinfo(self.__crypt)

        # Prefer using the native crypto binding when we know it's available.
        try:
            crypto_available = lib.mongocrypt_is_crypto_available()
        except AttributeError:
            # libmongocrypt < 1.9
            crypto_available = False

        if not crypto_available:
            if not lib.mongocrypt_setopt_crypto_hooks(
                self.__crypt,
                aes_256_cbc_encrypt,
                aes_256_cbc_decrypt,
                secure_random,
                hmac_sha_512,
                hmac_sha_256,
                sha_256,
                ffi.NULL,
            ):
                self.__raise_from_status()

            if not lib.mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5(
                self.__crypt, sign_rsaes_pkcs1_v1_5, ffi.NULL
            ):
                self.__raise_from_status()

            if not lib.mongocrypt_setopt_aes_256_ctr(
                self.__crypt, aes_256_ctr_encrypt, aes_256_ctr_decrypt, ffi.NULL
            ):
                self.__raise_from_status()
        elif sys.platform == "darwin" and Version(platform.mac_ver()[0]) < Version(
            "10.15"
        ):
            # MONGOCRYPT-440 libmongocrypt does not support AES-CTR on macOS < 10.15.
            if not lib.mongocrypt_setopt_aes_256_ctr(
                self.__crypt, aes_256_ctr_encrypt, aes_256_ctr_decrypt, ffi.NULL
            ):
                self.__raise_from_status()

        if self.__opts.crypt_shared_lib_path is not None:
            lib.mongocrypt_setopt_set_crypt_shared_lib_path_override(
                self.__crypt, self.__opts.crypt_shared_lib_path.encode("utf-8")
            )

        if not self.__opts.bypass_encryption:
            lib.mongocrypt_setopt_append_crypt_shared_lib_search_path(
                self.__crypt, b"$SYSTEM"
            )
        on_demand_aws = "aws" in kms_providers and not len(kms_providers["aws"])
        on_demand_gcp = "gcp" in kms_providers and not len(kms_providers["gcp"])
        on_demand_azure = "azure" in kms_providers and not len(kms_providers["azure"])
        if any([on_demand_aws, on_demand_gcp, on_demand_azure]):
            lib.mongocrypt_setopt_use_need_kms_credentials_state(self.__crypt)

        # Enable KMS retry and key_expiration_ms when available, libmongocrypt >= 1.12.0,
        try:
            if not lib.mongocrypt_setopt_retry_kms(self.__crypt, True):
                self.__raise_from_status()
            if self.__opts.key_expiration_ms is not None:
                if not lib.mongocrypt_setopt_key_expiration(
                    self.__crypt, self.__opts.key_expiration_ms
                ):
                    self.__raise_from_status()
        except AttributeError:
            # libmongocrypt < 1.12
            pass

        if not lib.mongocrypt_init(self.__crypt):
            self.__raise_from_status()

        if (
            self.__opts.crypt_shared_lib_required
            and self.crypt_shared_lib_version is None
        ):
            raise MongoCryptError(
                "crypt_shared_lib_required=True but the crypt_shared library could not be loaded "
                f"from crypt_shared_lib_path={self.__opts.crypt_shared_lib_path}"
                + " or the operating system's dynamic library search path"
            )

    def __raise_from_status(self):
        status = lib.mongocrypt_status_new()
        try:
            lib.mongocrypt_status(self.__crypt, status)
            exc = MongoCryptError.from_status(status)
        finally:
            lib.mongocrypt_status_destroy(status)
        raise exc

    @property
    def crypt_shared_lib_version(self):
        ver = lib.mongocrypt_crypt_shared_lib_version_string(self.__crypt, ffi.NULL)
        if ver == ffi.NULL:
            return None
        return ver

    def close(self):
        """Cleanup resources."""
        if self.__crypt is None:
            return
        # Since close is called by __del__, we need to be sure to guard
        # against the case where global variables are set to None at
        # interpreter shutdown, see PYTHON-3530.
        if lib is not None:
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
        return EncryptionContext(
            self._create_context(), self.__opts.kms_providers, database, command
        )

    def decryption_context(self, command):
        """Creates a context to use for decryption.

        :Parameters:
          - `command`: The encoded BSON command to decrypt.

        :Returns:
          A :class:`DecryptionContext`.
        """
        return DecryptionContext(
            self._create_context(), self.__opts.kms_providers, command
        )

    def explicit_encryption_context(self, value, opts):
        """Creates a context to use for explicit encryption.

        :Parameters:
          - `value`: The encoded document to encrypt, which must be in the
            form { "v" : BSON value to encrypt }}.
          - `opts`: A :class:`ExplicitEncryptOpts`.

        :Returns:
          A :class:`ExplicitEncryptionContext`.
        """
        return ExplicitEncryptionContext(
            self._create_context(), self.__opts.kms_providers, value, opts
        )

    def explicit_decryption_context(self, value):
        """Creates a context to use for explicit decryption.

        :Parameters:
          - `value`: The encoded document to decrypt, which must be in the
            form { "v" : encrypted BSON value }}.

        :Returns:
          A :class:`ExplicitDecryptionContext`.
        """
        return ExplicitDecryptionContext(
            self._create_context(), self.__opts.kms_providers, value
        )

    def data_key_context(self, kms_provider, opts=None):
        """Creates a context to use for key generation.

        :Parameters:
          - `kms_provider`: The KMS provider.
          - `opts`: An optional class:`DataKeyOpts`.

        :Returns:
          A :class:`DataKeyContext`.
        """
        return DataKeyContext(
            self._create_context(),
            self.__opts.kms_providers,
            kms_provider,
            opts,
            self.__callback,
        )

    def rewrap_many_data_key_context(self, filter, provider, master_key):
        """Creates a context to use for rewrapping many data keys.

        :Parameters:
          - `filter`: A document used to filter the data keys.
          - `provider`: (optional) The name of a different kms provider.
          - `master_key`: Optional document for the given provider.
            MUST have the fields corresponding to the
            given provider as specified in master_key. master_key MUST NOT be
            given if it is not applicable for the given provider.

        :Returns:
          A :class:`RewrapManyDataKeyContext`.
        """
        return RewrapManyDataKeyContext(
            self._create_context(),
            self.__opts.kms_providers,
            filter,
            provider,
            master_key,
            self.__callback,
        )


class MongoCryptContext:
    __slots__ = ("__ctx", "kms_providers")

    def __init__(self, ctx, kms_providers):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_providers`: The KMS provider map.
        """
        self.__ctx = ctx
        self.kms_providers = kms_providers

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

    def provide_kms_providers(self, providers):
        """Provide a map of KMS providers."""
        with MongoCryptBinaryIn(providers) as binary:
            if not lib.mongocrypt_ctx_provide_kms_providers(self.__ctx, binary.bin):
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

    def __init__(self, ctx, kms_providers, database, command):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
         - `kms_providers`: The KMS provider map.
          - `database`: Optional, the name of the database.
          - `command`: The BSON command to encrypt.
        """
        super().__init__(ctx, kms_providers)
        self.database = database
        try:
            with MongoCryptBinaryIn(command) as binary:
                database = str_to_bytes(database)
                if not lib.mongocrypt_ctx_encrypt_init(
                    ctx, database, len(database), binary.bin
                ):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class DecryptionContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, kms_providers, command):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_providers`: The KMS provider map.
          - `command`: The encoded BSON command to decrypt.
        """
        super().__init__(ctx, kms_providers)
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

    def __init__(self, ctx, kms_providers, value, opts):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_providers`: The KMS provider map.
          - `value`:  The encoded document to encrypt, which must be in the
            form { "v" : BSON value to encrypt }}.
          - `opts`: A :class:`ExplicitEncryptOpts`.
        """
        super().__init__(ctx, kms_providers)
        try:
            algorithm = str_to_bytes(opts.algorithm)
            if not lib.mongocrypt_ctx_setopt_algorithm(ctx, algorithm, -1):
                self._raise_from_status()

            if opts.key_id is not None:
                with MongoCryptBinaryIn(opts.key_id) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_id(ctx, binary.bin):
                        self._raise_from_status()

            if opts.key_alt_name is not None:
                with MongoCryptBinaryIn(opts.key_alt_name) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_alt_name(ctx, binary.bin):
                        self._raise_from_status()

            if opts.query_type is not None:
                qt = str_to_bytes(opts.query_type)
                if not lib.mongocrypt_ctx_setopt_query_type(ctx, qt, -1):
                    self._raise_from_status()

            if opts.contention_factor is not None:
                if not lib.mongocrypt_ctx_setopt_contention_factor(
                    ctx, opts.contention_factor
                ):
                    self._raise_from_status()

            if opts.range_opts is not None:
                with MongoCryptBinaryIn(opts.range_opts) as range_opts:
                    if not lib.mongocrypt_ctx_setopt_algorithm_range(
                        ctx, range_opts.bin
                    ):
                        self._raise_from_status()

            with MongoCryptBinaryIn(value) as binary:
                if opts.is_expression:
                    if not lib.mongocrypt_ctx_explicit_encrypt_expression_init(
                        ctx, binary.bin
                    ):
                        self._raise_from_status()
                else:
                    if not lib.mongocrypt_ctx_explicit_encrypt_init(ctx, binary.bin):
                        self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class ExplicitDecryptionContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, kms_providers, value):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_providers`: The KMS provider map.
          - `value`: The encoded BSON value to decrypt.
        """
        super().__init__(ctx, kms_providers)

        try:
            with MongoCryptBinaryIn(value) as binary:
                if not lib.mongocrypt_ctx_explicit_decrypt_init(ctx, binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class DataKeyContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, kms_providers, kms_provider, opts, callback):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_providers`: The KMS provider map.
          - `kms_provider`: The KMS provider.
          - `opts`: An optional class:`DataKeyOpts`.
          - `callback`: A :class:`MongoCryptCallback`.
        """
        super().__init__(ctx, kms_providers)
        try:
            if kms_provider not in kms_providers:
                raise ValueError(f"unknown kms_provider: {kms_provider}")

            # Account for provider names like "local:myname".
            provider_type = kms_provider.split(":")[0]
            if opts is None or opts.master_key is None:
                if provider_type in ["kmip", "local"]:
                    master_key = {}
                else:
                    raise ValueError(
                        f"master_key is required for kms_provider: {kms_provider!r}"
                    )
            else:
                master_key = opts.master_key.copy()

            if provider_type == "aws":
                if "region" not in master_key or "key" not in master_key:
                    raise ValueError(
                        'master_key must include "region" and "key" for '
                        f"kms_provider: {kms_provider!r}"
                    )
            elif provider_type == "azure":
                if "keyName" not in master_key or "keyVaultEndpoint" not in master_key:
                    raise ValueError(
                        'master key must include "keyName" and '
                        f'"keyVaultEndpoint" for kms_provider: {kms_provider!r}'
                    )
            elif provider_type == "gcp":
                if (
                    "projectId" not in master_key
                    or "location" not in master_key
                    or "keyRing" not in master_key
                    or "keyName" not in master_key
                ):
                    raise ValueError(
                        'master key must include "projectId", "location",'
                        f'"keyRing", and "keyName" for kms_provider: {kms_provider!r}'
                    )

            master_key["provider"] = kms_provider
            with MongoCryptBinaryIn(callback.bson_encode(master_key)) as mkey:
                if not lib.mongocrypt_ctx_setopt_key_encryption_key(ctx, mkey.bin):
                    self._raise_from_status()

            if opts.key_alt_names:
                for key_alt_name in opts.key_alt_names:
                    with MongoCryptBinaryIn(key_alt_name) as binary:
                        if not lib.mongocrypt_ctx_setopt_key_alt_name(ctx, binary.bin):
                            self._raise_from_status()

            if opts.key_material:
                with MongoCryptBinaryIn(opts.key_material) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_material(ctx, binary.bin):
                        self._raise_from_status()

            if not lib.mongocrypt_ctx_datakey_init(ctx):
                self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise


class MongoCryptKmsContext:
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

    @property
    def kms_provider(self):
        """The KMS provider identifier associated with this KMS request.

        :Returns:
          The KMS provider as a string, eg "aws", "azure", "gcp", or "kmip".

        .. versionadded:: 1.2
        """
        return _to_string(lib.mongocrypt_kms_ctx_get_kms_provider(self.__ctx, ffi.NULL))

    def feed(self, data):
        """Feed bytes from the HTTP response.

        :Parameters:
          - `data`: The bytes of the HTTP response. Must not exceed
            :attr:`bytes_needed`.
        """
        with MongoCryptBinaryIn(data) as binary:
            if not lib.mongocrypt_kms_ctx_feed(self.__ctx, binary.bin):
                self.__raise_from_status()

    @property
    def usleep(self):
        """Indicates how long to sleep in microseconds before sending this request.

        .. versionadded:: 1.12
        """
        try:
            return lib.mongocrypt_kms_ctx_usleep(self.__ctx)
        except AttributeError:
            # libmongocrypt < 1.12
            return 0

    def fail(self):
        """Indicate a network-level failure.

        .. versionadded:: 1.12
        """
        try:
            if not lib.mongocrypt_kms_ctx_fail(self.__ctx):
                self.__raise_from_status()
        except AttributeError:
            # libmongocrypt < 1.12
            pass

    def __raise_from_status(self):
        status = lib.mongocrypt_status_new()
        try:
            lib.mongocrypt_kms_ctx_status(self.__ctx, status)
            exc = MongoCryptError.from_status(status)
        finally:
            lib.mongocrypt_status_destroy(status)
        raise exc


class RewrapManyDataKeyContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, kms_providers, filter, provider, master_key, callback):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
         - `kms_providers`: The KMS provider map.
          - `filter`: The filter to use when finding data keys to rewrap in the key vault collection..
          - `provider`: (optional) The name of a different kms provider.
          - `master_key`: Optional document for the given provider.
          - `callback`: A :class:`MongoCryptCallback`.
        """
        super().__init__(ctx, kms_providers)
        key_encryption_key_bson = None
        if provider is not None:
            data = dict(provider=provider)
            if master_key:
                data.update(master_key)
            key_encryption_key_bson = callback.bson_encode(data)

        try:
            if key_encryption_key_bson:
                with MongoCryptBinaryIn(key_encryption_key_bson) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_encryption_key(
                        ctx, binary.bin
                    ):
                        self._raise_from_status()

            filter_bson = callback.bson_encode(filter)

            with MongoCryptBinaryIn(filter_bson) as binary:
                if not lib.mongocrypt_ctx_rewrap_many_datakey_init(ctx, binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise
