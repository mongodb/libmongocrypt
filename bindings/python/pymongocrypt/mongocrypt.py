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

import copy


from pymongocrypt.binary import (MongoCryptBinaryIn,
                                 MongoCryptBinaryOut)
from pymongocrypt.binding import ffi, lib, _to_string
from pymongocrypt.compat import (safe_bytearray_or_base64, str_to_bytes,
                                 unicode_type)
from pymongocrypt.credentials import _ask_for_kms_credentials
from pymongocrypt.errors import MongoCryptError
from pymongocrypt.state_machine import MongoCryptCallback

from pymongocrypt.crypto import (aes_256_cbc_encrypt,
                                 aes_256_cbc_decrypt,
                                 aes_256_ctr_decrypt,
                                 aes_256_ctr_encrypt,
                                 hmac_sha_256,
                                 hmac_sha_512,
                                 sha_256,
                                 secure_random,
                                 sign_rsaes_pkcs1_v1_5)


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
                a byte array or a base64-encoded string. On Python 2,
                base64-encoded strings must be passed as unicode literals.
              - `kmip`: Map with "endpoint" as a string.
              - `local`: Map with "key" as a 96-byte array or the equivalent
                base64-encoded string. On Python 2, base64-encoded strings
                must be passed as unicode literals.
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

        if 'aws' in kms_providers:
            aws = kms_providers["aws"]
            if not isinstance(aws, dict):
                raise ValueError("kms_providers['aws'] must be a dict")
            if len(aws):
                if "accessKeyId" not in aws or "secretAccessKey" not in aws:
                    raise ValueError("kms_providers['aws'] must contain "
                                     "'accessKeyId' and 'secretAccessKey'")

        if 'azure' in kms_providers:
            azure = kms_providers["azure"]
            if not isinstance(azure, dict):
                raise ValueError("kms_providers['azure'] must be a dict")
            if len(azure):
                if 'clientId' not in azure or 'clientSecret' not in azure:
                    raise ValueError("kms_providers['azure'] must contain "
                                     "'clientId' and 'clientSecret'")

        if 'gcp' in kms_providers:
            gcp = kms_providers['gcp']
            if not isinstance(gcp, dict):
                raise ValueError("kms_providers['gcp'] must be a dict")
            if len(gcp):
                if 'email' not in gcp or 'privateKey' not in gcp:
                    raise ValueError("kms_providers['gcp'] must contain "
                                     "'email' and 'privateKey'")
                if not isinstance(kms_providers['gcp']['privateKey'],
                                  (bytes, unicode_type)):
                    raise TypeError("kms_providers['gcp']['privateKey'] must "
                                    "be an instance of bytes or str "
                                    "(unicode in Python 2)")

        if 'kmip' in kms_providers:
            kmip = kms_providers['kmip']
            if not isinstance(kmip, dict):
                raise ValueError("kms_providers['kmip'] must be a dict")
            if 'endpoint' not in kmip:
                raise ValueError("kms_providers['kmip'] must contain "
                                 "'endpoint'")
            if not isinstance(kms_providers['kmip']['endpoint'],
                              (str, unicode_type)):
                raise TypeError("kms_providers['kmip']['endpoint'] must "
                                "be an instance of str")

        if 'local' in kms_providers:
            local = kms_providers['local']
            if not isinstance(local, dict):
                raise ValueError("kms_providers['local'] must be a dict")
            if 'key' not in local:
                raise ValueError("kms_providers['local'] must contain 'key'")
            if not isinstance(kms_providers['local']['key'],
                              (bytes, unicode_type)):
                raise TypeError("kms_providers['local']['key'] must be an "
                                "instance of bytes or str (unicode in "
                                "Python 2)")

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


class MongoCrypt(object):

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

        if not isinstance(callback, MongoCryptCallback):
            raise TypeError("callback must be a MongoCryptCallback")

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

        # Make fields that can be passed as binary or string safe to
        # encode to BSON.
        base64_or_bytes_fields = [("local", "key"), ("gcp", "privateKey")]
        for f1, f2 in base64_or_bytes_fields:
            value = kms_providers.get(f1, {}).get(f2, None)
            if value is not None:
                safe_value = safe_bytearray_or_base64(value)
                if value != safe_value:
                    kms_providers = copy.deepcopy(kms_providers)
                    kms_providers[f1][f2] = safe_value
        with MongoCryptBinaryIn(
                self.__callback.bson_encode(kms_providers)) as kmsopt:
            if not lib.mongocrypt_setopt_kms_providers(
                    self.__crypt, kmsopt.bin):
                self.__raise_from_status()

        schema_map = self.__opts.schema_map
        if schema_map is not None:
            with MongoCryptBinaryIn(schema_map) as binary_schema_map:
                if not lib.mongocrypt_setopt_schema_map(
                        self.__crypt, binary_schema_map.bin):
                    self.__raise_from_status()

        encrypted_fields_map = self.__opts.encrypted_fields_map
        if encrypted_fields_map is not None:
            with MongoCryptBinaryIn(encrypted_fields_map) as binary_encrypted_fields_map:
                if not lib.mongocrypt_setopt_encrypted_field_config_map(
                        self.__crypt, binary_encrypted_fields_map.bin):
                    self.__raise_from_status()

        if self.__opts.bypass_query_analysis:
            lib.mongocrypt_setopt_bypass_query_analysis(self.__crypt)

        if not lib.mongocrypt_setopt_crypto_hooks(
                self.__crypt, aes_256_cbc_encrypt, aes_256_cbc_decrypt,
                secure_random, hmac_sha_512, hmac_sha_256, sha_256, ffi.NULL):
            self.__raise_from_status()

        if not lib.mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5(
                self.__crypt, sign_rsaes_pkcs1_v1_5, ffi.NULL):
            self.__raise_from_status()

        if not lib.mongocrypt_setopt_aes_256_ctr(
                self.__crypt, aes_256_ctr_encrypt, aes_256_ctr_decrypt, ffi.NULL):
            self.__raise_from_status()

        if self.__opts.crypt_shared_lib_path is not None:
            lib.mongocrypt_setopt_set_crypt_shared_lib_path_override(
                self.__crypt, self.__opts.crypt_shared_lib_path.encode("utf-8"))

        if not self.__opts.bypass_encryption:
            lib.mongocrypt_setopt_append_crypt_shared_lib_search_path(self.__crypt, b"$SYSTEM")
        on_demand_aws = 'aws' in kms_providers and not len(kms_providers['aws'])
        on_demand_gcp = 'gcp' in kms_providers and not len(kms_providers['gcp'])
        on_demand_azure = 'azure' in kms_providers and not len(kms_providers['azure'])
        if any([on_demand_aws, on_demand_gcp, on_demand_azure]):
            lib.mongocrypt_setopt_use_need_kms_credentials_state(self.__crypt)

        if not lib.mongocrypt_init(self.__crypt):
            self.__raise_from_status()

        if self.__opts.crypt_shared_lib_required and self.crypt_shared_lib_version is None:
            raise MongoCryptError(
                "crypt_shared_lib_required=True but the crypt_shared library could not be loaded "
                "from crypt_shared_lib_path={}".format(
                    self.__opts.crypt_shared_lib_path) +
                " or the operating system's dynamic library search path")

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
        return EncryptionContext(self._create_context(), self.__opts.kms_providers, database, command)

    def decryption_context(self, command):
        """Creates a context to use for decryption.

        :Parameters:
          - `command`: The encoded BSON command to decrypt.

        :Returns:
          A :class:`DecryptionContext`.
        """
        return DecryptionContext(self._create_context(), self.__opts.kms_providers, command)

    def explicit_encryption_context(self, value, opts):
        """Creates a context to use for explicit encryption.

        :Parameters:
          - `value`: The encoded document to encrypt, which must be in the
            form { "v" : BSON value to encrypt }}.
          - `opts`: A :class:`ExplicitEncryptOpts`.

        :Returns:
          A :class:`ExplicitEncryptionContext`.
        """
        return ExplicitEncryptionContext(self._create_context(),
            self.__opts.kms_providers, value, opts)

    def explicit_decryption_context(self, value):
        """Creates a context to use for explicit decryption.

        :Parameters:
          - `value`: The encoded document to decrypt, which must be in the
            form { "v" : encrypted BSON value }}.

        :Returns:
          A :class:`ExplicitDecryptionContext`.
        """
        return ExplicitDecryptionContext(self._create_context(),
            self.__opts.kms_providers, value)

    def data_key_context(self, kms_provider, opts=None):
        """Creates a context to use for key generation.

        :Parameters:
          - `kms_provider`: The KMS provider.
          - `opts`: An optional class:`DataKeyOpts`.

        :Returns:
          A :class:`DataKeyContext`.
        """
        return DataKeyContext(self._create_context(), self.__opts.kms_providers, kms_provider, opts,
                              self.__callback)

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
        return RewrapManyDataKeyContext(self._create_context(), self.__opts.kms_providers, filter, provider, master_key, self.__callback)


class MongoCryptContext(object):
    __slots__ = ("__ctx", "__kms_providers")

    def __init__(self, ctx, kms_providers):
        """Abstracts libmongocrypt's mongocrypt_ctx_t type.

        :Parameters:
          - `ctx`: A mongocrypt_ctx_t. This MongoCryptContext takes ownership
            of the underlying mongocrypt_ctx_t.
          - `kms_providers`: The KMS provider map.
        """
        self.__ctx = ctx
        self.__kms_providers = kms_providers

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

    def ask_for_kms_credentials(self):
        """Get on-demand kms credentials"""
        return _ask_for_kms_credentials(self.__kms_providers)

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
        super(EncryptionContext, self).__init__(ctx, kms_providers)
        self.database = database
        try:
            with MongoCryptBinaryIn(command) as binary:
                database = str_to_bytes(database)
                if not lib.mongocrypt_ctx_encrypt_init(
                       ctx, database, len(database), binary.bin):
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
        super(DecryptionContext, self).__init__(ctx, kms_providers)
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
        super(ExplicitEncryptionContext, self).__init__(ctx, kms_providers)
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
                if not lib.mongocrypt_ctx_setopt_contention_factor(ctx, opts.contention_factor):
                    self._raise_from_status()

            with MongoCryptBinaryIn(value) as binary:
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
        super(ExplicitDecryptionContext, self).__init__(ctx, kms_providers)

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
        super(DataKeyContext, self).__init__(ctx, kms_providers)
        try:
            if kms_provider not in ['aws', 'gcp', 'azure', 'kmip', 'local']:
                raise ValueError('unknown kms_provider: %s' % (kms_provider,))

            if opts is None or opts.master_key is None:
                if kms_provider in ['kmip', 'local']:
                    master_key = {}
                else:
                    raise ValueError(
                        'master_key is required for kms_provider: "%s"' % (
                            kms_provider,))
            else:
                master_key = opts.master_key.copy()

            if kms_provider == 'aws':
                if ('region' not in master_key or
                        'key' not in master_key):
                    raise ValueError(
                        'master_key must include "region" and "key" for '
                        'kms_provider: "aws"')
            elif kms_provider == 'azure':
                if ('keyName' not in master_key or
                        'keyVaultEndpoint' not in master_key):
                    raise ValueError(
                        'master key must include "keyName" and '
                        '"keyVaultEndpoint" for kms_provider: "azure"')
            elif kms_provider == 'gcp':
                if ('projectId' not in master_key or
                        'location' not in master_key or
                        'keyRing' not in master_key or
                        'keyName' not in master_key):
                    raise ValueError(
                        'master key must include "projectId", "location",'
                        '"keyRing", and "keyName" for kms_provider: "gcp"')

            master_key['provider'] = kms_provider
            with MongoCryptBinaryIn(
                    callback.bson_encode(master_key)) as mkey:
                if not lib.mongocrypt_ctx_setopt_key_encryption_key(
                        ctx, mkey.bin):
                    self._raise_from_status()

            if opts.key_alt_names:
                for key_alt_name in opts.key_alt_names:
                    with MongoCryptBinaryIn(key_alt_name) as binary:
                        if not lib.mongocrypt_ctx_setopt_key_alt_name(
                                ctx, binary.bin):
                            self._raise_from_status()

            if opts.key_material:
                with MongoCryptBinaryIn(opts.key_material) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_material(
                            ctx, binary.bin):
                        self._raise_from_status()

            if not lib.mongocrypt_ctx_datakey_init(ctx):
                self._raise_from_status()
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

    @property
    def kms_provider(self):
        """The KMS provider identifier associated with this KMS request.

        :Returns:
          The KMS provider as a string, eg "aws", "azure", "gcp", or "kmip".

        .. versionadded:: 1.2
        """
        return _to_string(
            lib.mongocrypt_kms_ctx_get_kms_provider(self.__ctx, ffi.NULL))

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


class RewrapManyDataKeyContext(MongoCryptContext):
    __slots__ = ()

    def __init__(self, ctx, kms_providers, filter, provider, master_key,
        callback):
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
        super(RewrapManyDataKeyContext, self).__init__(ctx, kms_providers)
        key_encryption_key_bson = None
        if provider is not None:
            data = dict(provider=provider)
            if master_key:
                data.update(master_key)
            key_encryption_key_bson = callback.bson_encode(data)

        try:
            if key_encryption_key_bson:
                with MongoCryptBinaryIn(key_encryption_key_bson) as binary:
                    if not lib.mongocrypt_ctx_setopt_key_encryption_key(ctx, binary.bin):
                        self._raise_from_status()

            filter_bson = callback.bson_encode(filter)

            with MongoCryptBinaryIn(filter_bson) as binary:
                if not lib.mongocrypt_ctx_rewrap_many_datakey_init(ctx, binary.bin):
                    self._raise_from_status()
        except Exception:
            # Destroy the context on error.
            self._close()
            raise
