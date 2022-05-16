/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.mongodb.crypt.capi;

import com.mongodb.crypt.capi.CAPI.cstring;
import com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_log_fn_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_status_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_t;
import com.sun.jna.Pointer;
import org.bson.BsonDocument;
import org.bson.BsonString;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Supplier;

import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_INDEX_TYPE_EQUALITY;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_INDEX_TYPE_NONE;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_ERROR;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_FATAL;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_INFO;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_TRACE;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_WARNING;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_datakey_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_decrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_encrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_explicit_decrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_explicit_encrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_new;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_algorithm;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_contention_factor;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_index_type;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_key_alt_name;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_key_encryption_key;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_key_id;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_masterkey_aws;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_masterkey_aws_endpoint;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_masterkey_local;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_query_type;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_new;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_aes_256_ctr;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_bypass_query_analysis;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_crypto_hooks;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_encrypted_field_config_map;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_provider_aws;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_provider_local;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_providers;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_log_handler;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_schema_map;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_use_need_kms_credentials_state;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_new;
import static com.mongodb.crypt.capi.CAPIHelper.toBinary;
import static org.bson.assertions.Assertions.isTrue;
import static org.bson.assertions.Assertions.notNull;

class MongoCryptImpl implements MongoCrypt {
    private static final Logger LOGGER = Loggers.getLogger();
    private static final String INDEXED = "Indexed";
    private static final String UNINDEXED = "Unindexed";

    private final mongocrypt_t wrapped;

    // Keep a strong reference to all the callbacks so that they don't get garbage collected
    @SuppressWarnings("FieldCanBeLocal")
    private final LogCallback logCallback;

    @SuppressWarnings("FieldCanBeLocal")
    private final CipherCallback aesCBC256EncryptCallback;
    @SuppressWarnings("FieldCanBeLocal")
    private final CipherCallback aesCBC256DecryptCallback;
    @SuppressWarnings("FieldCanBeLocal")
    private final CipherCallback aesCTR256EncryptCallback;
    @SuppressWarnings("FieldCanBeLocal")
    private final CipherCallback aesCTR256DecryptCallback;
    @SuppressWarnings("FieldCanBeLocal")
    private final MacCallback hmacSha512Callback;
    @SuppressWarnings("FieldCanBeLocal")
    private final MacCallback hmacSha256Callback;
    @SuppressWarnings("FieldCanBeLocal")
    private final MessageDigestCallback sha256Callback;
    @SuppressWarnings("FieldCanBeLocal")
    private final SecureRandomCallback secureRandomCallback;
    @SuppressWarnings("FieldCanBeLocal")
    private final SigningRSAESPKCSCallback signingRSAESPKCSCallback;

    private final AtomicBoolean closed;

    MongoCryptImpl(final MongoCryptOptions options) {
        closed = new AtomicBoolean();
        wrapped = mongocrypt_new();
        if (wrapped == null) {
            throw new MongoCryptException("Unable to create new mongocrypt object");
        }

        logCallback = new LogCallback();

        configure(() -> mongocrypt_setopt_log_handler(wrapped, logCallback, null));

        // We specify NoPadding here because the underlying C library is responsible for padding prior
        // to executing the callback
        aesCBC256EncryptCallback = new CipherCallback("AES", "AES/CBC/NoPadding", Cipher.ENCRYPT_MODE);
        aesCBC256DecryptCallback = new CipherCallback("AES", "AES/CBC/NoPadding", Cipher.DECRYPT_MODE);
        aesCTR256EncryptCallback = new CipherCallback("AES", "AES/CTR/NoPadding", Cipher.ENCRYPT_MODE);
        aesCTR256DecryptCallback = new CipherCallback("AES", "AES/CTR/NoPadding", Cipher.DECRYPT_MODE);

        hmacSha512Callback = new MacCallback("HmacSHA512");
        hmacSha256Callback = new MacCallback("HmacSHA256");
        sha256Callback = new MessageDigestCallback("SHA-256");
        secureRandomCallback = new SecureRandomCallback(new SecureRandom());

        configure(() -> mongocrypt_setopt_crypto_hooks(wrapped, aesCBC256EncryptCallback, aesCBC256DecryptCallback,
                                                        secureRandomCallback, hmacSha512Callback, hmacSha256Callback,
                                                        sha256Callback, null));

        signingRSAESPKCSCallback = new SigningRSAESPKCSCallback();
        configure(() -> mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5(wrapped, signingRSAESPKCSCallback, null));
        configure(() -> mongocrypt_setopt_aes_256_ctr(wrapped, aesCTR256EncryptCallback, aesCTR256DecryptCallback, null));

        if (options.getLocalKmsProviderOptions() != null) {
            try (BinaryHolder localMasterKeyBinaryHolder = toBinary(options.getLocalKmsProviderOptions().getLocalMasterKey())) {
                configure(() -> mongocrypt_setopt_kms_provider_local(wrapped, localMasterKeyBinaryHolder.getBinary()));
            }
        }

        if (options.getAwsKmsProviderOptions() != null) {
            configure(() -> mongocrypt_setopt_kms_provider_aws(wrapped,
                                                                new cstring(options.getAwsKmsProviderOptions().getAccessKeyId()), -1,
                                                                new cstring(options.getAwsKmsProviderOptions().getSecretAccessKey()), -1));
        }

        if (options.isNeedsKmsCredentialsStateEnabled()) {
            mongocrypt_setopt_use_need_kms_credentials_state(wrapped);
        }

        if (options.getKmsProviderOptions() != null) {
            try (BinaryHolder binaryHolder = toBinary(options.getKmsProviderOptions())) {
                configure(() -> mongocrypt_setopt_kms_providers(wrapped, binaryHolder.getBinary()));
            }
        }

        if (options.getLocalSchemaMap() != null) {
            BsonDocument localSchemaMapDocument = new BsonDocument();
            localSchemaMapDocument.putAll(options.getLocalSchemaMap());

            try (BinaryHolder localSchemaMapBinaryHolder = toBinary(localSchemaMapDocument)) {
                configure(() -> mongocrypt_setopt_schema_map(wrapped, localSchemaMapBinaryHolder.getBinary()));
            }
        }

        if (options.isBypassQueryAnalysis()) {
            mongocrypt_setopt_bypass_query_analysis(wrapped);
        }

        if (options.getEncryptedFieldsMap() != null) {
            BsonDocument localEncryptedFieldsMap = new BsonDocument();
            localEncryptedFieldsMap.putAll(options.getEncryptedFieldsMap());

            try (BinaryHolder localEncryptedFieldsMapHolder = toBinary(localEncryptedFieldsMap)) {
                configure(() -> mongocrypt_setopt_encrypted_field_config_map(wrapped, localEncryptedFieldsMapHolder.getBinary()));
            }
        }

        configure(() -> mongocrypt_init(wrapped));
    }

    @Override
    public MongoCryptContext createEncryptionContext(final String database, final BsonDocument commandDocument) {
        isTrue("open", !closed.get());
        notNull("database", database);
        notNull("commandDocument", commandDocument);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        try (BinaryHolder commandDocumentBinaryHolder = toBinary(commandDocument)) {
            configure(() -> mongocrypt_ctx_encrypt_init(context, new cstring(database), -1,
                                                         commandDocumentBinaryHolder.getBinary()), context);
            return new MongoCryptContextImpl(context);
        }
    }

    @Override
    public MongoCryptContext createDecryptionContext(final BsonDocument document) {
        isTrue("open", !closed.get());
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        try (BinaryHolder documentBinaryHolder = toBinary(document)){
            configure(() -> mongocrypt_ctx_decrypt_init(context, documentBinaryHolder.getBinary()), context);
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createDataKeyContext(final String kmsProvider, final MongoDataKeyOptions options) {
        isTrue("open", !closed.get());
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        if (kmsProvider.equals("aws")) {
            configure(() -> mongocrypt_ctx_setopt_masterkey_aws(context,
                                                                 new cstring(options.getMasterKey().getString("region").getValue()), -1,
                                                                 new cstring(options.getMasterKey().getString("key").getValue()), -1), context);
            if (options.getMasterKey().containsKey("endpoint")) {
                configure(() -> mongocrypt_ctx_setopt_masterkey_aws_endpoint(context,
                                                                              new cstring(options.getMasterKey().getString("endpoint").getValue()), -1), context);
            }
        } else if (kmsProvider.equals("local")) {
            configure(() -> mongocrypt_ctx_setopt_masterkey_local(context), context);
        } else {
            BsonDocument masterKey = options.getMasterKey().clone();
            masterKey.put("provider", new BsonString(kmsProvider));
            try (BinaryHolder masterKeyHolder = toBinary(masterKey)) {
                configure(() -> mongocrypt_ctx_setopt_key_encryption_key(context, masterKeyHolder.getBinary()), context);
            }
        }

        if (options.getKeyAltNames() != null) {
            for (String cur : options.getKeyAltNames()) {
                try (BinaryHolder keyAltNameBinaryHolder = toBinary(new BsonDocument("keyAltName", new BsonString(cur)))) {
                    configure(() -> mongocrypt_ctx_setopt_key_alt_name(context, keyAltNameBinaryHolder.getBinary()), context);
                }
            }
        }

        if (!mongocrypt_ctx_datakey_init(context)) {
            MongoCryptContextImpl.throwExceptionFromStatus(context);
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createExplicitEncryptionContext(final BsonDocument document, final MongoExplicitEncryptOptions options) {
        isTrue("open", !closed.get());
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        if (options.getKeyId() != null) {
            try (BinaryHolder keyIdBinaryHolder = toBinary(ByteBuffer.wrap(options.getKeyId().getData()))) {
                configure(() -> mongocrypt_ctx_setopt_key_id(context, keyIdBinaryHolder.getBinary()), context);
            }
        } else if (options.getKeyAltName() != null) {
            try (BinaryHolder keyAltNameBinaryHolder = toBinary(new BsonDocument("keyAltName", new BsonString(options.getKeyAltName())))) {
                configure(() -> mongocrypt_ctx_setopt_key_alt_name(context, keyAltNameBinaryHolder.getBinary()), context);
            }
        }

        if (INDEXED.equalsIgnoreCase(options.getAlgorithm())) {
            configure(() -> mongocrypt_ctx_setopt_index_type(context, MONGOCRYPT_INDEX_TYPE_EQUALITY), context);
            if (options.getQueryType() != null) {
                configure(() -> mongocrypt_ctx_setopt_query_type(context, options.getQueryType().getQueryType()), context);
            }
            if (options.getContentionFactor() != null) {
                configure(() -> mongocrypt_ctx_setopt_contention_factor(context, options.getContentionFactor()), context);
            }
        } else if (options.getAlgorithm().equalsIgnoreCase(UNINDEXED)) {
            configure(() -> mongocrypt_ctx_setopt_index_type(context, MONGOCRYPT_INDEX_TYPE_NONE), context);
        } else {
            configure(() -> mongocrypt_ctx_setopt_algorithm(context, new cstring(options.getAlgorithm()), -1), context);
        }

        try (BinaryHolder documentBinaryHolder = toBinary(document)) {
            configure(() -> mongocrypt_ctx_explicit_encrypt_init(context, documentBinaryHolder.getBinary()), context);
        }

        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createExplicitDecryptionContext(final BsonDocument document) {
        isTrue("open", !closed.get());
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        try (BinaryHolder binaryHolder = toBinary(document)) {
            configure(() -> mongocrypt_ctx_explicit_decrypt_init(context, binaryHolder.getBinary()), context);
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {
            mongocrypt_destroy(wrapped);
        }
    }

    private void configure(final Supplier<Boolean> successSupplier) {
        if (!successSupplier.get()) {
            throwExceptionFromStatus();
        }
    }

    private void configure(final Supplier<Boolean> successSupplier, final mongocrypt_ctx_t context) {
        if (!successSupplier.get()) {
            MongoCryptContextImpl.throwExceptionFromStatus(context);
        }
    }

    private void throwExceptionFromStatus() {
        mongocrypt_status_t status = mongocrypt_status_new();
        mongocrypt_status(wrapped, status);
        MongoCryptException e = new MongoCryptException(status);
        mongocrypt_status_destroy(status);
        throw e;
    }

    static class LogCallback implements mongocrypt_log_fn_t {
        @Override
        public void log(final int level, final cstring message, final int messageLength, final Pointer ctx) {
            if (level == MONGOCRYPT_LOG_LEVEL_FATAL) {
                LOGGER.error(message.toString());
            }
            if (level == MONGOCRYPT_LOG_LEVEL_ERROR) {
                LOGGER.error(message.toString());
            }
            if (level == MONGOCRYPT_LOG_LEVEL_WARNING) {
                LOGGER.warn(message.toString());
            }
            if (level == MONGOCRYPT_LOG_LEVEL_INFO) {
                LOGGER.info(message.toString());
            }
            if (level == MONGOCRYPT_LOG_LEVEL_TRACE) {
                LOGGER.trace(message.toString());
            }
        }
    }
}
