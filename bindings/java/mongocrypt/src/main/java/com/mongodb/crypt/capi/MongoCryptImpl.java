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
import com.mongodb.crypt.capi.CAPI.mongocrypt_binary_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_log_fn_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_status_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_t;
import com.sun.jna.Pointer;
import org.bson.BsonDocument;
import org.bson.BsonString;

import java.nio.ByteBuffer;
import java.util.Map;

import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_ERROR;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_FATAL;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_INFO;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_TRACE;
import static com.mongodb.crypt.capi.CAPI.MONGOCRYPT_LOG_LEVEL_WARNING;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_binary_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_datakey_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_decrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_encrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_explicit_decrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_explicit_encrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_new;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_algorithm;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_key_alt_name;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_key_id;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_masterkey_aws;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_masterkey_local;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_new;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_provider_aws;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_provider_local;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_log_handler;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_schema_map;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_new;
import static com.mongodb.crypt.capi.CAPIHelper.toBinary;
import static org.bson.assertions.Assertions.isTrue;
import static org.bson.assertions.Assertions.notNull;

class MongoCryptImpl implements MongoCrypt {
    private static final Logger LOGGER = Loggers.getLogger();

    private final mongocrypt_t wrapped;
    private volatile boolean closed;

    MongoCryptImpl(final MongoCryptOptions options) {
        wrapped = mongocrypt_new();
        if (wrapped == null) {
            throw new MongoCryptException("Unable to create new mongocrypt object");
        }

        boolean success;

        success = mongocrypt_setopt_log_handler(wrapped, new LogCallback(), null);
        if (!success) {
            throwExceptionFromStatus();
        }

        if (options.getLocalKmsProviderOptions() != null) {
            mongocrypt_binary_t localMasterKeyBinary = toBinary(options.getLocalKmsProviderOptions().getLocalMasterKey());
            try {
                success = mongocrypt_setopt_kms_provider_local(wrapped, localMasterKeyBinary);
                if (!success) {
                    throwExceptionFromStatus();
                }
            } finally {
                mongocrypt_binary_destroy(localMasterKeyBinary);
            }
        }

        if (options.getAwsKmsProviderOptions() != null) {
            success = mongocrypt_setopt_kms_provider_aws(wrapped,
                    new cstring(options.getAwsKmsProviderOptions().getAccessKeyId()), -1,
                    new cstring(options.getAwsKmsProviderOptions().getSecretAccessKey()), -1);
            if (!success) {
                throwExceptionFromStatus();
            }
        }

        if (options.getLocalSchemaMap() != null) {
            BsonDocument localSchemaMapDocument = new BsonDocument();
            for (Map.Entry<String, BsonDocument> cur: options.getLocalSchemaMap().entrySet()) {
                localSchemaMapDocument.put(cur.getKey(), cur.getValue());
            }

            mongocrypt_binary_t localSchemaMapBinary = toBinary(localSchemaMapDocument);
            try {
                success = mongocrypt_setopt_schema_map(wrapped, localSchemaMapBinary);
                if (!success) {
                    throwExceptionFromStatus();
                }
            } finally {
                mongocrypt_binary_destroy(localSchemaMapBinary);
            }
        }
        
        success = mongocrypt_init(wrapped);
        if (!success) {
            throwExceptionFromStatus();
        }
    }

    @Override
    public MongoCryptContext createEncryptionContext(final String database, final BsonDocument commandDocument) {
        isTrue("open", !closed);
        notNull("database", database);
        notNull("commandDocument", commandDocument);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        mongocrypt_binary_t commandDocumentBinary = toBinary(commandDocument);

        try {
            boolean success = mongocrypt_ctx_encrypt_init(context, new cstring(database), -1, commandDocumentBinary);

            if (!success) {
                MongoCryptContextImpl.throwExceptionFromStatus(context);
            }
            return new MongoCryptContextImpl(context);
        } finally {
            mongocrypt_binary_destroy(commandDocumentBinary);
        }
    }

    @Override
    public MongoCryptContext createDecryptionContext(final BsonDocument document) {
        isTrue("open", !closed);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        mongocrypt_binary_t documentBinary = toBinary(document);
        try {
            boolean success = mongocrypt_ctx_decrypt_init(context, documentBinary);
            if (!success) {
                MongoCryptContextImpl.throwExceptionFromStatus(context);
            }
        } finally {
            mongocrypt_binary_destroy(documentBinary);
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createDataKeyContext(final String kmsProvider, final MongoDataKeyOptions options) {
        isTrue("open", !closed);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        boolean success;

        if (kmsProvider.equals("aws")) {
            success = mongocrypt_ctx_setopt_masterkey_aws(context,
                    new cstring(options.getMasterKey().getString("region").getValue()), -1,
                    new cstring(options.getMasterKey().getString("key").getValue()), -1);
        } else if (kmsProvider.equals("local")) {
            success = mongocrypt_ctx_setopt_masterkey_local(context);
        } else {
            throw new IllegalArgumentException("Unsupported KMS provider " + kmsProvider);
        }

        if (!success) {
            MongoCryptContextImpl.throwExceptionFromStatus(context);
        }

        success = mongocrypt_ctx_datakey_init(context);
        if (!success) {
            MongoCryptContextImpl.throwExceptionFromStatus(context);
        }

        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createExplicitEncryptionContext(final BsonDocument document, final MongoExplicitEncryptOptions options) {
        isTrue("open", !closed);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        boolean success;

        if (options.getKeyId() != null) {
            mongocrypt_binary_t keyIdBinary = toBinary(ByteBuffer.wrap(options.getKeyId().getData()));
            try {
                success = mongocrypt_ctx_setopt_key_id(context, keyIdBinary);
                if (!success) {
                    MongoCryptContextImpl.throwExceptionFromStatus(context);
                }
            } finally {
                mongocrypt_binary_destroy(keyIdBinary);
            }
        } else if (options.getKeyAltName() != null) {
            mongocrypt_binary_t keyAltNameBinary = toBinary(new BsonDocument("keyAltName", new BsonString(options.getKeyAltName())));
            try {
                success = mongocrypt_ctx_setopt_key_alt_name(context, keyAltNameBinary);
                if (!success) {
                    MongoCryptContextImpl.throwExceptionFromStatus(context);
                }
            } finally {
                mongocrypt_binary_destroy(keyAltNameBinary);
            }
        }

        success = mongocrypt_ctx_setopt_algorithm(context, new cstring(options.getAlgorithm()), -1);
        if (!success) {
            MongoCryptContextImpl.throwExceptionFromStatus(context);
        }

        mongocrypt_binary_t documentBinary = toBinary(document);
        try {
            success = mongocrypt_ctx_explicit_encrypt_init(context, documentBinary);
            if (!success) {
                MongoCryptContextImpl.throwExceptionFromStatus(context);
            }
        } finally {
            mongocrypt_binary_destroy(documentBinary);
        }

        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createExplicitDecryptionContext(final BsonDocument document) {
        isTrue("open", !closed);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        boolean success = mongocrypt_ctx_explicit_decrypt_init(context, toBinary(document));
        if (!success) {
            MongoCryptContextImpl.throwExceptionFromStatus(context);
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public void close() {
        mongocrypt_destroy(wrapped);
        closed = true;
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
