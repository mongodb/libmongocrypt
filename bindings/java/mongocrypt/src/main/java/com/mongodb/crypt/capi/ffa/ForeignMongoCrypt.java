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

package com.mongodb.crypt.capi.ffa;

import com.mongodb.crypt.capi.MongoCrypt;
import com.mongodb.crypt.capi.MongoCryptContext;
import com.mongodb.crypt.capi.MongoCryptOptions;
import com.mongodb.crypt.capi.MongoDataKeyOptions;
import com.mongodb.crypt.capi.MongoExplicitEncryptOptions;
import com.mongodb.crypt.capi.MongoRewrapManyDataKeyOptions;
import com.mongodb.crypt.capi.ffa.generated.mongocrypt_h;
import org.bson.BsonDocument;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static com.mongodb.crypt.capi.ffa.ForeignHelper.documentToSegment;
import static com.mongodb.crypt.capi.ffa.ForeignHelper.toBinary;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_decrypt_init;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_explicit_decrypt_init;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_explicit_encrypt_init;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_new;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_destroy;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_init;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_new;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_setopt_kms_provider_aws;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_setopt_kms_provider_local;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_destroy;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_message;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_new;
import static org.bson.assertions.Assertions.isTrue;

/**
 * Not part of the public API
 */
public class ForeignMongoCrypt implements MongoCrypt {
    private final MemorySegment wrapped;
    private final Arena arena = Arena.ofShared();
    private final AtomicBoolean closed = new AtomicBoolean();

    public ForeignMongoCrypt(final MongoCryptOptions options) {
        wrapped = mongocrypt_new();

        if (options.getAwsKmsProviderOptions() != null) {
            configure(() -> mongocrypt_setopt_kms_provider_aws(wrapped,
                    arena.allocateUtf8String(options.getAwsKmsProviderOptions().getAccessKeyId()), -1,
                    arena.allocateUtf8String(options.getAwsKmsProviderOptions().getSecretAccessKey()), -1));
        }

        if (options.getLocalKmsProviderOptions() != null) {
            configure(() -> {
                final ByteBuffer buffer = options.getLocalKmsProviderOptions().getLocalMasterKey();
                return mongocrypt_setopt_kms_provider_local(wrapped, toBinary(buffer, arena));
            });
        }
        configure(() -> mongocrypt_init(wrapped));
    }

    @Override
    public MongoCryptContext createEncryptionContext(String database, BsonDocument command) {
        var context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        var arena = Arena.ofShared();
        var documentSegment = documentToSegment(command, arena);
        // TODO: JNA impl passes `context` to configure.  Is that needed here too?
        configure(() -> mongocrypt_h.mongocrypt_ctx_encrypt_init(context, arena.allocateUtf8String(database), -1, documentSegment));
        return new ForeignMongoCryptContext(context, arena);
    }

    @Override
    public MongoCryptContext createDecryptionContext(BsonDocument document) {
        isTrue("open", !closed.get());
        var context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        var arena = Arena.ofShared();
        var documentSegment = documentToSegment(document, arena);
        configure(() -> mongocrypt_ctx_decrypt_init(context, documentSegment));

        return new ForeignMongoCryptContext(context, arena);
    }

    @Override
    public MongoCryptContext createDataKeyContext(String kmsProvider, MongoDataKeyOptions options) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MongoCryptContext createExplicitEncryptionContext(BsonDocument document, MongoExplicitEncryptOptions options) {
        isTrue("open", !closed.get());
        var arena = Arena.ofShared();
        var context = configureExplicitEncryption(options);
        configure(() -> mongocrypt_ctx_explicit_encrypt_init(context, documentToSegment(document, arena)));
        return new ForeignMongoCryptContext(context, arena);
    }

    private MemorySegment configureExplicitEncryption(final MongoExplicitEncryptOptions options) {
        var context = mongocrypt_ctx_new(wrapped);
        if (context.equals(MemorySegment.NULL)) {
            throwExceptionFromStatus();
        }

        if (options.getKeyId() != null) {
            configure(() -> {
                byte[] bytes = options.getKeyId().getData();
                return mongocrypt_h.mongocrypt_ctx_setopt_key_id(context, toBinary(bytes, arena));
            });
        }

        if (options.getAlgorithm() != null) {
            configure(() -> mongocrypt_h.mongocrypt_ctx_setopt_algorithm(context,
                    arena.allocateUtf8String(options.getAlgorithm()), -1));
        }

        return context;
    }

    @Override
    public MongoCryptContext createEncryptExpressionContext(BsonDocument document, MongoExplicitEncryptOptions options) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MongoCryptContext createExplicitDecryptionContext(BsonDocument document) {
        isTrue("open", !closed.get());

        var arena = Arena.ofShared();
        var context = mongocrypt_ctx_new(wrapped);
        if (context.equals(MemorySegment.NULL)) {
            throwExceptionFromStatus();
        }

        configure(() -> mongocrypt_ctx_explicit_decrypt_init(context, documentToSegment(document, arena)));

        return new ForeignMongoCryptContext(context, arena);
    }

    @Override
    public MongoCryptContext createRewrapManyDatakeyContext(BsonDocument filter, MongoRewrapManyDataKeyOptions options) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getCryptSharedLibVersionString() {
        throw new UnsupportedOperationException();
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

    private void throwExceptionFromStatus() {
        var status = mongocrypt_status_new();
        mongocrypt_status(wrapped, status);

        var messageSegment = mongocrypt_status_message(status, MemorySegment.NULL);
        var message = messageSegment.getUtf8String(0);
        mongocrypt_status_destroy(status);
        throw new RuntimeException(message);
    }
}
