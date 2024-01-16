/*
 * Copyright (c) 2008 - 2013 10gen, Inc. <http://10gen.com>
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

import com.mongodb.crypt.capi.MongoCryptContext;
import com.mongodb.crypt.capi.MongoKeyDecryptor;
import org.bson.BsonDocument;
import org.bson.RawBsonDocument;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.mongodb.crypt.capi.ffa.ForeignHelper.documentToSegment;
import static com.mongodb.crypt.capi.ffa.ForeignHelper.toDocument;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_binary_destroy;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_binary_new;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_destroy;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_finalize;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_kms_done;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_mongo_done;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_mongo_feed;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_mongo_op;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_next_kms_ctx;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_state;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_ctx_status;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_destroy;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_message;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_new;

public class ForeignMongoCryptContext implements MongoCryptContext {
    private final MemorySegment wrapped;
    private final Arena arena;
    private final AtomicBoolean closed = new AtomicBoolean();

    public ForeignMongoCryptContext(MemorySegment wrapped, Arena arena) {
        this.wrapped = wrapped;
        this.arena = arena;
    }

    @Override
    public State getState() {
        var index = mongocrypt_ctx_state(wrapped);
        return State.fromIndex(index);
    }

    @Override
    public RawBsonDocument getMongoOperation() {
        var binary = mongocrypt_binary_new();
        try {
            var success = mongocrypt_ctx_mongo_op(wrapped, binary);
            if (!success) {
                throwExceptionFromStatus();
            }
            return toDocument(binary);
        } finally {
            mongocrypt_binary_destroy(binary);
        }
    }

    @Override
    public void addMongoOperationResult(BsonDocument document) {
        var binarySegment = documentToSegment(document, arena);
        boolean success = mongocrypt_ctx_mongo_feed(wrapped, binarySegment);
        if (!success) {
            throwExceptionFromStatus();
        }
        mongocrypt_binary_destroy(binarySegment);
    }

    @Override
    public void completeMongoOperation() {
        var success = mongocrypt_ctx_mongo_done(wrapped);
        if (!success) {
            throwExceptionFromStatus();
        }
    }

    @Override
    public void provideKmsProviderCredentials(BsonDocument credentialsDocument) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MongoKeyDecryptor nextKeyDecryptor() {
        var kmsContext = mongocrypt_ctx_next_kms_ctx(wrapped);
        if (kmsContext.equals(MemorySegment.NULL)) {
            return null;
        }
        return new ForeignMongoKeyDecryptor(kmsContext, arena);
    }

    @Override
    public void completeKeyDecryptors() {
        var success = mongocrypt_ctx_kms_done(wrapped);
        if (!success) {
            throwExceptionFromStatus();
        }
    }

    @Override
    public RawBsonDocument finish() {
        var binary = mongocrypt_binary_new();
        try {
            var success = mongocrypt_ctx_finalize(wrapped, binary);
            if (!success) {
                throwExceptionFromStatus();
            }
            return toDocument(binary);
        } finally {
            mongocrypt_binary_destroy(binary);
        }
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {
            mongocrypt_ctx_destroy(wrapped);
            arena.close();
        }
    }

    private void throwExceptionFromStatus() {
        var status = mongocrypt_status_new();
        mongocrypt_ctx_status(wrapped, status);

        var messageSegment = mongocrypt_status_message(status, MemorySegment.NULL);
        var message = messageSegment.getUtf8String(0);
        mongocrypt_status_destroy(status);
        throw new RuntimeException(message);
    }
}
