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

import com.mongodb.crypt.capi.MongoKeyDecryptor;
import com.mongodb.crypt.capi.ffa.generated.mongocrypt_h;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import static com.mongodb.crypt.capi.ffa.ForeignHelper.toBinary;
import static com.mongodb.crypt.capi.ffa.ForeignHelper.toByteArray;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_binary_new;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_kms_ctx_bytes_needed;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_kms_ctx_endpoint;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_kms_ctx_status;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_destroy;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_message;
import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_status_new;

public class ForeignMongoKeyDecryptor implements MongoKeyDecryptor {
    private final MemorySegment wrapped;
    private final Arena arena;

    public ForeignMongoKeyDecryptor(final MemorySegment wrapped, final Arena arena) {
        this.wrapped = wrapped;
        this.arena = arena;
    }

    @Override
    public String getKmsProvider() {
        return mongocrypt_h.mongocrypt_kms_ctx_get_kms_provider(wrapped,
                arena.allocate(ValueLayout.JAVA_INT, Integer.MAX_VALUE)).getUtf8String(0);
    }

    @Override
    public String getHostName() {
        MemorySegment hostNamePointer = arena.allocate(ValueLayout.ADDRESS);
        var success = mongocrypt_kms_ctx_endpoint(wrapped, hostNamePointer);
        if (!success) {
            throwExceptionFromStatus();
        }
        var hostNameSegment = hostNamePointer.get(ValueLayout.ADDRESS, 0);
        // TODO: Not sure how to do this without knowing the size to reinterpret as.
        // Using 256 as a max host name size, relying on the null terminator to not go past the end
        return hostNameSegment.reinterpret(256).getUtf8String(0);
    }

    @Override
    public ByteBuffer getMessage() {
        var binarySegment = mongocrypt_binary_new();

        try {
            var success = mongocrypt_h.mongocrypt_kms_ctx_message(wrapped, binarySegment);
            if (!success) {
                throwExceptionFromStatus();
            }
            return ByteBuffer.wrap(toByteArray(binarySegment));
        } finally {
            mongocrypt_h.mongocrypt_binary_destroy(binarySegment);
        }
    }

    @Override
    public int bytesNeeded() {
        return mongocrypt_kms_ctx_bytes_needed(wrapped);
    }

    @Override
    public void feed(ByteBuffer bytes) {
        var binarySegment = toBinary(bytes, arena);
        var success = mongocrypt_h.mongocrypt_kms_ctx_feed(wrapped, binarySegment);
        if (!success) {
            throwExceptionFromStatus();
        }
    }

    private void throwExceptionFromStatus() {
        var status = mongocrypt_status_new();
        mongocrypt_kms_ctx_status(wrapped, status);

        var messageSegment = mongocrypt_status_message(status, MemorySegment.NULL);
        var message = messageSegment.getUtf8String(0);
        mongocrypt_status_destroy(status);
        throw new RuntimeException(message);
    }
}
