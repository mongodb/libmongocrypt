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

import com.mongodb.crypt.capi.CAPI.mongocrypt_binary_t;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import org.bson.BsonBinaryWriter;
import org.bson.BsonDocument;
import org.bson.RawBsonDocument;
import org.bson.codecs.BsonValueCodecProvider;
import org.bson.codecs.Codec;
import org.bson.codecs.EncoderContext;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.io.BasicOutputBuffer;

import java.nio.ByteBuffer;

import static com.mongodb.crypt.capi.CAPI.mongocrypt_binary_data;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_binary_len;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_binary_new_from_data;

final class CAPIHelper {

    private static final CodecRegistry CODEC_REGISTRY = CodecRegistries.fromProviders(new BsonValueCodecProvider());

    @SuppressWarnings("unchecked")
    static mongocrypt_binary_t toBinary(final BsonDocument document) {
        BasicOutputBuffer buffer = new BasicOutputBuffer();
        BsonBinaryWriter writer = new BsonBinaryWriter(buffer);
        ((Codec<BsonDocument>) CODEC_REGISTRY.get(document.getClass())).encode(writer, document, EncoderContext.builder().build());

        Pointer pointer = new Memory(buffer.size());
        pointer.write(0, buffer.getInternalBuffer(), 0, buffer.size());

        return mongocrypt_binary_new_from_data(pointer, buffer.getSize());
    }

    static RawBsonDocument toDocument(final mongocrypt_binary_t binary) {
        ByteBuffer byteBuffer = toByteBuffer(binary);
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        return new RawBsonDocument(bytes);
    }

    static mongocrypt_binary_t toBinary(final ByteBuffer buffer) {
        byte[] message = new byte[buffer.remaining()];
        buffer.get(message, 0, buffer.remaining());

        Pointer pointer = new Memory(message.length);
        pointer.write(0, message, 0, message.length);

        return mongocrypt_binary_new_from_data(pointer, message.length);
    }

    static ByteBuffer toByteBuffer(final mongocrypt_binary_t binary) {
        Pointer pointer = mongocrypt_binary_data(binary);
        int length = mongocrypt_binary_len(binary);
        return pointer.getByteBuffer(0, length);
    }

    private CAPIHelper() {
    }
}
