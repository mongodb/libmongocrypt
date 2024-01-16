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

import org.bson.BsonBinaryWriter;
import org.bson.BsonDocument;
import org.bson.RawBsonDocument;
import org.bson.codecs.BsonDocumentCodec;
import org.bson.codecs.EncoderContext;
import org.bson.io.BasicOutputBuffer;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import static com.mongodb.crypt.capi.ffa.generated.mongocrypt_h.mongocrypt_binary_new_from_data;


final class ForeignHelper {

    static MemorySegment toBinary(final ByteBuffer buffer, Arena arena) {
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes, 0, buffer.remaining());
        return toBinary(bytes, arena);
    }

    static MemorySegment toBinary(byte[] bytes, Arena arena) {
        var byteSegment = arena.allocateArray(ValueLayout.JAVA_BYTE, bytes);
        return mongocrypt_binary_new_from_data(byteSegment, bytes.length);
    }

    static MemorySegment documentToSegment(BsonDocument document, Arena arena) {
        var outputBuffer = new BasicOutputBuffer();
        var writer = new BsonBinaryWriter(outputBuffer);
        new BsonDocumentCodec().encode(writer, document, EncoderContext.builder().build());
        return toBinary(outputBuffer.toByteArray(), arena);
    }

    static RawBsonDocument toDocument(final MemorySegment binary) {
        var bytes = toByteArray(binary);
        return new RawBsonDocument(bytes);
    }

    static byte[] toByteArray(final MemorySegment binary) {
        // TODO: use AddressLayout?
        var length = binary.get(ValueLayout.JAVA_INT, 8);  // TODO: assumes pointer size of 8
        var dataAddress = binary.get(ValueLayout.JAVA_LONG, 0);
        var dataSegment = MemorySegment.ofAddress(dataAddress).reinterpret(length);
        var bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = dataSegment.get(ValueLayout.JAVA_BYTE, i);
        }
        return bytes;
    }
}
