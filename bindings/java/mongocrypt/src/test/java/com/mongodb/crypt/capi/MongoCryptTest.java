/*
 * Copyright 2008-present MongoDB, Inc.
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

import com.mongodb.crypt.capi.MongoCryptContext.State;
import org.bson.BsonDocument;
import org.bson.codecs.BsonDocumentCodec;
import org.bson.codecs.DecoderContext;
import org.bson.json.JsonReader;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@SuppressWarnings("SameParameterValue")
public class MongoCryptTest {
    @Test
    public void testEncrypt() throws URISyntaxException, IOException {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        MongoCryptContext encryptor = mongoCrypt.createEncryptionContext("test.test", null);

        assertEquals(State.NEED_MONGO_COLLINFO, encryptor.getState());

        BsonDocument listCollectionsFilter = encryptor.getMongoOperation();
        assertEquals(getResourceAsDocument("list-collections-filter.json"), listCollectionsFilter);

        encryptor.addMongoOperationResult(getResourceAsDocument("collection-info.json"));
        encryptor.completeMongoOperation();
        assertEquals(State.NEED_MONGO_MARKINGS, encryptor.getState());

        BsonDocument jsonSchema = encryptor.getMongoOperation();
        assertEquals(getResourceAsDocument("json-schema.json"), jsonSchema);

        encryptor.addMongoOperationResult(getResourceAsDocument("mongocryptd-reply.json"));
        encryptor.completeMongoOperation();
        assertEquals(State.NEED_MONGO_KEYS, encryptor.getState());

        testkeyBroker(encryptor);

        assertEquals(State.READY, encryptor.getState());

        BsonDocument encryptedDocument = encryptor.finish();
        assertEquals(State.DONE, encryptor.getState());
        assertEquals(getResourceAsDocument("encrypted-command.json"), encryptedDocument);

        encryptor.close();

        mongoCrypt.close();
    }


    @Test
    public void testDecrypt() throws IOException, URISyntaxException {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        MongoCryptContext decryptor = mongoCrypt.createDecryptionContext(getResourceAsDocument("encrypted-command-reply.json"));

        assertEquals(State.NEED_MONGO_KEYS, decryptor.getState());

        testkeyBroker(decryptor);

        assertEquals(State.READY, decryptor.getState());

        BsonDocument decryptedDocument = decryptor.finish();
        assertEquals(State.DONE, decryptor.getState());
        assertEquals(getResourceAsDocument("command-reply.json"), decryptedDocument);

        decryptor.close();

        mongoCrypt.close();
    }

    private void testkeyBroker(final MongoCryptContext context) throws URISyntaxException, IOException {
        BsonDocument keyFilter = context.getMongoOperation();
        assertEquals(getResourceAsDocument("key-filter.json"), keyFilter);
        context.addMongoOperationResult(getResourceAsDocument("key-document.json"));
        context.completeMongoOperation();
        assertEquals(State.NEED_KMS, context.getState());

        MongoKeyDecryptor keyDecryptor = context.nextKeyDecryptor();

        // TODO: get this working
        assertEquals("kms.us-east-1.amazonaws.com", keyDecryptor.getHostName());

        ByteBuffer keyDecryptorMessage = keyDecryptor.getMessage();
        assertEquals(741, keyDecryptorMessage.remaining());

        int bytesNeeded = keyDecryptor.bytesNeeded();
        assertEquals(1024, bytesNeeded);

        keyDecryptor.feed(getHttpResourceAsByteBuffer("kms-reply.txt"));
        bytesNeeded = keyDecryptor.bytesNeeded();
        assertEquals(0, bytesNeeded); // WHY IS THIS STILL EQUAL TO 1024?

        assertNull(context.nextKeyDecryptor());

        context.completeKeyDecryptors();
    }
    
    private MongoCrypt createMongoCrypt() {
        return MongoCrypts.create(MongoCryptOptions
                .builder()
                .awsKmsProviderOptions(MongoAwsKmsProviderOptions.builder()
                        .accessKeyId("example")
                        .secretAccessKey("example")
                        .build())
                .build());
    }

    private static BsonDocument getResourceAsDocument(final String fileName) throws URISyntaxException, IOException {
        URL resource = MongoCryptTest.class.getResource("/" + fileName);
        if (resource == null) {
            throw new RuntimeException("Could not find file " + fileName);
        }
        File resourceFile = new File(resource.toURI());
        return new BsonDocumentCodec().decode(new JsonReader(getFileAsString(resourceFile, System.getProperty("line.separator"))),
                DecoderContext.builder().build());
    }

    private static ByteBuffer getHttpResourceAsByteBuffer(final String fileName) throws URISyntaxException, IOException {
        URL resource = MongoCryptTest.class.getResource("/" + fileName);
        File resourceFile = new File(resource.toURI());
        return ByteBuffer.wrap(getFileAsString(resourceFile, "\r\n").getBytes(Charset.forName("UTF-8")));
    }

    private static String getFileAsString(final File file, String lineSeparator) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), Charset.forName("UTF-8")))) {
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                if (!first) {
                    stringBuilder.append(lineSeparator);
                }
                first = false;
                stringBuilder.append(line);
            }
        }
        return stringBuilder.toString();
    }
}
