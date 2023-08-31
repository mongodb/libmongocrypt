/*
 * Copyright 2023-present MongoDB, Inc.
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

package com.mongodb.crypt.benchmark;

import com.mongodb.crypt.capi.*;
import org.bson.*;

import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class BenchmarkRunner {
    static final int NUM_FIELDS = 1500;
    static final int NUM_WARMUP_SECS = 2;
    static final int NUM_SECS = 10;
    static final byte[] LOCAL_MASTER_KEY = new byte[]{
            -99, -108, 75, 13, -109, -48, -59, 68, -91, 114, -3, 50, 27, -108, 48, -112, 35, 53,
            115, 124, -16, -10, -62, -12, -38, 35, 86, -25, -113, 4, -52, -6, -34, 117, -76, 81,
            -121, -13, -117, -105, -41, 75, 68, 59, -84, 57, -94, -58, 77, -111, 0, 62, -47, -6, 74,
            48, -63, -46, -58, 94, -5, -84, 65, -14, 72, 19, 60, -101, 80, -4, -89, 36, 122, 46, 2,
            99, -93, -58, 22, 37, 81, 80, 120, 62, 15, -40, 110, -124, -90, -20, -115, 45, 36, 71,
            -27, -81
    };

    private static String getFileAsString(final String fileName) {
        try {
            URL resource = BenchmarkRunner.class.getResource("/" + fileName);
            if (resource == null) {
                throw new RuntimeException("Could not find file " + fileName);
            }
            return Files.readString(Path.of(resource.toURI()));
        } catch (Throwable t) {
            throw new RuntimeException("Could not parse file " + fileName, t);
        }
    }

    private static BsonDocument getResourceAsDocument(final String fileName) {
        return BsonDocument.parse(getFileAsString(fileName));
    }

    private static MongoCrypt createMongoCrypt() {
        return MongoCrypts.create(MongoCryptOptions
                .builder()
                .localKmsProviderOptions(MongoLocalKmsProviderOptions.builder()
                        .localMasterKey(ByteBuffer.wrap(LOCAL_MASTER_KEY))
                        .build())
                .build());
    }

    private static long measureMedianOpsPerSecOfDecrypt(MongoCrypt mongoCrypt, BsonDocument toDecrypt, int numSecs) {
        ArrayList<Long> opsPerSecs = new ArrayList<Long>(numSecs);
        for (int i = 0; i < numSecs; i++) {
            long opsPerSec = 0;
            long start = System.nanoTime();
            // Run for one second.
            while (System.nanoTime() - start < 1_000_000_000) {
                try (MongoCryptContext ctx = mongoCrypt.createDecryptionContext(toDecrypt)) {
                    assert ctx.getState() == MongoCryptContext.State.READY;
                    ctx.finish();
                    opsPerSec++;
                }
            }
            opsPerSecs.add(opsPerSec);
        }
        Collections.sort(opsPerSecs);
        return opsPerSecs.get(numSecs / 2);
    }

    public static void main(String[] args) throws IOException {
        System.out.printf("BenchmarkRunner is using libmongocrypt version=%s, NUM_WARMUP_SECS=%d, NUM_SECS=%d%n", CAPI.mongocrypt_version(null).toString(), NUM_WARMUP_SECS, NUM_SECS);
        // `keyDocument` is a Data Encryption Key (DEK) encrypted with the Key Encryption Key (KEK) `LOCAL_MASTER_KEY`.
        BsonDocument keyDocument = getResourceAsDocument("keyDocument.json");
        try (MongoCrypt mongoCrypt = createMongoCrypt()) {
            // `encrypted` will contain encrypted fields.
            BsonDocument encrypted = new BsonDocument();
            {
                for (int i = 0; i < NUM_FIELDS; i++) {
                    MongoExplicitEncryptOptions options = MongoExplicitEncryptOptions.builder()
                            .keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, Base64.getDecoder().decode("YWFhYWFhYWFhYWFhYWFhYQ==")))
                            .algorithm("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
                            .build();
                    BsonDocument toEncrypt = new BsonDocument("v", new BsonString(String.format("value %04d", i)));
                    try (MongoCryptContext ctx = mongoCrypt.createExplicitEncryptionContext(toEncrypt, options)) {
                        // If mongocrypt_t has not yet cached the DEK, supply it.
                        if (MongoCryptContext.State.NEED_MONGO_KEYS == ctx.getState()) {
                            ctx.addMongoOperationResult(keyDocument);
                            ctx.completeMongoOperation();
                        }
                        assert ctx.getState() == MongoCryptContext.State.READY;
                        RawBsonDocument result = ctx.finish();
                        BsonValue encryptedValue = result.get("v");
                        String key = String.format("key%04d", i);
                        encrypted.append(key, encryptedValue);
                    }
                }
            }

            String created_at = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
            // Warm up benchmark and discard the result.
            measureMedianOpsPerSecOfDecrypt(mongoCrypt, encrypted, NUM_WARMUP_SECS);
            // Decrypt `encrypted` and measure ops/sec.
            long medianOpsPerSec = measureMedianOpsPerSecOfDecrypt(mongoCrypt, encrypted, NUM_SECS);
            System.out.printf("Decrypting 1500 fields median ops/sec : %d%n", medianOpsPerSec);
            String completed_at = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);

            // Print the results in JSON that can be accepted by the `perf.send` command.
            // See https://docs.devprod.prod.corp.mongodb.com/evergreen/Project-Configuration/Project-Commands#perfsend for the expected `perf.send` input.
            BsonDocument results = new BsonDocument().append("results", new BsonArray(
                    Arrays.asList(
                            new BsonDocument()
                                    .append("info", new BsonDocument().append("test_name", new BsonString("java_decrypt_1500")))
                                    .append("created_at", new BsonString(created_at))
                                    .append("completed_at", new BsonString(completed_at))
                                    .append("artifacts", new BsonArray())
                                    .append("metrics", new BsonArray(Arrays.asList(
                                            new BsonDocument()
                                                    .append("name", new BsonString("medianOpsPerSec"))
                                                    .append("type", new BsonString("THROUGHPUT"))
                                                    .append("value", new BsonInt64(medianOpsPerSec))
                                    )))
                                    .append("sub_tests", new BsonArray())
                    )
            ));
            String resultsString = results.toJson();
            // Remove the prefix and suffix when writing to a file so only the [ ... ] array is included.
            resultsString = resultsString.substring("{\"results\": ".length(), resultsString.length() - 1);

            String resultsFilePath = "results.json";
            try (OutputStreamWriter fileWriter = new OutputStreamWriter(new FileOutputStream(resultsFilePath), StandardCharsets.UTF_8)) {
                fileWriter.write(resultsString);
            }
            System.out.println("Results written to file: " + resultsFilePath);
        }
    }
}
