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
import com.mongodb.crypt.capi.jna.CAPI;
import com.mongodb.crypt.capi.jna.MongoCrypts;
import org.bson.*;

import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

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
            return new String(Files.readAllBytes(Paths.get(resource.toURI())));
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

    // DecryptTask decrypts a document repeatedly for a specified number of seconds and records ops/sec.
    private static class DecryptTask implements Runnable {
        public DecryptTask (MongoCrypt mongoCrypt, BsonDocument toDecrypt, int numSecs, CountDownLatch doneSignal) {
            this.mongoCrypt = mongoCrypt;
            this.toDecrypt = toDecrypt;
            this.opsPerSecs = new ArrayList<Long>(numSecs);
            this.numSecs = numSecs;
            this.doneSignal = doneSignal;
        }
        public void run() {
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
            doneSignal.countDown();
        }
        public long getMedianOpsPerSecs () {
            if (opsPerSecs.size() == 0) {
                throw new IllegalStateException("opsPerSecs is empty. Was `run` called?");
            }
            Collections.sort(opsPerSecs);
            return opsPerSecs.get(numSecs / 2);
        }
        private MongoCrypt mongoCrypt;
        private BsonDocument toDecrypt;
        private ArrayList<Long> opsPerSecs;
        private int numSecs;
        private CountDownLatch doneSignal;
    }
    public static void main(String[] args) throws IOException, InterruptedException, ExecutionException {
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

            // Warm up benchmark and discard the result.
            DecryptTask warmup = new DecryptTask(mongoCrypt, encrypted, NUM_WARMUP_SECS, new CountDownLatch(1));
            warmup.run();

            // Decrypt `encrypted` and measure ops/sec.
            // Check with varying thread counts to measure impact of a shared pool of Cipher instances.
            int[] threadCounts = {1,2,8,64};
            ArrayList<Long> totalMedianOpsPerSecs = new ArrayList<Long>(threadCounts.length);
            ArrayList<String> createdAts = new ArrayList<String>(threadCounts.length);
            ArrayList<String> completedAts = new ArrayList<String>(threadCounts.length);

            for (int threadCount : threadCounts) {
                ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
                CountDownLatch doneSignal = new CountDownLatch(threadCount);
                ArrayList<DecryptTask> decryptTasks = new ArrayList<DecryptTask>(threadCount);
                createdAts.add(ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT));

                for (int i = 0; i < threadCount; i++) {
                    DecryptTask decryptTask = new DecryptTask(mongoCrypt, encrypted, NUM_SECS, doneSignal);
                    decryptTasks.add(decryptTask);
                    executorService.submit(decryptTask);
                }

                // Await completion of all tasks. Tasks are expected to complete shortly after NUM_SECS. Time out `await` if time exceeds 2 * NUM_SECS.
                boolean ok = doneSignal.await(NUM_SECS * 2, TimeUnit.SECONDS);
                assert ok;
                completedAts.add(ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT));
                // Sum the median ops/secs of all tasks to get total throughput.
                long totalMedianOpsPerSec = 0;
                for (DecryptTask decryptTask : decryptTasks) {
                    totalMedianOpsPerSec += decryptTask.getMedianOpsPerSecs();
                }
                System.out.printf("threadCount=%d. Decrypting 1500 fields median ops/sec : %d%n", threadCount, totalMedianOpsPerSec);
                totalMedianOpsPerSecs.add(totalMedianOpsPerSec);
                executorService.shutdown();
                ok = executorService.awaitTermination(NUM_SECS * 2, TimeUnit.SECONDS);
                assert ok;
            }

            // Print the results in JSON that can be accepted by the `perf.send` command.
            // See https://docs.devprod.prod.corp.mongodb.com/evergreen/Project-Configuration/Project-Commands#perfsend for the expected `perf.send` input.
            ArrayList<BsonDocument> resultsArray = new ArrayList<BsonDocument>(threadCounts.length);
            for (int i = 0; i < threadCounts.length; i++) {
                int threadCount = threadCounts[i];
                long totalMedianOpsPerSec = totalMedianOpsPerSecs.get(i);
                String createdAt = createdAts.get(i);
                String completedAt = completedAts.get(i);

                resultsArray.add(new BsonDocument()
                    .append("info", new BsonDocument()
                            .append("test_name", new BsonString("java_decrypt_1500"))
                            .append("args", new BsonDocument()
                                .append("threadCount", new BsonInt32(threadCount))))
                    .append("created_at", new BsonString(createdAt))
                    .append("completed_at", new BsonString(completedAt))
                    .append("artifacts", new BsonArray())
                    .append("metrics", new BsonArray(Arrays.asList(
                            new BsonDocument()
                                    .append("name", new BsonString("medianOpsPerSec"))
                                    .append("type", new BsonString("THROUGHPUT"))
                                    .append("value", new BsonInt64(totalMedianOpsPerSec))
                    )))
                    .append("sub_tests", new BsonArray()));
            }

            BsonDocument results = new BsonDocument().append("results", new BsonArray(resultsArray));
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
