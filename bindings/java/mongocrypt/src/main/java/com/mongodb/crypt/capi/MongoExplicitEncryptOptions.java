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

import org.bson.BsonBinary;

import java.util.Arrays;

/**
 * Options for explicit encryption.
 */
public class MongoExplicitEncryptOptions {
    private final BsonBinary keyId;
    private final String algorithm;
    private final byte[] initializationVector;

    /**
     * The builder for the options
     */
    public static class Builder {
        private BsonBinary keyId;
        private String algorithm;
        private byte[] initializationVector;

        private Builder() {
        }

        /**
         * Add the key identifier.
         *
         * @param keyId the key idenfifier
         * @return this
         */
        public Builder keyId(final BsonBinary keyId) {
            this.keyId = keyId;
            return this;
        }

        /**
         * Add the encryption algorithm.
         *
         * @param algorithm the encryption algorithm
         * @return this
         */
        public Builder algorithm(final String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Add the initialization vector
         * @param initializationVector the initialization vector
         * @return this
         */
        public Builder initializationVector(final byte[] initializationVector) {
            this.initializationVector = initializationVector;
            return this;
        }

        /**
         * Build the options.
         *
         * @return the options
         */
        public MongoExplicitEncryptOptions build() {
            return new MongoExplicitEncryptOptions(this);
        }
    }

    /**
     * Create a builder for the options.
     * 
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Gets the key identifier
     * @return the key identifier
     */
    public BsonBinary getKeyId() {
        return keyId;
    }

    /**
     * Gets the encryption algorithm
     * @return the encryption algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the initialization vector
     * @return the initialization vector
     */
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    private MongoExplicitEncryptOptions(Builder builder) {
        this.keyId = builder.keyId;
        this.algorithm = builder.algorithm;
        this.initializationVector = builder.initializationVector;
    }

    @Override
    public String toString() {
        return "MongoExplicitEncryptOptions{" +
                "keyId=" + keyId +
                ", algorithm='" + algorithm + '\'' +
                ", initializationVector=" + Arrays.toString(initializationVector) +
                '}';
    }
}
