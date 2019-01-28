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

import org.bson.BsonDocument;

import java.io.Closeable;

/**
 * An interface representing the lifecycle of an encryption or decryption request.  It's modelled as a state machine.
 */
public interface MongoCryptContext extends Closeable {

    /**
     * The possible states.
     */
    enum State {
        NOTHING_TO_DO(CAPI.MONGOCRYPT_CTX_NOTHING_TO_DO),

        NEED_MONGO_COLLINFO(CAPI.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO),

        NEED_MONGO_MARKINGS(CAPI.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS),

        NEED_MONGO_KEYS(CAPI.MONGOCRYPT_CTX_NEED_MONGO_KEYS),

        NEED_KMS(CAPI.MONGOCRYPT_CTX_NEED_KMS),

        READY(CAPI.MONGOCRYPT_CTX_READY),

        DONE(CAPI.MONGOCRYPT_CTX_DONE);

        private final int index;

        State(final int index) {
            this.index = index;
        }

        static State fromIndex(final int index) {
            for (State state : State.values()) {
                if (state.index == index) {
                    return state;
                }
            }
            throw new MongoCryptException("Unknown context state " + index);
        }
    }

    /**
     * Gets the current state.
     *
     * @return the current state
     */
    State getState();

    /**
     *
     * @return the operation to execute
     */
    BsonDocument getMongoOperation();

    /**
     *
     * @param document a result of the operation
     */
    void addMongoOperationResult(BsonDocument document);

    /**
     * Signal completion of the operation
     */
    void completeMongoOperation();

    /**
     *
     * @return the next key decryptor, or null if there are no more
     */
    MongoKeyDecryptor nextKeyDecryptor();

    /**
     * Indicate that all key decryptors have been completed
     */
    void completeKeyDecryptors();

    /**
     *
     * @return the encrypted or decrypted document
     */
    BsonDocument finish();

    @Override
    void close();
}
