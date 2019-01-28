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

import org.bson.BsonDocument;

import java.io.Closeable;

/**
 * A context for encryption/decryption operations.
 */
public interface MongoCrypt extends Closeable {

    /**
     * Create a context to use for encryption
     *
     * @param  namespace the namespace
     * @param  localSchemaDocument local schema document, which may be null
     * @return the context
     */
    MongoCryptContext createEncryptionContext(String namespace, BsonDocument localSchemaDocument);

    /**
     * Create a context to use for decryption
     *
     * @param document the document to decrypt
     * @return the the context
     */
    MongoCryptContext createDecryptionContext(BsonDocument document);

    @Override
    void close();
}
