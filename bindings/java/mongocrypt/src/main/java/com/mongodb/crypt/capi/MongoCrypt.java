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
 * A context for encryption/decryption operations.
 */
public interface MongoCrypt extends Closeable {

    /**
     * Create a context to use for encryption
     *
     * @param namespace           the namespace
     * @param localSchemaDocument local schema document, which may be null
     * @return the context
     */
    MongoCryptContext createEncryptionContext(String namespace, BsonDocument localSchemaDocument);

    /**
     * Create a context to use for decryption
     *
     * @param document the document to decrypt
     * @return the context
     */
    MongoCryptContext createDecryptionContext(BsonDocument document);

    /**
     * Create a context to use for creating a data key
     * @param kmsProvider the KMS provider
     * @param options the data key options
     * @return the context
     */
    MongoCryptContext createDataKeyContext(String kmsProvider, MongoDataKeyOptions options);
    
    /**
     * Create a context to use for encryption
     *
     * @param document the document to encrypt, which must be in the form { "v" : BSON value to encrypt }}
     * @param options  the explicit encryption options
     * @return the context
     */
    MongoCryptContext createExplicitEncryptionContext(BsonDocument document, MongoExplicitEncryptOptions options);

    /**
     * Create a context to use for encryption
     *
     * @param document the document to decrypt,which must be in the form { "v" : encrypted BSON value }
     * @return the context
     */
    MongoCryptContext createExplicitDecryptionContext(BsonDocument document);

    @Override
    void close();
}
