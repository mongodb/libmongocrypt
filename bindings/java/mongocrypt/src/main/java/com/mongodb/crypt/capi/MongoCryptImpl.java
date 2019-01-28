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

import com.mongodb.crypt.capi.CAPI.cstring;
import com.mongodb.crypt.capi.CAPI.mongocrypt_binary_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_status_t;
import com.mongodb.crypt.capi.CAPI.mongocrypt_t;
import org.bson.BsonDocument;

import static com.mongodb.crypt.capi.CAPI.mongocrypt_binary_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_decrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_encrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_new;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_ctx_setopt_schema;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_init;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_new;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_provider_aws;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_setopt_kms_provider_local;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_destroy;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_new;
import static com.mongodb.crypt.capi.CAPIHelper.toBinary;
import static org.bson.assertions.Assertions.isTrue;

class MongoCryptImpl implements MongoCrypt {
    private final mongocrypt_t wrapped;
    private volatile boolean closed;

    MongoCryptImpl(final MongoCryptOptions options) {
        wrapped = mongocrypt_new();
        if (wrapped == null) {
            throw new MongoCryptException("Unable to create new mongocrypt object");
        }

        boolean success;
        if (options.getLocalKmsProviderOptions() != null) {
            mongocrypt_binary_t localMasterKeyBinary = toBinary(options.getLocalKmsProviderOptions().getLocalMasterKey());
            try {
                success = mongocrypt_setopt_kms_provider_local(wrapped, localMasterKeyBinary);
                if (!success) {
                    throwExceptionFromStatus();
                }
            } finally {
                mongocrypt_binary_destroy(localMasterKeyBinary);
            }
        }

        if (options.getAwsKmsProviderOptions() != null) {
            success = mongocrypt_setopt_kms_provider_aws(wrapped,
                    new cstring(options.getAwsKmsProviderOptions().getAccessKeyId()),
                    new cstring(options.getAwsKmsProviderOptions().getSecretAccessKey()));
            if (!success) {
                throwExceptionFromStatus();
            }
        }

        success = mongocrypt_init(wrapped);
        if (!success) {
            throwExceptionFromStatus();
        }
    }

    @Override
    public MongoCryptContext createEncryptionContext(final String namespace, final BsonDocument localSchemaDocument) {
        isTrue("open", !closed);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }

        if (localSchemaDocument != null) {
            mongocrypt_binary_t binary = toBinary(localSchemaDocument);

            try {
                if (!mongocrypt_ctx_setopt_schema(context, binary)) {
                    throwExceptionFromStatus();
                }
            } finally {
                mongocrypt_binary_destroy(binary);
            }
        }

        boolean success = mongocrypt_ctx_encrypt_init(context, new cstring(namespace), namespace.length());
        if (!success) {
            throwExceptionFromStatus();
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public MongoCryptContext createDecryptionContext(final BsonDocument document) {
        isTrue("open", !closed);
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);
        if (context == null) {
            throwExceptionFromStatus();
        }
        boolean success = mongocrypt_ctx_decrypt_init(context, toBinary(document));
        if (!success) {
            throwExceptionFromStatus();
        }
        return new MongoCryptContextImpl(context);
    }

    @Override
    public void close() {
        mongocrypt_destroy(wrapped);
        closed = true;
    }

    private void throwExceptionFromStatus() {
        mongocrypt_status_t status = mongocrypt_status_new();
        mongocrypt_status(wrapped, status);
        MongoCryptException e = new MongoCryptException(status);
        mongocrypt_status_destroy(status);
        throw e;
    }
}
