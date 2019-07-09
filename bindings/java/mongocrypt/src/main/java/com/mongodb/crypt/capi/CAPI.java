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

import com.sun.jna.Callback;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.ptr.PointerByReference;

//CHECKSTYLE:OFF

/**
 * For internal use only. Not part of the public API.
 */
@SuppressWarnings("WeakerAccess")
public class CAPI {

    public static class cstring extends PointerType {
        public cstring() {
            super();
        }

        public cstring(String string) {
            Pointer m = new Memory(string.length() + 1);
            m.setString(0, string);
            setPointer(m);
        }

        public String toString() {
            return getPointer().getString(0);
        }
    }


    /**
     * Indicates success or contains error information.
     * <p>
     * Functions like @ref mongocrypt_ctx_encrypt_init follow a pattern to expose a
     * status. A boolean is returned. True indicates success, and false indicates
     * failure. On failure a status on the handle is set, and is accessible with a
     * corresponding status function. E.g. @ref mongocrypt_ctx_status.
     */
    public static class mongocrypt_status_t extends PointerType {
    }

    /**
     * Contains all options passed on initialization of a @ref mongocrypt_ctx_t.
     */
    public static class mongocrypt_opts_t extends PointerType {
    }

    /**
     * A non-owning view of a byte buffer.
     * <p>
     * Functions returning a mongocrypt_binary_t* expect it to be destroyed with
     * mongocrypt_binary_destroy.
     */
    public static class mongocrypt_binary_t extends PointerType {
    }

    /**
     * The top-level handle to libmongocrypt.
     * <p>
     * Create a mongocrypt_t handle to perform operations within libmongocrypt:
     * encryption, decryption, registering log callbacks, etc.
     * <p>
     * Functions on a mongocrypt_t are thread safe, though functions on derived
     * handle (e.g. mongocrypt_encryptor_t) are not and must be owned by a single
     * thread. See each handle's documentation for thread-safety considerations.
     * <p>
     * Multiple mongocrypt_t handles may be created.
     */
    public static class mongocrypt_t extends PointerType {
    }

    /**
     * Manages the state machine for encryption or decryption.
     */
    public static class mongocrypt_ctx_t extends PointerType {
    }

    /**
     * Manages a single KMS HTTP request/response.
     */
    public static class mongocrypt_kms_ctx_t extends PointerType {
    }


    /**
     * Returns the version string x.y.z for libmongocrypt.
     *
     * @param len, an optional length of the returned string. May be NULL.
     * @return the version string x.y.z for libmongocrypt.
     */
    public static native cstring
    mongocrypt_version(Pointer len);


    /**
     * Create a new non-owning view of a buffer (data + length).
     * <p>
     * Use this to create a mongocrypt_binary_t used for output parameters.
     *
     * @return A new mongocrypt_binary_t.
     */
    public static native mongocrypt_binary_t
    mongocrypt_binary_new();


    /**
     * Create a new non-owning view of a buffer (data + length).
     *
     * @param data A pointer to an array of bytes. This is not copied. data must outlive the binary object.
     * @param len  The length of the @p data byte array.
     * @return A new mongocrypt_binary_t.
     */
    public static native mongocrypt_binary_t
    mongocrypt_binary_new_from_data(Pointer data, int len);


    /**
     * Get a pointer to the referenced data.
     *
     * @param binary The @ref mongocrypt_binary_t.
     * @return A pointer to the referenced data.
     */
    public static native Pointer
    mongocrypt_binary_data(mongocrypt_binary_t binary);


    /**
     * Get the length of the referenced data.
     *
     * @param binary The @ref mongocrypt_binary_t.
     * @return The length of the referenced data.
     */
    public static native int
    mongocrypt_binary_len(mongocrypt_binary_t binary);


    /**
     * Free the @ref mongocrypt_binary_t.
     * <p>
     * This does not free the referenced data. Refer to individual function
     * documentation to determine the lifetime guarantees of the underlying
     * data.
     *
     * @param binary The mongocrypt_binary_t destroy.
     */
    public static native void
    mongocrypt_binary_destroy(mongocrypt_binary_t binary);


    public static final int MONGOCRYPT_STATUS_OK = 0;
    public static final int MONGOCRYPT_STATUS_ERROR_CLIENT = 1;
    public static final int MONGOCRYPT_STATUS_ERROR_KMS = 2;

    /**
     * Create a new status object.
     * <p>
     * Use a new status object to retrieve the status from a handle by passing
     * this as an out-parameter to functions like @ref mongocrypt_ctx_status.
     * When done, destroy it with @ref mongocrypt_status_destroy.
     *
     * @return A new status object.
     */
    public static native mongocrypt_status_t
    mongocrypt_status_new();


    /**
     * Indicates success or the type of error.
     *
     * @param status The status object.
     * @return A @ref mongocrypt_status_type_t.
     */

    public static native int
    mongocrypt_status_type(mongocrypt_status_t status);


    /**
     * Get an error code or 0.
     *
     * @param status The status object.
     * @return An error code.
     */
    public static native int
    mongocrypt_status_code(mongocrypt_status_t status);


    /**
     * Get the error message associated with a status, or an empty string.
     *
     * @param status The status object.
     * @param len, an optional length of the returned string. May be NULL.
     * @return An error message or an empty string.
     */
    public static native cstring
    mongocrypt_status_message(mongocrypt_status_t status, Pointer len);


    /**
     * Returns true if the status indicates success.
     *
     * @param status The status to check.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_status_ok(mongocrypt_status_t status);


    /**
     * Free the memory for a status object.
     *
     * @param status The status to destroy.
     */
    public static native void
    mongocrypt_status_destroy(mongocrypt_status_t status);


    public static final int MONGOCRYPT_LOG_LEVEL_FATAL = 0;
    public static final int MONGOCRYPT_LOG_LEVEL_ERROR = 1;
    public static final int MONGOCRYPT_LOG_LEVEL_WARNING = 2;
    public static final int MONGOCRYPT_LOG_LEVEL_INFO = 3;
    public static final int MONGOCRYPT_LOG_LEVEL_TRACE = 4;


    /**
     * A log callback function. Set a custom log callback with mongocrypt_setopt_log_handler.
     */
    public interface mongocrypt_log_fn_t extends Callback {
        void log(int level, cstring message, int message_len, Pointer ctx);
    }

    /**
     * Allocate a new @ref mongocrypt_t object.
     * <p>
     * Initialize with @ref mongocrypt_init. When done, free with @ref
     * mongocrypt_destroy.
     *
     * @return A new @ref mongocrypt_t object.
     */
    public static native mongocrypt_t
    mongocrypt_new();

    /**
     * Set a handler to get called on every log message.
     *
     * @param crypt   The @ref mongocrypt_t object.
     * @param log_fn  The log callback.
     * @param log_ctx A context passed as an argument to the log callback every
     *                invokation.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_setopt_log_handler(mongocrypt_t crypt,
                                  mongocrypt_log_fn_t log_fn,
                                  Pointer log_ctx);


    /**
     * Set a handler to get called on every log message.
     *
     * @param crypt                 The @ref mongocrypt_t object.
     * @param aws_access_key_id     The AWS access key ID used to generate KMS
     *                              messages.
     * @param aws_access_key_id_len The string length (in bytes) of @p
     *  * aws_access_key_id. Pass -1 to determine the string length with strlen (must
     *  * be NULL terminated).
     * @param aws_secret_access_key The AWS secret access key used to generate
     *                              KMS messages.
     * @param aws_secret_access_key_len The string length (in bytes) of @p
     * aws_secret_access_key. Pass -1 to determine the string length with strlen
     * (must be NULL terminated).
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_setopt_kms_provider_aws(mongocrypt_t crypt,
                                       cstring aws_access_key_id,
                                       int aws_access_key_id_len,
                                       cstring aws_secret_access_key,
                                       int aws_secret_access_key_len);

    /**
     * Configure a local KMS provider on the @ref mongocrypt_t object.
     *
     * @param crypt The @ref mongocrypt_t object.
     * @param key A 64 byte master key used to encrypt and decrypt key vault keys.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_setopt_kms_provider_local(mongocrypt_t crypt,
                                         mongocrypt_binary_t key);

    /**
     * Set a local schema map for encryption.
     *
     * @param crypt The @ref mongocrypt_t object.
     * @param schema_map A BSON document representing the schema map supplied by
     * the user. The keys are collection namespaces and values are JSON schemas.
     * @return A boolean indicating success. If false, an error status is set.
     * Retrieve it with @ref mongocrypt_status
     */
    public static native boolean
    mongocrypt_setopt_schema_map (mongocrypt_t crypt, mongocrypt_binary_t schema_map);
    
    /**
     * Initialize new @ref mongocrypt_t object.
     *
     * @param crypt The @ref mongocrypt_t object.
     * @return A boolean indicating success. Failure may occur if previously set options are invalid.
     */
    public static native boolean
    mongocrypt_init(mongocrypt_t crypt);


    /**
     * Get the status associated with a @ref mongocrypt_t object.
     *
     * @param crypt  The @ref mongocrypt_t object.
     * @param status Receives the status.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_status(mongocrypt_t crypt, mongocrypt_status_t status);


    /**
     * Destroy the @ref mongocrypt_t object.
     *
     * @param crypt The @ref mongocrypt_t object to destroy.
     */
    public static native void
    mongocrypt_destroy(mongocrypt_t crypt);


    /**
     * Set the key id to use for explicit encryption.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @param key_id The key_id to use.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_setopt_key_id (mongocrypt_ctx_t ctx,
                                  mongocrypt_binary_t key_id);

    /**
     * Set the keyAltName to use for explicit encryption.
     * keyAltName should be a binary encoding a bson document
     * with the following format: <code>{ "keyAltName" : &gt;BSON UTF8 value&lt; }</code>
     *
     * <p>It is an error to set both this and the key id.</p>
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @param key_alt_name The name to use.
     * @return A boolean indicating success. If false, an error status is set.
     * Retrieve it with @ref mongocrypt_ctx_status
     */
    public static native boolean
    mongocrypt_ctx_setopt_key_alt_name (mongocrypt_ctx_t ctx,
                                        mongocrypt_binary_t key_alt_name);

    /**
     * Set the algorithm used for encryption to either
     * deterministic or random encryption. This value
     * should only be set when using explicit encryption.
     *
     * If -1 is passed in for "len", then "algorithm" is
     * assumed to be a null-terminated string.
     *
     * Valid values for algorithm are:
     *   "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
     *   "AEAD_AES_256_CBC_HMAC_SHA_512-Randomized"
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @param algorithm A string specifying the algorithm to
     * use for encryption.
     * @param len The length of the algorithm string.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_setopt_algorithm (mongocrypt_ctx_t ctx,
                                     cstring algorithm,
                                     int len);


    /**
     * Create a new uninitialized @ref mongocrypt_ctx_t.
     * <p>
     * Initialize the context with functions like @ref mongocrypt_ctx_encrypt_init.
     * When done, destroy it with @ref mongocrypt_ctx_destroy.
     *
     * @param crypt The @ref mongocrypt_t object.
     * @return A new context.
     */
    public static native mongocrypt_ctx_t
    mongocrypt_ctx_new(mongocrypt_t crypt);


    /**
     * Get the status associated with a @ref mongocrypt_ctx_t object.
     *
     * @param ctx    The @ref mongocrypt_ctx_t object.
     * @param status Receives the status.
     * @return A boolean indicating success.
     */

    public static native boolean
    mongocrypt_ctx_status(mongocrypt_ctx_t ctx, mongocrypt_status_t status);


    /**
     * Identify the AWS KMS master key to use for creating a data key.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @param region The AWS region.
     * @param region_len The string length of @p region. Pass -1 to determine
     * the string length with strlen (must be NULL terminated).
     * @param cmk The Amazon Resource Name (ARN) of the customer master key
     * (CMK).
     * @param cmk_len The string length of @p cmk_len. Pass -1 to determine the
     * string length with strlen (must be NULL terminated).
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_setopt_masterkey_aws (mongocrypt_ctx_t ctx,
                                         cstring region,
                                         int region_len,
                                         cstring cmk,
                                         int cmk_len);


    /**
     * Set the master key to "local" for creating a data key.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_setopt_masterkey_local (mongocrypt_ctx_t ctx);


    /**
     * Initialize a context to create a data key.
     *
     * Set options before using @ref mongocrypt_ctx_setopt_masterkey_aws and
     * mongocrypt_ctx_setopt_masterkey_local.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @return A boolean indicating success.
     *
     * Assumes a master key option has been set, and an associated KMS provider
     * has been set on the parent @ref mongocrypt_t.
     */
    public static native boolean
    mongocrypt_ctx_datakey_init (mongocrypt_ctx_t ctx);
    
    /**
     * Initialize a context for encryption.
     *
     * Associated options:
     * - @ref mongocrypt_ctx_setopt_cache_noblock
     * - @ref mongocrypt_ctx_setopt_schema
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @param db The database name.
     * @param db_len The byte length of @p db. Pass -1 to determine the string length with strlen (must be NULL terminated).
     * @param cmd The BSON command to be encrypted.
     * @return A boolean indicating success. If false, an error status is set.
     * Retrieve it with @ref mongocrypt_ctx_status
     */
    public static native boolean
    mongocrypt_ctx_encrypt_init(mongocrypt_ctx_t ctx,
                                cstring db,
                                int db_len,
                                mongocrypt_binary_t cmd);

    /**
     * Explicit helper method to encrypt a single BSON object. Contexts
     * created for explicit encryption will not go through mongocryptd.
     *
     * To specify a key_id, algorithm, or iv to use, please use the
     * corresponding mongocrypt_setopt methods before calling this.
     *
     * This method expects the passed-in BSON to be of the form:
     * { "v" : BSON value to encrypt }
     *
     * @param ctx A @ref mongocrypt_ctx_t.
     * @param msg A @ref mongocrypt_binary_t the plaintext BSON value.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_explicit_encrypt_init (mongocrypt_ctx_t ctx,
                                          mongocrypt_binary_t msg);

    /**
     * Initialize a context for decryption.
     *
     * @param ctx The mongocrypt_ctx_t object.
     * @param doc The document to be decrypted.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_decrypt_init(mongocrypt_ctx_t ctx, mongocrypt_binary_t doc);


    /**
     * Explicit helper method to decrypt a single BSON object.
     *
     * @param ctx A @ref mongocrypt_ctx_t.
     * @param msg A @ref mongocrypt_binary_t the encrypted BSON.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_explicit_decrypt_init (mongocrypt_ctx_t ctx,
                                          mongocrypt_binary_t msg);


    public static final int MONGOCRYPT_CTX_ERROR = 0;
    public static final int MONGOCRYPT_CTX_NEED_MONGO_COLLINFO = 1; /* run on main MongoClient */
    public static final int MONGOCRYPT_CTX_NEED_MONGO_MARKINGS = 2; /* run on mongocryptd. */
    public static final int MONGOCRYPT_CTX_NEED_MONGO_KEYS = 3;     /* run on key vault */
    public static final int MONGOCRYPT_CTX_NEED_KMS = 4;
    public static final int MONGOCRYPT_CTX_READY = 5; /* ready for encryption/decryption */
    public static final int MONGOCRYPT_CTX_DONE = 6;


    /**
     * Get the current state of a context.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @return A @ref mongocrypt_ctx_state_t.
     */
    public static native int
    mongocrypt_ctx_state(mongocrypt_ctx_t ctx);


    /**
     * Get BSON necessary to run the mongo operation when mongocrypt_ctx_t
     * is in MONGOCRYPT_CTX_NEED_MONGO_* states.
     *
     * <p>
     * op_bson is a BSON document to be used for the operation.
     * - For MONGOCRYPT_CTX_NEED_MONGO_COLLINFO it is a listCollections filter.
     * - For MONGOCRYPT_CTX_NEED_MONGO_KEYS it is a find filter.
     * - For MONGOCRYPT_CTX_NEED_MONGO_MARKINGS it is a JSON schema to append.
     * </p>
     *
     * @param ctx     The @ref mongocrypt_ctx_t object.
     * @param op_bson A BSON document for the MongoDB operation.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_mongo_op(mongocrypt_ctx_t ctx, mongocrypt_binary_t op_bson);


    /**
     * Feed a BSON reply or result when when mongocrypt_ctx_t is in
     * MONGOCRYPT_CTX_NEED_MONGO_* states. This may be called multiple times
     * depending on the operation.
     * <p>
     * op_bson is a BSON document to be used for the operation.
     * - For MONGOCRYPT_CTX_NEED_MONGO_COLLINFO it is a doc from a listCollections
     * cursor.
     * - For MONGOCRYPT_CTX_NEED_MONGO_KEYS it is a doc from a find cursor.
     * - For MONGOCRYPT_CTX_NEED_MONGO_MARKINGS it is a reply from mongocryptd.
     *
     * @param ctx   The @ref mongocrypt_ctx_t object.
     * @param reply A BSON document for the MongoDB operation.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_mongo_feed(mongocrypt_ctx_t ctx, mongocrypt_binary_t reply);


    /**
     * Call when done feeding the reply (or replies) back to the context.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @return A boolean indicating success.
     */

    public static native boolean
    mongocrypt_ctx_mongo_done(mongocrypt_ctx_t ctx);

    /**
     * Get the next KMS handle.
     * <p>
     * Multiple KMS handles may be retrieved at once. Drivers may do this to fan
     * out multiple concurrent KMS HTTP requests. Feeding multiple KMS requests
     * is thread-safe.
     * <p>
     * Is KMS handles are being handled synchronously, the driver can reuse the same
     * TLS socket to send HTTP requests and receive responses.
     *
     * @param ctx A @ref mongocrypt_ctx_t.
     * @return a new @ref mongocrypt_kms_ctx_t or NULL.
     */
    public static native mongocrypt_kms_ctx_t
    mongocrypt_ctx_next_kms_ctx(mongocrypt_ctx_t ctx);

    /**
     * Get the HTTP request message for a KMS handle.
     *
     * @param kms A @ref mongocrypt_kms_ctx_t.
     * @param msg The HTTP request to send to KMS.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_kms_ctx_message(mongocrypt_kms_ctx_t kms,
                               mongocrypt_binary_t msg);

    /**
     * Get the hostname from which to connect over TLS.
     * <p>
     * The storage for @p endpoint is not owned by the caller, but
     * is valid until calling @ref mongocrypt_ctx_kms_done on the
     * parent @ref mongocrypt_ctx_t.
     *
     * @param kms      A @ref mongocrypt_kms_ctx_t.
     * @param endpoint The output hostname.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_kms_ctx_endpoint(mongocrypt_kms_ctx_t kms, PointerByReference endpoint);

    /**
     * Indicates how many bytes to feed into @ref mongocrypt_kms_ctx_feed.
     *
     * @param kms The @ref mongocrypt_kms_ctx_t.
     * @return The number of requested bytes.
     */
    public static native int
    mongocrypt_kms_ctx_bytes_needed(mongocrypt_kms_ctx_t kms);


    /**
     * Feed bytes from the HTTP response.
     * <p>
     * Feeding more bytes than what has been returned in @ref
     * mongocrypt_kms_ctx_bytes_needed is an error.
     *
     * @param kms   The @ref mongocrypt_kms_ctx_t.
     * @param bytes The bytes to feed.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_kms_ctx_feed(mongocrypt_kms_ctx_t kms, mongocrypt_binary_t bytes);


    /**
     * Get the status associated with a @ref mongocrypt_kms_ctx_t object.
     *
     * @param kms    The @ref mongocrypt_kms_ctx_t object.
     * @param status Receives the status.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_kms_ctx_status(mongocrypt_kms_ctx_t kms,
                              mongocrypt_status_t status);


    /**
     * Call when done handling all KMS contexts.
     *
     * @param ctx The @ref mongocrypt_ctx_t object.
     * @return A boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_kms_done(mongocrypt_ctx_t ctx);


    /**
     * Perform the final encryption or decryption.
     *
     * @param ctx A @ref mongocrypt_ctx_t.
     * @param out The final BSON to send to the server.
     * @return a boolean indicating success.
     */
    public static native boolean
    mongocrypt_ctx_finalize(mongocrypt_ctx_t ctx, mongocrypt_binary_t out);


    /**
     * Destroy and free all memory associated with a @ref mongocrypt_ctx_t.
     *
     * @param ctx A @ref mongocrypt_ctx_t.
     */
    public static native void
    mongocrypt_ctx_destroy(mongocrypt_ctx_t ctx);

    static final String NATIVE_LIBRARY_NAME = "mongocrypt";

    static {
        Native.register(CAPI.class, NATIVE_LIBRARY_NAME);
    }
}
