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
 */
#ifndef MONGOCRYPT_H
#define MONGOCRYPT_H

/** @file mongocrypt.h The top-level handle to libmongocrypt. */

#include "mongocrypt-export.h"
#include "mongocrypt-compat.h"

#define MONGOCRYPT_VERSION "0.4.0"

/**
 * Returns the version string x.y.z for libmongocrypt.
 *
 * @param[out] len, an optional length of the returned string. May be NULL.
 * @returns a NULL terminated version string x.y.z for libmongocrypt.
 */
MONGOCRYPT_EXPORT
const char *
mongocrypt_version (uint32_t *len);


/**
 * A non-owning view of a byte buffer.
 *
 * Functions returning a mongocrypt_binary_t* expect it to be destroyed with
 * mongocrypt_binary_destroy.
 */
typedef struct _mongocrypt_binary_t mongocrypt_binary_t;


/**
 * Create a new non-owning view of a buffer (data + length).
 *
 * Use this to create a mongocrypt_binary_t used for output parameters.
 *
 * @returns A new mongocrypt_binary_t.
 */
MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_binary_new (void);


/**
 * Create a new non-owning view of a buffer (data + length).
 *
 * @param[in] data A pointer to an array of bytes. This is not copied. @p data
 * must outlive the binary object.
 * @param[in] len The length of the @p data byte array.
 *
 * @returns A new @ref mongocrypt_binary_t.
 */
MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_binary_new_from_data (uint8_t *data, uint32_t len);


/**
 * Get a pointer to the referenced data.
 *
 * @param[in] binary The @ref mongocrypt_binary_t.
 *
 * @returns A pointer to the referenced data.
 */
MONGOCRYPT_EXPORT
const uint8_t *
mongocrypt_binary_data (const mongocrypt_binary_t *binary);


/**
 * Get the length of the referenced data.
 *
 * @param[in] binary The @ref mongocrypt_binary_t.
 *
 * @returns The length of the referenced data.
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_binary_len (const mongocrypt_binary_t *binary);


/**
 * Free the @ref mongocrypt_binary_t.
 *
 * This does not free the referenced data. Refer to individual function
 * documentation to determine the lifetime guarantees of the underlying
 * data.
 *
 * @param[in] binary The mongocrypt_binary_t destroy.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_binary_destroy (mongocrypt_binary_t *binary);


/**
 * Indicates success or contains error information.
 *
 * Functions like @ref mongocrypt_ctx_encrypt_init follow a pattern to expose a
 * status. A boolean is returned. True indicates success, and false indicates
 * failure. On failure a status on the handle is set, and is accessible with a
 * corresponding <handle>_status function. E.g. @ref mongocrypt_ctx_status.
 */
typedef struct _mongocrypt_status_t mongocrypt_status_t;


typedef enum {
   MONGOCRYPT_STATUS_OK = 0,
   MONGOCRYPT_STATUS_ERROR_CLIENT = 1,
   MONGOCRYPT_STATUS_ERROR_KMS = 2
} mongocrypt_status_type_t;


/**
 * Create a new status object.
 *
 * Use a new status object to retrieve the status from a handle by passing
 * this as an out-parameter to functions like @ref mongocrypt_ctx_status.
 * When done, destroy it with @ref mongocrypt_status_destroy.
 *
 * @returns A new status object.
 */
MONGOCRYPT_EXPORT
mongocrypt_status_t *
mongocrypt_status_new (void);


/**
 * Indicates success or the type of error.
 *
 * @param[in] status The status object.
 *
 * @returns A @ref mongocrypt_status_type_t.
 */
MONGOCRYPT_EXPORT
mongocrypt_status_type_t
mongocrypt_status_type (mongocrypt_status_t *status);


/**
 * Get an error code or 0.
 *
 * @param[in] status The status object.
 *
 * @returns An error code.
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_status_code (mongocrypt_status_t *status);


/**
 * Get the error message associated with a status or NULL.
 *
 * @param[in] status The status object.
 * @param[out] len, an optional length of the returned string. May be NULL.
 *
 * @returns A NULL terminated error message or NULL.
 */
MONGOCRYPT_EXPORT
const char *
mongocrypt_status_message (mongocrypt_status_t *status, uint32_t *len);


/**
 * Returns true if the status indicates success.
 *
 * @param[in] status The status to check.
 *
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_status_ok (mongocrypt_status_t *status);


/**
 * Free the memory for a status object.
 *
 * @param[in] status The status to destroy.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_status_destroy (mongocrypt_status_t *status);


typedef enum {
   MONGOCRYPT_LOG_LEVEL_FATAL = 0,
   MONGOCRYPT_LOG_LEVEL_ERROR = 1,
   MONGOCRYPT_LOG_LEVEL_WARNING = 2,
   MONGOCRYPT_LOG_LEVEL_INFO = 3,
   MONGOCRYPT_LOG_LEVEL_TRACE = 4
} mongocrypt_log_level_t;


/**
 * A log callback function. Set a custom log callback with @ref
 * mongocrypt_setopt_log_handler.
 *
 * @param[in] message A NULL terminated message.
 * @param[in] message_len The length of message.
 * @param[in] ctx A context provided by the caller of @ref
 * mongocrypt_setopt_log_handler.
 */
typedef void (*mongocrypt_log_fn_t) (mongocrypt_log_level_t level,
                                     const char *message,
                                     uint32_t message_len,
                                     void *ctx);


/**
 * The top-level handle to libmongocrypt.
 *
 * Create a mongocrypt_t handle to perform operations within libmongocrypt:
 * encryption, decryption, registering log callbacks, etc.
 *
 * Functions on a mongocrypt_t are thread safe, though functions on derived
 * handles (e.g. mongocrypt_ctx_t) are not and must be owned by a single
 * thread. See each handle's documentation for thread-safety considerations.
 *
 * Multiple mongocrypt_t handles may be created.
 */
typedef struct _mongocrypt_t mongocrypt_t;


/**
 * Allocate a new @ref mongocrypt_t object.
 *
 * Set options using mongocrypt_setopt_* functions, then initialize with @ref
 * mongocrypt_init. When done with the @ref mongocrypt_t, free with @ref
 * mongocrypt_destroy.
 *
 * @returns A new @ref mongocrypt_t object.
 */
MONGOCRYPT_EXPORT
mongocrypt_t *
mongocrypt_new (void);


/**
 * Set a handler on the @ref mongocrypt_t object to get called on every log
 * message.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @param[in] log_fn The log callback.
 * @param[in] log_ctx A context passed as an argument to the log callback every
 * invokation.
 * @pre @ref mongocrypt_init has not been called on @p crypt.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_setopt_log_handler (mongocrypt_t *crypt,
                               mongocrypt_log_fn_t log_fn,
                               void *log_ctx);


/**
 * Configure an AWS KMS provider on the @ref mongocrypt_t object.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @param[in] aws_access_key_id The AWS access key ID used to generate KMS
 * messages.
 * @param[in] aws_access_key_id_len The string length (in bytes) of @p
 * aws_access_key_id. Pass -1 to determine the string length with strlen (must
 * be NULL terminated).
 * @param[in] aws_secret_access_key The AWS secret access key used to generate
 * KMS messages.
 * @param[in] aws_secret_access_key_len The string length (in bytes) of @p
 * aws_secret_access_key. Pass -1 to determine the string length with strlen
 * (must be NULL terminated).
 * @pre @ref mongocrypt_init has not been called on @p crypt.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_setopt_kms_provider_aws (mongocrypt_t *crypt,
                                    const char *aws_access_key_id,
                                    int32_t aws_access_key_id_len,
                                    const char *aws_secret_access_key,
                                    int32_t aws_secret_access_key_len);


/**
 * Configure a local KMS provider on the @ref mongocrypt_t object.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @param[in] key A 64 byte master key used to encrypt and decrypt key vault
 * keys.
 * @pre @ref mongocrypt_init has not been called on @p crypt.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_setopt_kms_provider_local (mongocrypt_t *crypt,
                                      mongocrypt_binary_t *key);


/**
 * Initialize new @ref mongocrypt_t object.
 *
 * Set options before using @ref mongocrypt_setopt_kms_provider_local, @ref
 * mongocrypt_setopt_kms_provider_aws, or @ref mongocrypt_setopt_log_handler.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 *
 * @returns A boolean indicating success. Failure may occur if previously set
 * options are invalid.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_init (mongocrypt_t *crypt);


/**
 * Get the status associated with a @ref mongocrypt_t object.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @param[out] status Receives the status.
 *
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_status (mongocrypt_t *crypt, mongocrypt_status_t *status);


/**
 * Destroy the @ref mongocrypt_t object.
 *
 * @param[in] crypt The @ref mongocrypt_t object to destroy.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_destroy (mongocrypt_t *crypt);


/**
 * Manages the state machine for encryption or decryption.
 */
typedef struct _mongocrypt_ctx_t mongocrypt_ctx_t;


/**
 * Set the key id to use for explicit encryption.
 *
 * It is an error to set both this and the key alt name.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] key_id The key_id to use.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_key_id (mongocrypt_ctx_t *ctx,
                              mongocrypt_binary_t *key_id);

/**
 * Set the keyAltName to use for explicit encryption.
 * keyAltName should be a binary encoding a bson document
 * with the following format:
 *
 *   { "keyAltName" : <BSON UTF8 value> }
 *
 * It is an error to set both this and the key id.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] key_alt_name The name to use.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_key_alt_name (mongocrypt_ctx_t *ctx,
                                    mongocrypt_binary_t *key_alt_name);

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
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @p algorithm A string specifying the algorithm to
 * use for encryption.
 * @p len The length of the algorithm string.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_algorithm (mongocrypt_ctx_t *ctx,
                                 char *algorithm,
                                 int len);


/**
 * Set an initialization vector to be used with explicit
 * encryption. This should not be set for auto encryption.
 *
 * If using randomized encryption, setting this option will
 * cause an error. If using deterministic encryption, failing
 * to set this option will cause an error.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] iv The initialization vector to use.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_initialization_vector (mongocrypt_ctx_t *ctx,
                                             mongocrypt_binary_t *iv);


/**
 * Disable blocking waits on the shared key (or collinfo) cache.
 *
 * By default, if a @ref mongocrypt_ctx_t needs data currently
 * being fetched by another @ref mongocrypt_ctx_t, it will block until
 * the dependent context has fetched that data.
 *
 * For drivers that do not want libmongocrypt to block (e.g. async drivers)
 * setting this option puts the responsibility of waiting into the caller. If
 * (and only if) this option is set, a @ref mongocrypt_ctx_t may enter the state
 * MONGOCRYPT_CTX_WAITING. The caller can then get a list of dependent contexts
 * with @ref mongocrypt_ctx_next_dependent_ctx_id and call @ref
 * mongocrypt_ctx_wait_done to attempt to make progress.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @returns A boolean indicating success.
 * @see @ref mongocrypt_ctx_id and @ref mongocrypt_ctx_next_dependent_ctx_id.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_cache_noblock (mongocrypt_ctx_t *ctx);


/**
 * Create a new uninitialized @ref mongocrypt_ctx_t.
 *
 * Initialize the context with functions like @ref mongocrypt_ctx_encrypt_init.
 * When done, destroy it with @ref mongocrypt_ctx_destroy.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @returns A new context.
 */
MONGOCRYPT_EXPORT
mongocrypt_ctx_t *
mongocrypt_ctx_new (mongocrypt_t *crypt);


/**
 * Get the status associated with a @ref mongocrypt_ctx_t object.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[out] status Receives the status.
 *
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_status (mongocrypt_ctx_t *ctx, mongocrypt_status_t *out);


/**
 * Get a unique non-zero ID for this context.
 *
 * Always returns the same ID.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns a unique ID for this context.
 * @see @ref mongocrypt_ctx_next_dependent_ctx_id and @ref
 * mongocrypt_setopt_cache_noblock
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_ctx_id (mongocrypt_ctx_t *ctx);


/**
 * Identify the AWS KMS master key to use for creating a data key.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] region The AWS region.
 * @param[in] region_len The string length of @p region. Pass -1 to determine
 * the string length with strlen (must be NULL terminated).
 * @param[in] cmk The Amazon Resource Name (ARN) of the customer master key
 * (CMK).
 * @param[in] cmk_len The string length of @p cmk_len. Pass -1 to determine the
 * string length with strlen (must be NULL terminated).
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_masterkey_aws (mongocrypt_ctx_t *ctx,
                                     const char *region,
                                     int32_t region_len,
                                     const char *cmk,
                                     int32_t cmk_len);


/**
 * Set the master key to "local" for creating a data key.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_masterkey_local (mongocrypt_ctx_t *ctx);


/**
 * Initialize a context to create a data key.
 *
 * Set options before using @ref mongocrypt_ctx_setopt_masterkey_aws and
 * @ref mongocrypt_ctx_setopt_masterkey_local.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns A boolean indicating success.
 * @pre A master key option has been set, and an associated KMS provider
 * has been set on the parent @ref mongocrypt_t.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_datakey_init (mongocrypt_ctx_t *ctx);


/**
 * Set a local schema for encryption.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] schema A BSON local schema supplied by the user.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_setopt_schema (mongocrypt_ctx_t *ctx,
                              mongocrypt_binary_t *schema);


/**
 * Initialize a context for encryption.
 *
 * Set options before using @ref mongocrypt_ctx_setopt_schema.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] ns The namespace of the collection the driver is operating on.
 * @param[in] ns_len The strlen of @p ns. Pass -1 to determine the string length
 * with strlen (must be NULL terminated).
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             int32_t ns_len);

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
 * @param[in] ctx A @ref mongocrypt_ctx_t.
 * @param[in] msg A @ref mongocrypt_binary_t the plaintext BSON value.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_explicit_encrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg);


/**
 * Initialize a context for decryption.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] doc The document to be decrypted.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_decrypt_init (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *doc);


/**
 * Explicit helper method to decrypt a single BSON object.
 *
 * @param[in] ctx A @ref mongocrypt_ctx_t.
 * @param[in] msg A @ref mongocrypt_binary_t the encrypted BSON.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_explicit_decrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg);


typedef enum {
   MONGOCRYPT_CTX_ERROR = 0,
   MONGOCRYPT_CTX_NOTHING_TO_DO = 1,
   MONGOCRYPT_CTX_NEED_MONGO_COLLINFO = 2, /* run on main MongoClient */
   MONGOCRYPT_CTX_NEED_MONGO_MARKINGS = 3, /* run on mongocryptd. */
   MONGOCRYPT_CTX_NEED_MONGO_KEYS = 4,     /* run on key vault */
   MONGOCRYPT_CTX_NEED_KMS = 5,
   MONGOCRYPT_CTX_READY = 6, /* ready for encryption/decryption */
   MONGOCRYPT_CTX_DONE = 7,
   MONGOCRYPT_CTX_WAITING = 8 /* waiting for data from other contexts. */
} mongocrypt_ctx_state_t;


/**
 * Get the current state of a context.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns A @ref mongocrypt_ctx_state_t.
 */
MONGOCRYPT_EXPORT
mongocrypt_ctx_state_t
mongocrypt_ctx_state (mongocrypt_ctx_t *ctx);


/**
 * Get BSON necessary to run the mongo operation when mongocrypt_ctx_t
 * is in MONGOCRYPT_CTX_NEED_MONGO_* states.
 *
 * @p op_bson is a BSON document to be used for the operation.
 * - For MONGOCRYPT_CTX_NEED_MONGO_COLLINFO it is a listCollections filter.
 * - For MONGOCRYPT_CTX_NEED_MONGO_KEYS it is a find filter.
 * - For MONGOCRYPT_CTX_NEED_MONGO_MARKINGS it is a JSON schema to append.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[out] op_bson A BSON document for the MongoDB operation.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *op_bson);


/**
 * Feed a BSON reply or result when when mongocrypt_ctx_t is in
 * MONGOCRYPT_CTX_NEED_MONGO_* states. This may be called multiple times
 * depending on the operation.
 *
 * op_bson is a BSON document to be used for the operation.
 * - For MONGOCRYPT_CTX_NEED_MONGO_COLLINFO it is a doc from a listCollections
 * cursor.
 * - For MONGOCRYPT_CTX_NEED_MONGO_KEYS it is a doc from a find cursor.
 * - For MONGOCRYPT_CTX_NEED_MONGO_MARKINGS it is a reply from mongocryptd.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] reply A BSON document for the MongoDB operation.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_mongo_feed (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *reply);


/**
 * Call when done feeding the reply (or replies) back to the context.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_mongo_done (mongocrypt_ctx_t *ctx);


/**
 * Manages a single KMS HTTP request/response.
 */
typedef struct _mongocrypt_kms_ctx_t mongocrypt_kms_ctx_t;


/**
 * Get the next KMS handle.
 *
 * Multiple KMS handles may be retrieved at once. Drivers may do this to fan
 * out multiple concurrent KMS HTTP requests. Feeding multiple KMS requests
 * is thread-safe.
 *
 * If KMS handles are being handled synchronously, the driver can reuse the same
 * TLS socket to send HTTP requests and receive responses.
 *
 * @param[in] ctx A @ref mongocrypt_ctx_t.
 * @returns a new @ref mongocrypt_kms_ctx_t or NULL.
 */
MONGOCRYPT_EXPORT
mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx);


/**
 * Get the HTTP request message for a KMS handle.
 *
 * @param[in] kms A @ref mongocrypt_kms_ctx_t.
 * @param[out] msg The HTTP request to send to KMS.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_kms_ctx_message (mongocrypt_kms_ctx_t *kms,
                            mongocrypt_binary_t *msg);


/**
 * Get the hostname from which to connect over TLS.
 *
 * The storage for @p endpoint is not owned by the caller, but
 * is valid until calling @ref mongocrypt_ctx_kms_done on the
 * parent @ref mongocrypt_ctx_t.
 *
 * @param[in] kms A @ref mongocrypt_kms_ctx_t.
 * @param[out] endpoint The output hostname as a NULL terminated string.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_kms_ctx_endpoint (mongocrypt_kms_ctx_t *kms, const char **endpoint);


/**
 * Indicates how many bytes to feed into @ref mongocrypt_kms_ctx_feed.
 *
 * @param[in] kms The @ref mongocrypt_kms_ctx_t.
 * @returns The number of requested bytes.
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_kms_ctx_bytes_needed (mongocrypt_kms_ctx_t *kms);


/**
 * Feed bytes from the HTTP response.
 *
 * Feeding more bytes than what has been returned in @ref
 * mongocrypt_kms_ctx_bytes_needed is an error.
 *
 * @param[in] kms The @ref mongocrypt_kms_ctx_t.
 * @param[in] bytes The bytes to feed.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_kms_ctx_feed (mongocrypt_kms_ctx_t *kms, mongocrypt_binary_t *bytes);


/**
 * Get the status associated with a @ref mongocrypt_kms_ctx_t object.
 *
 * @param[in] kms The @ref mongocrypt_kms_ctx_t object.
 * @param[out] status Receives the status.
 *
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_kms_ctx_status (mongocrypt_kms_ctx_t *kms,
                           mongocrypt_status_t *status);


/**
 * Call when done handling all KMS contexts.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 *
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_kms_done (mongocrypt_ctx_t *ctx);


/**
 * Iterate over the list of dependent contexts by ID.
 *
 * Call when in MONGOCRYPT_CTX_WAITING state.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns A non-zero context ID or 0.
 * @see @ref mongocrypt_ctx_id
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_ctx_next_dependent_ctx_id (mongocrypt_ctx_t *ctx);


/**
 * Call when in MONGOCRYPT_CTX_WAITING state to attempt to make
 * progress.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @returns A bool indicating success.
 * @see @ref mongocrypt_ctx_id
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_wait_done (mongocrypt_ctx_t *ctx);


/**
 * Perform the final encryption or decryption.
 *
 * @param[in] ctx A @ref mongocrypt_ctx_t.
 * @param[out] out The final BSON to send to the server.
 *
 * @returns a bool indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);


/**
 * Destroy and free all memory associated with a @ref mongocrypt_ctx_t.
 *
 * @param[in] ctx A @ref mongocrypt_ctx_t.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_ctx_destroy (mongocrypt_ctx_t *ctx);


#endif /* MONGOCRYPT_H */
