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
 * @returns the version string x.y.z for libmongocrypt.
 */
MONGOCRYPT_EXPORT
const char *
mongocrypt_version (void);


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
 *
 * @returns An error message or NULL.
 */
MONGOCRYPT_EXPORT
const char *
mongocrypt_status_message (mongocrypt_status_t *status);


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


/**
 * Contains all options passed on initialization of a @ref mongocrypt_ctx_t.
 */
typedef struct _mongocrypt_opts_t mongocrypt_opts_t;


typedef enum {
   MONGOCRYPT_AWS_REGION = 0,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY = 1,
   MONGOCRYPT_AWS_ACCESS_KEY_ID = 2,
   MONGOCRYPT_LOG_FN = 3,
   MONGOCRYPT_LOG_CTX = 4
} mongocrypt_opt_t;


/**
 * Create a new options object.
 *
 * @returns A new @ref mongocrypt_opts_t object.
 */
MONGOCRYPT_EXPORT
mongocrypt_opts_t *
mongocrypt_opts_new (void);


/**
 * Set an option.
 *
 * @param[in] opts The options object.
 * @param[in] opt The option to set.
 * @param[in] value The type-erased option value.
 *
 * Options values depend on @p opt.
 * - MONGOCRYPT_AWS_REGION expects a char *.
 * - MONGOCRYPT_AWS_SECRET_ACCESS_KEY expects a char *.
 * - MONGOCRYPT_AWS_ACCESS_KEY_ID expects a char *.
 * - MONGOCRYPT_LOG_FN expects a @ref mongocrypt_log_fn_t.
 * - MONGOCRYPT_LOG_CTX expects a void*.
 *
 * Passing the wrong type has dire consequences.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value);


/**
 * Destroy an options object.
 *
 * @param[in] opts The options object to destroy.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts);


typedef enum {
   MONGOCRYPT_LOG_LEVEL_FATAL = 0,
   MONGOCRYPT_LOG_LEVEL_ERROR = 1,
   MONGOCRYPT_LOG_LEVEL_WARNING = 2,
   MONGOCRYPT_LOG_LEVEL_INFO = 3,
   MONGOCRYPT_LOG_LEVEL_TRACE = 4
} mongocrypt_log_level_t;


/**
 * A log callback function. Set a custom log callback with @ref
 * mongocrypt_opts_set_opt.
 */
typedef void (*mongocrypt_log_fn_t) (mongocrypt_log_level_t level,
                                     const char *message,
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
 * Initialize with @ref mongocrypt_init. When done, free with @ref
 * mongocrypt_destroy.
 *
 * @returns A new @ref mongocrypt_t object.
 */
MONGOCRYPT_EXPORT
mongocrypt_t *
mongocrypt_new (void);


/**
 * Initialize new @ref mongocrypt_t object.
 *
 * @param[in] crypt The @ref mongocrypt_t object.
 * @param[in] opts An options object.
 *
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_init (mongocrypt_t *crypt, mongocrypt_opts_t *opts);


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
 * Initialize a context for encryption.
 *
 * @param[in] ctx The @ref mongocrypt_ctx_t object.
 * @param[in] ns The namespace of the collection the driver is operating on.
 * @param[in] ns_len The strlen of @p ns.
 * @returns A boolean indicating success.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             uint32_t ns_len);


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


typedef enum {
   MONGOCRYPT_CTX_ERROR = 0,
   MONGOCRYPT_CTX_NOTHING_TO_DO = 1,
   MONGOCRYPT_CTX_NEED_MONGO_COLLINFO = 2, /* run on main MongoClient */
   MONGOCRYPT_CTX_NEED_MONGO_MARKINGS = 3, /* run on mongocryptd. */
   MONGOCRYPT_CTX_NEED_MONGO_KEYS = 4,     /* run on key vault */
   MONGOCRYPT_CTX_NEED_KMS = 5,
   MONGOCRYPT_CTX_READY = 6, /* ready for encryption/decryption */
   MONGOCRYPT_CTX_DONE = 7
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
