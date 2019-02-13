#ifndef MONGOCRYPT_MONGOCRYPT_PRIVATE_H
#define MONGOCRYPT_MONGOCRYPT_PRIVATE_H

#include "mongocrypt.h"
#include "mongoc/mongoc.h"

#define MONGOCRYPT_MAC_KEY_LEN 32
#define MONGOCRYPT_ENC_KEY_LEN 32
#define MONGOCRYPT_IV_LEN 16
#define MONGOCRYPT_HMAC_LEN 32
#define MONGOCRYPT_BLOCK_SIZE 16

/* TODO: when native crypto support is added, conditionally define this. */
#define MONGOC_ENABLE_SSL_OPENSSL

#define MONGOCRYPT_GENERIC_ERROR_CODE 1

#define CLIENT_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (           \
      status, MONGOCRYPT_ERROR_TYPE_CLIENT, code, __VA_ARGS__)

#define CLIENT_ERR(...) \
   CLIENT_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

#define KMS_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (status, MONGOCRYPT_ERROR_TYPE_KMS, code, __VA_ARGS__)

#define KMS_ERR(...) KMS_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

/* TODO: consider changing this into a function */
#define MONGOCRYPTD_ERR_W_REPLY(bson_err, reply)                    \
   do {                                                             \
      if (bson_err.domain == MONGOC_ERROR_SERVER) {                 \
         _mongocrypt_set_error (status,                             \
                                MONGOCRYPT_ERROR_TYPE_MONGOCRYPTD,  \
                                bson_err.code,                      \
                                "%s",                               \
                                NULL);                              \
         if (reply) {                                               \
            status->ctx = bson_copy (reply);                        \
         }                                                          \
      } else { /* actually a client-side error. */                  \
         CLIENT_ERR_W_CODE (bson_err.code, "%s", bson_err.message); \
      }                                                             \
   } while (0)


#if defined(BSON_OS_UNIX)
#include <pthread.h>
#define mongocrypt_mutex_destroy pthread_mutex_destroy
#define mongocrypt_mutex_init(_n) pthread_mutex_init ((_n), NULL)
#define mongocrypt_mutex_lock pthread_mutex_lock
#define mongocrypt_mutex_t pthread_mutex_t
#define mongocrypt_mutex_unlock pthread_mutex_unlock
#else
#define mongocrypt_mutex_destroy DeleteCriticalSection
#define mongocrypt_mutex_init InitializeCriticalSection
#define mongocrypt_mutex_lock EnterCriticalSection
#define mongocrypt_mutex_t CRITICAL_SECTION
#define mongocrypt_mutex_unlock LeaveCriticalSection
#endif

/* TODO: remove after integrating into libmongoc */
#define BSON_SUBTYPE_ENCRYPTED 6

#define MONGOCRYPT_TRACE

#ifdef MONGOCRYPT_TRACE
#define CRYPT_TRACE(...)                                 \
   do {                                                  \
      if (getenv ("MONGOCRYPT_TRACE")) {                 \
         printf ("[CRYPT %s:%d] ", BSON_FUNC, __LINE__); \
         printf (__VA_ARGS__);                           \
         printf ("\n");                                  \
      }                                                  \
   } while (0)
#define CRYPT_ENTRY                                             \
   do {                                                         \
      if (getenv ("MONGOCRYPT_TRACE")) {                        \
         printf ("[CRYPT entry] %s:%d\n", BSON_FUNC, __LINE__); \
      }                                                         \
   } while (0)
#else
#define TRACE(msg, ...)
#define CRYPT_ENTRY
#endif

const char *
tmp_json (const bson_t *bson);

void
_mongocrypt_set_error (mongocrypt_status_t *status,
                       mongocrypt_error_type_t type,
                       uint32_t code,
                       const char *format,
                       ...);

void
_bson_error_to_mongocrypt_error (const bson_error_t *bson_error,
                                 mongocrypt_error_type_t type,
                                 uint32_t code,
                                 mongocrypt_status_t *status);

/* This is an internal struct to make working with binary values more
 * convenient.
 * - a non-owning buffer can be constructed from a bson_iter_t.
 * - a non-owning buffer can become an owned buffer by copying.
 * - a buffer can be appended as a BSON binary in a bson_t.
 */
typedef struct {
   uint8_t *data;
   uint32_t len;
   bool owned;
   bson_subtype_t subtype;
} _mongocrypt_buffer_t;

struct _mongocrypt_status_t {
   uint32_t type;
   uint32_t code;
   char message[1024];
   void *ctx;
};

struct _mongocrypt_opts_t {
   char *aws_region;
   char *aws_secret_access_key;
   char *aws_access_key_id;
   char *mongocryptd_uri;
};

typedef struct {
   _mongocrypt_buffer_t id;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_buffer_t data_key;
} _mongocrypt_key_t;

/* Dear reader, please have a laugh at the "key cache". */
typedef struct {
   bson_t *key_bson;
   _mongocrypt_key_t key;
   bool used;
} _mongocrypt_keycache_entry_t;

struct _mongocrypt_t {
   mongoc_client_pool_t *mongocryptd_pool;
   mongocrypt_opts_t *opts;
   mongocrypt_mutex_t mutex;
   /* For now, this "key cache" is just guarded by the same mutex. */
   _mongocrypt_keycache_entry_t keycache[64];
};

bool
_mongocrypt_keycache_add (mongocrypt_t *crypt,
                          _mongocrypt_buffer_t *docs,
                          uint32_t num_docs,
                          mongocrypt_status_t *status);
const _mongocrypt_key_t *
_mongocrypt_keycache_get_by_id (mongocrypt_t *crypt,
                                const _mongocrypt_buffer_t *uuid,
                                mongocrypt_status_t *status);
void
_mongocrypt_keycache_dump (mongocrypt_t *crypt);

void
_mongocrypt_owned_buffer_from_iter (bson_iter_t *iter,
                                    _mongocrypt_buffer_t *out);

void
_mongocrypt_unowned_buffer_from_iter (bson_iter_t *iter,
                                      _mongocrypt_buffer_t *out);

void
_mongocrypt_buffer_cleanup (_mongocrypt_buffer_t *binary);

void
_mongocrypt_bson_append_buffer (bson_t *bson,
                                const char *key,
                                uint32_t key_len,
                                _mongocrypt_buffer_t *in);

typedef struct {
   bson_iter_t v_iter;
   _mongocrypt_buffer_t iv;
   /* one of the following is zeroed, and the other is set. */
   _mongocrypt_buffer_t key_id;
   const bson_value_t *key_alt_name;
   const char *keyvault_alias;
} _mongocrypt_marking_t;

/* consider renaming to encrypted_w_metadata? */
typedef struct {
   _mongocrypt_buffer_t data;
   _mongocrypt_buffer_t iv;
   _mongocrypt_buffer_t key_id;
   const char *keyvault_alias; /* not null terminated. */
   uint16_t keyvault_alias_len;
} _mongocrypt_ciphertext_t;

bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status);
bool
_mongocrypt_ciphertext_parse_unowned (const bson_t *bson,
                                      _mongocrypt_ciphertext_t *out,
                                      mongocrypt_status_t *status);
bool
_mongocrypt_key_parse (const bson_t *bson,
                       _mongocrypt_key_t *out,
                       mongocrypt_status_t *status);

bool
_mongocryptd_marking_reply_parse (const bson_t *bson,
                                  mongocrypt_request_t *request,
                                  mongocrypt_status_t *status);

void
mongocrypt_key_cleanup (_mongocrypt_key_t *key);

uint32_t
_mongocrypt_calculate_ciphertext_len (uint32_t plaintext_len);

bool
_mongocrypt_do_encryption (const _mongocrypt_buffer_t *iv,
                           const _mongocrypt_buffer_t *associated_data,
                           const _mongocrypt_buffer_t *key,
                           const _mongocrypt_buffer_t *plaintext,
                           _mongocrypt_buffer_t *ciphertext,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status);

bool
_mongocrypt_do_decryption (const _mongocrypt_buffer_t *associated_data,
                           const _mongocrypt_buffer_t *key,
                           const _mongocrypt_buffer_t *ciphertext,
                           _mongocrypt_buffer_t *plaintext,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status);

/* Modifies key */
bool
_mongocrypt_kms_decrypt (mongocrypt_t *crypt,
                         _mongocrypt_key_t *key,
                         mongocrypt_status_t *status);


typedef bool (*_mongocrypt_traverse_callback_t) (void *ctx,
                                                 _mongocrypt_buffer_t *in,
                                                 mongocrypt_status_t *status);


typedef bool (*_mongocrypt_transform_callback_t) (void *ctx,
                                                  _mongocrypt_buffer_t *in,
                                                  bson_value_t *out,
                                                  mongocrypt_status_t *status);


bool
_mongocrypt_traverse_binary_in_bson (_mongocrypt_traverse_callback_t cb,
                                     void *ctx,
                                     uint8_t match_first_byte,
                                     bson_iter_t iter,
                                     mongocrypt_status_t *status);

bool
_mongocrypt_transform_binary_in_bson (_mongocrypt_transform_callback_t cb,
                                      void *ctx,
                                      uint8_t match_first_byte,
                                      bson_iter_t iter,
                                      bson_t *out,
                                      mongocrypt_status_t *status);

typedef enum {
   MONGOCRYPT_REQUEST_ENCRYPT,
   MONGOCRYPT_REQUEST_ENCRYPT_VALUE,
   MONGOCRYPT_REQUEST_DECRYPT,
   MONGOCRYPT_REQUEST_DECRYPT_VALUE
} _mongocrypt_request_type_t;

struct _mongocrypt_request_t {
   mongocrypt_t *crypt;
   _mongocrypt_request_type_t type;
   bool has_encryption_placeholders;
   bson_t mongocryptd_reply;
   bson_iter_t result_iter;
   uint32_t num_key_queries;
   /* TODO: do something better for key_query requests.
      Consider copying mongoc_array, vendoring something,
      or just power-of-two growth.
    */
   mongocrypt_key_query_t key_queries[32];
   uint32_t key_query_iter;

   const mongocrypt_binary_t *encrypted_docs;
   uint32_t num_input_docs;
};

#endif
