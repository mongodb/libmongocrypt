#ifndef MONGOCRYPT_MONGOCRYPT_PRIVATE_H
#define MONGOCRYPT_MONGOCRYPT_PRIVATE_H

#include "mongocrypt.h"

#define MONGOCRYPT_GENERIC_ERROR_CODE 1

#define CLIENT_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (           \
      error, MONGOCRYPT_ERROR_TYPE_CLIENT, code, __VA_ARGS__)

#define CLIENT_ERR(...) \
   CLIENT_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

#define KMS_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (error, MONGOCRYPT_ERROR_TYPE_KMS, code, __VA_ARGS__)

#define KMS_ERR(...) KMS_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

/* TODO: consider changing this into a function */
#define MONGOCRYPTD_ERR_W_REPLY(bson_err, reply)                    \
   do {                                                             \
      if (bson_err.domain == MONGOC_ERROR_SERVER) {                 \
         _mongocrypt_set_error (error,                              \
                                MONGOCRYPT_ERROR_TYPE_MONGOCRYPTD,  \
                                bson_err.code,                      \
                                "%s",                               \
                                NULL);                              \
         if (reply) {                                               \
            (*error)->ctx = bson_copy (reply);                      \
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
#define ENTRY
#endif

const char *
tmp_json (const bson_t *bson);

void
_mongocrypt_set_error (mongocrypt_error_t **error,
                       mongocrypt_error_type_t type,
                       uint32_t code,
                       const char *format,
                       ...);

void
_bson_error_to_mongocrypt_error (const bson_error_t *bson_error,
                                 mongocrypt_error_type_t type,
                                 uint32_t code,
                                 mongocrypt_error_t **error);

struct _mongocrypt_opts_t {
   char *aws_region;
   char *aws_secret_access_key;
   char *aws_access_key_id;
   char *mongocryptd_uri;
   char *default_keyvault_client_uri;
};

struct _mongocrypt_t {
   /* initially only one supported. Later, use from marking/ciphertext. */
   mongoc_client_pool_t *keyvault_pool;
   mongoc_client_pool_t *mongocryptd_pool;
   mongocrypt_opts_t *opts;
   mongocrypt_mutex_t mutex;
};

/* It's annoying passing around multiple values for bson binary values. */
typedef struct {
   uint8_t *data;
   bson_subtype_t subtype;
   uint32_t len;
   bool owned;
} mongocrypt_binary_t;

struct _mongocrypt_error_t {
   uint32_t type;
   uint32_t code;
   char message[1024];
   void *ctx;
};

void
mongocrypt_binary_from_iter (bson_iter_t *iter, mongocrypt_binary_t *out);
void
mongocrypt_binary_from_iter_unowned (bson_iter_t *iter,
                                     mongocrypt_binary_t *out);
void
mongocrypt_binary_cleanup (mongocrypt_binary_t *binary);
void
mongocrypt_bson_append_binary (bson_t *bson,
                               const char *key,
                               uint32_t key_len,
                               mongocrypt_binary_t *in);

typedef struct {
   bson_iter_t v_iter;
   mongocrypt_binary_t iv;
   /* one of the following is zeroed, and the other is set. */
   mongocrypt_binary_t key_id;
   const char *key_alt_name;
} mongocrypt_marking_t;

/* consider renaming to encrypted_w_metadata? */
typedef struct {
   mongocrypt_binary_t e;
   mongocrypt_binary_t iv;
   mongocrypt_binary_t key_id;
} mongocrypt_encrypted_t;

typedef struct {
   mongocrypt_binary_t id;
   mongocrypt_binary_t key_material;
   mongocrypt_binary_t data_key;
} mongocrypt_key_t;

bool
_mongocrypt_marking_parse_unowned (const bson_t *bson,
                                   mongocrypt_marking_t *out,
                                   mongocrypt_error_t **error);
bool
_mongocrypt_encrypted_parse_unowned (const bson_t *bson,
                                     mongocrypt_encrypted_t *out,
                                     mongocrypt_error_t **error);
bool
_mongocrypt_key_parse (const bson_t *bson,
                       mongocrypt_key_t *out,
                       mongocrypt_error_t **error);

void
mongocrypt_key_cleanup (mongocrypt_key_t *key);

bool
_mongocrypt_do_encryption (const uint8_t *iv,
                           const uint8_t *key,
                           const uint8_t *data,
                           uint32_t data_len,
                           uint8_t **out,
                           uint32_t *out_len,
                           mongocrypt_error_t **error);

bool
_mongocrypt_do_decryption (const uint8_t *iv,
                           const uint8_t *key,
                           const uint8_t *data,
                           uint32_t data_len,
                           uint8_t **out,
                           uint32_t *out_len,
                           mongocrypt_error_t **error);

/* Modifies key */
bool
_mongocrypt_kms_decrypt (mongocrypt_t *crypt,
                         mongocrypt_key_t *key,
                         mongocrypt_error_t **error);

#endif
