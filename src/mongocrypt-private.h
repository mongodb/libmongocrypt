#ifndef MONGOCRYPT_MONGOCRYPT_PRIVATE_H
#define MONGOCRYPT_MONGOCRYPT_PRIVATE_H

#include "mongocrypt.h"

#define SET_CRYPT_ERR(...) _mongocrypt_set_error (error, 1, 1, __VA_ARGS__)

/* TOOD: remove after integrating into libmongoc */
#define BSON_SUBTYPE_ENCRYPTED 6

#define mongocrypt_TRACE

#ifdef mongocrypt_TRACE
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
_mongocrypt_set_error (mongocrypt_error_t *error, /* OUT */
                       uint32_t domain,           /* IN */
                       uint32_t code,             /* IN */
                       const char *format,        /* IN */
                       ...);

void
_bson_to_mongocrypt_error (const bson_error_t *bson_error,
                           mongocrypt_error_t *error);

struct _mongocrypt_opts_t {
   char *aws_region;
   char *aws_secret_access_key;
   char *aws_access_key_id;
   char *mongocryptd_uri;
   char *default_keyvault_client_uri;
};

struct _mongocrypt_t {
   /* initially only one supported. Later, use from marking/ciphertext. */
   mongoc_client_t *keyvault_client;
   mongoc_client_t *mongocryptd_client;
   mongocrypt_opts_t *opts;
};

/* It's annoying passing around multiple values for bson binary values. */
typedef struct {
   uint8_t *data;
   bson_subtype_t subtype;
   uint32_t len;
   bool owned;
} mongocrypt_binary_t;

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
                                   mongocrypt_error_t *error);
bool
_mongocrypt_encrypted_parse_unowned (const bson_t *bson,
                                     mongocrypt_encrypted_t *out,
                                     mongocrypt_error_t *error);
bool
_mongocrypt_key_parse (const bson_t *bson,
                       mongocrypt_key_t *out,
                       mongocrypt_error_t *error);

void
mongocrypt_key_cleanup (mongocrypt_key_t *key);

bool
_mongocrypt_do_encryption (const uint8_t *iv,
                           const uint8_t *key,
                           const uint8_t *data,
                           uint32_t data_len,
                           uint8_t **out,
                           uint32_t *out_len,
                           mongocrypt_error_t *error);

bool
_mongocrypt_do_decryption (const uint8_t *iv,
                           const uint8_t *key,
                           const uint8_t *data,
                           uint32_t data_len,
                           uint8_t **out,
                           uint32_t *out_len,
                           mongocrypt_error_t *error);

/* Modifies key */
bool
_mongocrypt_kms_decrypt (mongocrypt_t *crypt,
                         mongocrypt_key_t *key,
                         mongocrypt_error_t *error);

#endif
