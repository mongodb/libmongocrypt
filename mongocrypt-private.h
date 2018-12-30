#ifndef MONGOCRYPT_MONGOCRYPT_PRIVATE_H
#define MONGOCRYPT_MONGOCRYPT_PRIVATE_H

#include "mongocrypt.h"

/* TODO: use a new error code. */
#define SET_CRYPT_ERR(...) \
   bson_set_error (        \
      error, MONGOC_ERROR_CLIENT, MONGOC_ERROR_CLIENT_NOT_READY, __VA_ARGS__)

/* TOOD: remove after integrating into libmongoc */
#define BSON_SUBTYPE_ENCRYPTED 6

#define MONGOC_CRYPT_TRACE

#ifdef MONGOC_CRYPT_TRACE
#define CRYPT_TRACE(...)                              \
   do {                                               \
      printf ("[CRYPT %s:%d] ", BSON_FUNC, __LINE__); \
      printf (__VA_ARGS__);                           \
      printf ("\n");                                  \
   } while (0)
#define CRYPT_ENTRY                                          \
   do {                                                      \
      printf ("[CRYPT entry] %s:%d\n", BSON_FUNC, __LINE__); \
   } while (0)
#else
#define TRACE(msg, ...)
#define ENTRY
#endif

const char *
tmp_json (const bson_t *bson);

struct _mongoc_crypt_opts_t {
   char *aws_region;
   char *aws_secret_access_key;
   char *aws_access_key_id;
   char *mongocryptd_uri;
   char *default_keyvault_client_uri;
};

struct _mongoc_crypt_t {
   /* initially only one supported. Later, use from marking/ciphertext. */
   mongoc_client_t *keyvault_client;
   mongoc_client_t *mongocryptd_client;
   mongoc_crypt_opts_t opts;
};


/* It's annoying passing around multiple values for bson binary values. */
typedef struct {
   uint8_t *data;
   bson_subtype_t subtype;
   uint32_t len;
   bool owned;
} mongoc_crypt_binary_t;

void
mongoc_crypt_binary_from_iter (bson_iter_t *iter, mongoc_crypt_binary_t *out);
void
mongoc_crypt_binary_from_iter_unowned (bson_iter_t *iter, mongoc_crypt_binary_t *out);
void
mongoc_crypt_binary_cleanup (mongoc_crypt_binary_t* binary);
void
mongoc_crypt_bson_append_binary (bson_t *bson,
                                 const char *key,
                                 uint32_t key_len,
                                 mongoc_crypt_binary_t *in);

typedef struct {
   bson_iter_t v_iter;
   mongoc_crypt_binary_t iv;
   /* one of the following is zeroed, and the other is set. */
   mongoc_crypt_binary_t key_id;
   const char *key_alt_name;
} mongoc_crypt_marking_t;

/* consider renaming to encrypted_w_metadata? */
typedef struct {
   mongoc_crypt_binary_t e;
   mongoc_crypt_binary_t iv;
   mongoc_crypt_binary_t key_id;
} mongoc_crypt_encrypted_t;

typedef struct {
   mongoc_crypt_binary_t id;
   mongoc_crypt_binary_t key_material;
   mongoc_crypt_binary_t data_key;
} mongoc_crypt_key_t;

bool
_mongoc_crypt_marking_parse_unowned (const bson_t *bson,
                                     mongoc_crypt_marking_t *out,
                                     bson_error_t *error);
bool
_mongoc_crypt_encrypted_parse_unowned (const bson_t *bson,
                                       mongoc_crypt_encrypted_t *out,
                                       bson_error_t *error);
bool
_mongoc_crypt_key_parse (const bson_t *bson,
                         mongoc_crypt_key_t *out,
                         bson_error_t *error);

void mongoc_crypt_key_cleanup(mongoc_crypt_key_t* key);

bool
_mongoc_crypt_do_encryption (const uint8_t *iv,
                             const uint8_t *key,
                             const uint8_t *data,
                             uint32_t data_len,
                             uint8_t **out,
                             uint32_t *out_len,
                             bson_error_t *error);


bool
_mongoc_crypt_do_decryption (const uint8_t *iv,
                             const uint8_t *key,
                             const uint8_t *data,
                             uint32_t data_len,
                             uint8_t **out,
                             uint32_t *out_len,
                             bson_error_t *error);

/* Modifies key */
bool
_mongoc_crypt_kms_decrypt (mongoc_crypt_t* crypt,
                           mongoc_crypt_key_t* key,
                           bson_error_t* error);

#endif
