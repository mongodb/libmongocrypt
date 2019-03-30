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

#ifndef MONGOCRYPT_PRIVATE_H
#define MONGOCRYPT_PRIVATE_H

#include "mongocrypt.h"
#include "bson/bson.h"

#include "mongocrypt-log-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-key-cache-private.h"
#include "mongocrypt-mutex-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-schema-cache-private.h"

#define MONGOCRYPT_GENERIC_ERROR_CODE 1

#define CLIENT_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (           \
      status, MONGOCRYPT_STATUS_ERROR_CLIENT, code, __VA_ARGS__)

#define CLIENT_ERR(...) \
   CLIENT_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

#define KMS_ERR_W_CODE(code, ...) \
   _mongocrypt_set_error (        \
      status, MONGOCRYPT_STATUS_ERROR_KMS, code, __VA_ARGS__)

#define KMS_ERR(...) KMS_ERR_W_CODE (MONGOCRYPT_GENERIC_ERROR_CODE, __VA_ARGS__)

#define MONGOCRYPT_STR_AND_LEN(x) (x) , ( sizeof(x) / sizeof((x)[0]) - 1 )

/* TODO: remove after integrating into libmongoc */
#define BSON_SUBTYPE_ENCRYPTED 6

/* TODO: Move these to mongocrypt-log-private.h? */
const char *
tmp_json (const bson_t *bson);

const char *
tmp_buf (const _mongocrypt_buffer_t *buf);


void
_mongocrypt_set_error (mongocrypt_status_t *status,
                       mongocrypt_status_type_t type,
                       uint32_t code,
                       const char *format,
                       ...);


struct _mongocrypt_t {
   bool initialized;
   _mongocrypt_opts_t opts;
   mongocrypt_mutex_t mutex;
   _mongocrypt_schema_cache_t *schema_cache;
   /* The key cache has its own interal mutex. */
   _mongocrypt_key_cache_t *key_cache;
   _mongocrypt_log_t log;
   mongocrypt_status_t *status;
};

typedef struct {
   uint8_t algorithm;
   bson_iter_t v_iter;
   _mongocrypt_buffer_t iv;
   /* one of the following is zeroed, and the other is set. */
   _mongocrypt_buffer_t key_id;
   const bson_value_t *key_alt_name;
} _mongocrypt_marking_t;


typedef struct {
   _mongocrypt_buffer_t key_id;
   uint8_t blob_subtype;
   uint8_t original_bson_type;
   _mongocrypt_buffer_t data;
} _mongocrypt_ciphertext_t;

/* TODO: reconsider where to put these parsing functions please. */
bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status);
bool
_test_mongocrypt_ciphertext_parse_unowned (_mongocrypt_buffer_t *buf,
                                           _mongocrypt_ciphertext_t *out,
                                           mongocrypt_status_t *status);

void
_test_mongocrypt_serialize_ciphertext (_mongocrypt_ciphertext_t *ciphertext,
                                       _mongocrypt_buffer_t *out);

typedef enum {
   TRAVERSE_MATCH_CIPHERTEXT,
   TRAVERSE_MATCH_MARKING
} traversal_match_t;

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
                                     traversal_match_t match,
                                     bson_iter_t *iter,
                                     mongocrypt_status_t *status);

bool
_mongocrypt_transform_binary_in_bson (_mongocrypt_transform_callback_t cb,
                                      void *ctx,
                                      traversal_match_t match,
                                      bson_iter_t *iter,
                                      bson_t *out,
                                      mongocrypt_status_t *status);

#endif /* MONGOCRYPT_PRIVATE_H */
