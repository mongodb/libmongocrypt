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

#ifndef MONGOCRYPT_CTX_PRIVATE_H
#define MONGOCRYPT_CTX_PRIVATE_H

#include "mongocrypt.h"
#include "mongocrypt-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-key-broker-private.h"

typedef enum {
   _MONGOCRYPT_TYPE_NONE,
   _MONGOCRYPT_TYPE_ENCRYPT,
   _MONGOCRYPT_TYPE_DECRYPT,
   _MONGOCRYPT_TYPE_CREATE_DATA_KEY,
} _mongocrypt_ctx_type_t;


typedef struct __mongocrypt_ctx_opts_t {
   _mongocrypt_kms_provider_t masterkey_kms_provider;
   char *masterkey_aws_cmk;
   uint32_t masterkey_aws_cmk_len;
   char *masterkey_aws_region;
   uint32_t masterkey_aws_region_len;
   _mongocrypt_buffer_t local_schema;

   /* For explicit encryption */
   _mongocrypt_buffer_t key_id;
   _mongocrypt_buffer_t key_alt_name;
   _mongocrypt_buffer_t iv;
   mongocrypt_encryption_algorithm_t algorithm;
} _mongocrypt_ctx_opts_t;


typedef bool (*_mongocrypt_ctx_mongo_op_fn) (mongocrypt_ctx_t *ctx,
                                             mongocrypt_binary_t *out);


typedef bool (*_mongocrypt_ctx_mongo_feed_fn) (mongocrypt_ctx_t *ctx,
                                               mongocrypt_binary_t *in);


typedef bool (*_mongocrypt_ctx_mongo_done_fn) (mongocrypt_ctx_t *ctx);


typedef bool (*_mongocrypt_ctx_finalize_fn) (mongocrypt_ctx_t *ctx,
                                             mongocrypt_binary_t *out);


typedef void (*_mongocrypt_ctx_cleanup_fn) (mongocrypt_ctx_t *ctx);

typedef mongocrypt_kms_ctx_t *(*_mongocrypt_ctx_next_kms_fn) (
   mongocrypt_ctx_t *ctx);

typedef bool (*_mongocrypt_ctx_kms_done_fn) (mongocrypt_ctx_t *ctx);


typedef struct {
   _mongocrypt_ctx_mongo_op_fn mongo_op_collinfo;
   _mongocrypt_ctx_mongo_feed_fn mongo_feed_collinfo;
   _mongocrypt_ctx_mongo_done_fn mongo_done_collinfo;

   _mongocrypt_ctx_mongo_op_fn mongo_op_markings;
   _mongocrypt_ctx_mongo_feed_fn mongo_feed_markings;
   _mongocrypt_ctx_mongo_done_fn mongo_done_markings;

   _mongocrypt_ctx_next_kms_fn next_kms_ctx;
   _mongocrypt_ctx_kms_done_fn kms_done;

   _mongocrypt_ctx_finalize_fn finalize;

   _mongocrypt_ctx_cleanup_fn cleanup;
} _mongocrypt_vtable_t;


struct _mongocrypt_ctx_t {
   mongocrypt_t *crypt;
   mongocrypt_ctx_state_t state;
   _mongocrypt_ctx_type_t type;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_t kb;
   _mongocrypt_vtable_t vtable;
   _mongocrypt_ctx_opts_t opts;
   uint32_t id;
};


/* Transition to the error state. An error status must have been set. */
bool
_mongocrypt_ctx_fail (mongocrypt_ctx_t *ctx);


/* Set an error status and transition to the error state. */
bool
_mongocrypt_ctx_fail_w_msg (mongocrypt_ctx_t *ctx, const char *msg);


typedef struct {
   mongocrypt_ctx_t parent;
   bool explicit;
   char *ns;
   const char *coll_name; /* points inside ns */
   _mongocrypt_buffer_t list_collections_filter;
   _mongocrypt_buffer_t schema;
   _mongocrypt_buffer_t original_cmd;
   _mongocrypt_buffer_t marking_cmd;
   _mongocrypt_buffer_t marked_cmd;
   _mongocrypt_buffer_t encrypted_cmd;
   _mongocrypt_buffer_t iv;
   _mongocrypt_buffer_t key_id;
} _mongocrypt_ctx_encrypt_t;


typedef struct {
   mongocrypt_ctx_t parent;
   bool explicit;
   _mongocrypt_buffer_t original_doc;
   _mongocrypt_buffer_t unwrapped_doc; /* explicit only */
   _mongocrypt_buffer_t decrypted_doc;
} _mongocrypt_ctx_decrypt_t;


typedef struct {
   mongocrypt_ctx_t parent;
   mongocrypt_kms_ctx_t kms;
   bool kms_returned;
   _mongocrypt_buffer_t key_doc;
   _mongocrypt_buffer_t encrypted_key_material;
} _mongocrypt_ctx_datakey_t;

/* Common initialization. */
bool
_mongocrypt_ctx_init (mongocrypt_ctx_t *ctx);

bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             int32_t ns_len);

bool
mongocrypt_ctx_decrypt_init (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *doc);

bool
mongocrypt_ctx_datakey_init (mongocrypt_ctx_t *ctx);

#endif /* MONGOCRYPT_CTX_PRIVATE_H */
