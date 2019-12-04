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
#include "mongocrypt-key-private.h"

typedef enum {
   _MONGOCRYPT_TYPE_NONE,
   _MONGOCRYPT_TYPE_ENCRYPT,
   _MONGOCRYPT_TYPE_DECRYPT,
   _MONGOCRYPT_TYPE_CREATE_DATA_KEY,
} _mongocrypt_ctx_type_t;


/* Option values are validated when set.
 * Different contexts accept/require different options,
 * validated when a context is initialized.
 */
typedef struct __mongocrypt_ctx_opts_t {
   _mongocrypt_kms_provider_t masterkey_kms_provider;
   char *masterkey_aws_cmk;
   uint32_t masterkey_aws_cmk_len;
   char *masterkey_aws_region;
   uint32_t masterkey_aws_region_len;
   char *masterkey_aws_endpoint;
   uint32_t masterkey_aws_endpoint_len;
   _mongocrypt_buffer_t key_id;
   _mongocrypt_key_alt_name_t *key_alt_names;
   mongocrypt_encryption_algorithm_t algorithm;
} _mongocrypt_ctx_opts_t;


/* All derived contexts may override these methods. */
typedef struct {
   bool (*mongo_op_collinfo) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);
   bool (*mongo_feed_collinfo) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in);
   bool (*mongo_done_collinfo) (mongocrypt_ctx_t *ctx);
   bool (*mongo_op_markings) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);
   bool (*mongo_feed_markings) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in);
   bool (*mongo_done_markings) (mongocrypt_ctx_t *ctx);
   bool (*mongo_op_keys) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);
   bool (*mongo_feed_keys) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in);
   bool (*mongo_done_keys) (mongocrypt_ctx_t *ctx);
   mongocrypt_kms_ctx_t *(*next_kms_ctx) (mongocrypt_ctx_t *ctx);
   bool (*kms_done) (mongocrypt_ctx_t *ctx);
   bool (*finalize) (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);
   void (*cleanup) (mongocrypt_ctx_t *ctx);
} _mongocrypt_vtable_t;


struct _mongocrypt_ctx_t {
   mongocrypt_t *crypt;
   mongocrypt_ctx_state_t state;
   _mongocrypt_ctx_type_t type;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_t kb;
   _mongocrypt_vtable_t vtable;
   _mongocrypt_ctx_opts_t opts;
   bool initialized;
   bool
      nothing_to_do; /* set to true if no encryption/decryption is required. */
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
   char *coll_name;
   char *db_name;
   char *ns;
   _mongocrypt_buffer_t list_collections_filter;
   _mongocrypt_buffer_t schema;
   /* TODO CDRIVER-3150: audit + rename these buffers.
    * original_cmd for explicit is {v: <BSON value>}, for auto is the command to
    * be encrypted.
    *
    * mongocryptd_cmd is only applicable for auto encryption. It is the original
    * command with JSONSchema appended.
    *
    * marked_cmd is the value of the 'result' field in mongocryptd response
    *
    * encrypted_cmd is the final output, the original command encrypted, or for
    * explicit, the {v: <ciphertext>} doc.
    */
   _mongocrypt_buffer_t original_cmd;
   _mongocrypt_buffer_t mongocryptd_cmd;
   _mongocrypt_buffer_t marked_cmd;
   _mongocrypt_buffer_t encrypted_cmd;
   _mongocrypt_buffer_t key_id;
   bool used_local_schema;
   /* collinfo_has_siblings is true if the schema came from a remote JSON
    * schema, and there were siblings. */
   bool collinfo_has_siblings;
} _mongocrypt_ctx_encrypt_t;


typedef struct {
   mongocrypt_ctx_t parent;
   bool explicit;
   /* TODO CDRIVER-3150: audit + rename these buffers.
    * Unlike ctx_encrypt, unwrapped_doc holds the binary value of the {v:
    * <ciphertext>} doc.
    * */
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


/* Used for option validation. True means required. False means prohibited. */
typedef enum {
   OPT_PROHIBITED = 0,
   OPT_REQUIRED,
   OPT_OPTIONAL
} _mongocrypt_ctx_opt_spec_t;
typedef struct {
   _mongocrypt_ctx_opt_spec_t masterkey;
   _mongocrypt_ctx_opt_spec_t schema;
   _mongocrypt_ctx_opt_spec_t key_descriptor; /* a key_id or key_alt_name */
   _mongocrypt_ctx_opt_spec_t key_alt_names;
   _mongocrypt_ctx_opt_spec_t algorithm;
   _mongocrypt_ctx_opt_spec_t endpoint;
} _mongocrypt_ctx_opts_spec_t;

/* Common initialization. */
bool
_mongocrypt_ctx_init (mongocrypt_ctx_t *ctx,
                      _mongocrypt_ctx_opts_spec_t *opt_spec)
   MONGOCRYPT_WARN_UNUSED_RESULT;

/* Set the state of the context from the state of keys in the key broker. */
bool
_mongocrypt_ctx_state_from_key_broker (mongocrypt_ctx_t *ctx)
   MONGOCRYPT_WARN_UNUSED_RESULT;

#endif /* MONGOCRYPT_CTX_PRIVATE_H */
