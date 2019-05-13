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

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-key-broker-private.h"


/* A failure status has already been set. */
bool
_mongocrypt_ctx_fail (mongocrypt_ctx_t *ctx)
{
   BSON_ASSERT (!mongocrypt_status_ok (ctx->status));
   ctx->state = MONGOCRYPT_CTX_ERROR;
   return false;
}


bool
_mongocrypt_ctx_fail_w_msg (mongocrypt_ctx_t *ctx, const char *msg)
{
   _mongocrypt_set_error (ctx->status,
                          MONGOCRYPT_STATUS_ERROR_CLIENT,
                          MONGOCRYPT_GENERIC_ERROR_CODE,
                          "%s",
                          msg);
   return _mongocrypt_ctx_fail (ctx);
}


static bool
_set_binary_opt (mongocrypt_ctx_t *ctx,
                 mongocrypt_binary_t *binary,
                 _mongocrypt_buffer_t *buf)
{
   BSON_ASSERT (ctx);

   if (!binary) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option must be non-NULL");
   }

   if (!_mongocrypt_buffer_empty (buf)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option already set");
   }

   _mongocrypt_buffer_copy_from_binary (buf, binary);
   buf->subtype = BSON_SUBTYPE_UUID;

   return true;
}

bool
mongocrypt_ctx_setopt_key_id (mongocrypt_ctx_t *ctx,
                              mongocrypt_binary_t *key_id)
{
   return _set_binary_opt (ctx, key_id, &ctx->opts.key_id);
}

bool
mongocrypt_ctx_setopt_key_alt_name (mongocrypt_ctx_t *ctx,
                                    mongocrypt_binary_t *key_alt_name)
{
   return _set_binary_opt (ctx, key_alt_name, &ctx->opts.key_alt_name);
}


bool
mongocrypt_ctx_setopt_algorithm (mongocrypt_ctx_t *ctx,
                                 char *algorithm,
                                 int len)
{
   size_t calculated_len;

   BSON_ASSERT (ctx);

   calculated_len = len == -1 ? strlen (algorithm) : (size_t) len;

   if (strncmp (algorithm,
                "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                calculated_len) == 0) {
      ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;
      return true;
   }

   if (strncmp (algorithm,
                "AEAD_AES_256_CBC_HMAC_SHA_512-Randomized",
                calculated_len) == 0) {
      ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM;
      return true;
   }

   return _mongocrypt_ctx_fail_w_msg (ctx, "unsupported algorithm");
}


bool
mongocrypt_ctx_setopt_initialization_vector (mongocrypt_ctx_t *ctx,
                                             mongocrypt_binary_t *iv)
{
   return _set_binary_opt (ctx, iv, &ctx->opts.iv);
}


mongocrypt_ctx_t *
mongocrypt_ctx_new (mongocrypt_t *crypt)
{
   mongocrypt_ctx_t *ctx;
   int ctx_size;

   ctx_size = sizeof (_mongocrypt_ctx_encrypt_t);
   if (sizeof (_mongocrypt_ctx_decrypt_t) > ctx_size) {
      ctx_size = sizeof (_mongocrypt_ctx_decrypt_t);
   }
   if (sizeof (_mongocrypt_ctx_datakey_t) > ctx_size) {
      ctx_size = sizeof (_mongocrypt_ctx_datakey_t);
   }
   ctx = bson_malloc0 (ctx_size);
   ctx->crypt = crypt;
   /* TODO: whether the key broker aborts due to missing keys might be
    * responsibility of sub-contexts. */
   _mongocrypt_key_broker_init (&ctx->kb, &crypt->opts, &crypt->cache_key);
   ctx->status = mongocrypt_status_new ();
   ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE;
   return ctx;
}


/* Common to both encrypt and decrypt context. */
static bool
_mongo_op_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   /* Construct the find filter to fetch keys. */
   if (!_mongocrypt_key_broker_filter (&ctx->kb, out)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   return true;
}


static bool
_mongo_feed_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   _mongocrypt_buffer_t buf;

   _mongocrypt_buffer_from_binary (&buf, in);
   if (!_mongocrypt_key_broker_add_doc (&ctx->kb, &buf)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   return true;
}


static bool
_mongo_done_keys (mongocrypt_ctx_t *ctx)
{
   if (!_mongocrypt_key_broker_done_adding_docs (&ctx->kb)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   if (_mongocrypt_key_broker_has (&ctx->kb, KEY_ENCRYPTED)) {
      ctx->state = MONGOCRYPT_CTX_NEED_KMS;
   } else {
      /* If all keys were obtained from cache, or keys were decrypted with
       * "local"
       * KMS provider, then skip right to READY. */
      ctx->state = MONGOCRYPT_CTX_READY;
   }
   return true;
}


bool
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_mongo_op_fn callme;

   if (!out) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }

   callme = NULL;
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      callme = ctx->vtable.mongo_op_collinfo;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      callme = ctx->vtable.mongo_op_markings;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      callme = _mongo_op_keys;
      break;
   case MONGOCRYPT_CTX_NEED_KMS:
   case MONGOCRYPT_CTX_ERROR:
   case MONGOCRYPT_CTX_DONE:
   case MONGOCRYPT_CTX_READY:
   case MONGOCRYPT_CTX_NOTHING_TO_DO:
   case MONGOCRYPT_CTX_WAITING:
      break;
   }
   if (NULL == callme) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
   return callme (ctx, out);
}


bool
mongocrypt_ctx_mongo_feed (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   _mongocrypt_ctx_mongo_feed_fn callme;

   if (!in) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }

   callme = NULL;
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      callme = ctx->vtable.mongo_feed_collinfo;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      callme = ctx->vtable.mongo_feed_markings;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      callme = _mongo_feed_keys;
      break;
   case MONGOCRYPT_CTX_NEED_KMS:
   case MONGOCRYPT_CTX_ERROR:
   case MONGOCRYPT_CTX_DONE:
   case MONGOCRYPT_CTX_READY:
   case MONGOCRYPT_CTX_NOTHING_TO_DO:
   case MONGOCRYPT_CTX_WAITING:
      break;
   }

   if (NULL == callme) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }

   return callme (ctx, in);
}


bool
mongocrypt_ctx_mongo_done (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_mongo_done_fn callme;

   callme = NULL;
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      callme = ctx->vtable.mongo_done_collinfo;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      callme = ctx->vtable.mongo_done_markings;
      break;
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      callme = _mongo_done_keys;
      break;
   case MONGOCRYPT_CTX_NEED_KMS:
   case MONGOCRYPT_CTX_ERROR:
   case MONGOCRYPT_CTX_DONE:
   case MONGOCRYPT_CTX_READY:
   case MONGOCRYPT_CTX_NOTHING_TO_DO:
   case MONGOCRYPT_CTX_WAITING:
      break;
   }

   if (NULL == callme) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
   return callme (ctx);
}


mongocrypt_ctx_state_t
mongocrypt_ctx_state (mongocrypt_ctx_t *ctx)
{
   return ctx->state;
}


mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx)
{
   return ctx->vtable.next_kms_ctx (ctx);
}


bool
mongocrypt_ctx_kms_done (mongocrypt_ctx_t *ctx)
{
   return ctx->vtable.kms_done (ctx);
}


bool
mongocrypt_ctx_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   if (!out) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }
   return ctx->vtable.finalize (ctx, out);
}

bool
mongocrypt_ctx_status (mongocrypt_ctx_t *ctx, mongocrypt_status_t *out)
{
   if (!mongocrypt_status_ok (ctx->status)) {
      _mongocrypt_status_copy_to (ctx->status, out);
      return false;
   }
   _mongocrypt_status_reset (out);
   return true;
}


void
mongocrypt_ctx_destroy (mongocrypt_ctx_t *ctx)
{
   if (!ctx) {
      return;
   }

   if (ctx->vtable.cleanup) {
      ctx->vtable.cleanup (ctx);
   }

   bson_free (ctx->opts.masterkey_aws_region);
   bson_free (ctx->opts.masterkey_aws_cmk);
   mongocrypt_status_destroy (ctx->status);
   _mongocrypt_key_broker_cleanup (&ctx->kb);
   _mongocrypt_buffer_cleanup (&ctx->opts.key_alt_name);
   _mongocrypt_buffer_cleanup (&ctx->opts.key_id);
   _mongocrypt_buffer_cleanup (&ctx->opts.iv);
   bson_free (ctx);
   return;
}


bool
mongocrypt_ctx_setopt_masterkey_aws (mongocrypt_ctx_t *ctx,
                                     const char *region,
                                     int32_t region_len,
                                     const char *cmk,
                                     int32_t cmk_len)
{
   if (ctx->opts.masterkey_kms_provider) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "master key already set");
   }

   if (!_mongocrypt_validate_and_copy_string (
          region, region_len, &ctx->opts.masterkey_aws_region)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid region");
   }

   if (!_mongocrypt_validate_and_copy_string (
          cmk, cmk_len, &ctx->opts.masterkey_aws_cmk)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid cmk passed");
   }

   ctx->opts.masterkey_kms_provider = MONGOCRYPT_KMS_PROVIDER_AWS;
   ctx->opts.masterkey_aws_region_len = region_len;
   ctx->opts.masterkey_aws_cmk_len = cmk_len;
   return true;
}


bool
mongocrypt_ctx_setopt_masterkey_local (mongocrypt_ctx_t *ctx)
{
   if (ctx->opts.masterkey_kms_provider) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "master key already set");
   }

   ctx->opts.masterkey_kms_provider = MONGOCRYPT_KMS_PROVIDER_LOCAL;
   return true;
}


bool
mongocrypt_ctx_setopt_schema (mongocrypt_ctx_t *ctx,
                              mongocrypt_binary_t *schema)
{
   if (!schema || !mongocrypt_binary_data (schema)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "passed null schema");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.local_schema)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "already set schema");
   }

   _mongocrypt_buffer_copy_from_binary (&ctx->opts.local_schema, schema);
   return true;
}


uint32_t
mongocrypt_ctx_id (mongocrypt_ctx_t *ctx)
{
   return ctx->id;
}


bool
_mongocrypt_ctx_init (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_mutex_lock (&ctx->crypt->mutex);
   ctx->id = ctx->crypt->ctx_counter++;
   _mongocrypt_mutex_unlock (&ctx->crypt->mutex);
   return true;
}

uint32_t
mongocrypt_ctx_next_dependant_ctx_id (mongocrypt_ctx_t *ctx)
{
   /* TODO: CDRIVER-3095 */
   return 0;
}

bool
mongocrypt_ctx_wait_done (mongocrypt_ctx_t *ctx)
{
   /* TODO: CDRIVER-3095 */
   return true;
}


bool
mongocrypt_ctx_setopt_cache_noblock (mongocrypt_ctx_t *ctx)
{
   /* TODO: CDRIVER-3095 */
   return true;
}
