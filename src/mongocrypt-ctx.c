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

#define ALGORITHM_DETERMINISTIC "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
#define ALGORITHM_DETERMINISTIC_LEN 43
#define ALGORITHM_RANDOM "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
#define ALGORITHM_RANDOM_LEN 36


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
                 _mongocrypt_buffer_t *buf,
                 bson_subtype_t subtype)
{
   BSON_ASSERT (ctx);

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (!binary || !binary->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option must be non-NULL");
   }

   if (!_mongocrypt_buffer_empty (buf)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option already set");
   }

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (subtype == BSON_SUBTYPE_UUID && binary->len != 16) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "expected 16 byte UUID");
   }

   _mongocrypt_buffer_copy_from_binary (buf, binary);
   buf->subtype = subtype;

   return true;
}


bool
mongocrypt_ctx_setopt_key_id (mongocrypt_ctx_t *ctx,
                              mongocrypt_binary_t *key_id)
{
   return _set_binary_opt (ctx, key_id, &ctx->opts.key_id, BSON_SUBTYPE_UUID);
}


bool
mongocrypt_ctx_setopt_key_alt_name (mongocrypt_ctx_t *ctx,
                                    mongocrypt_binary_t *key_alt_name)
{
   bson_t as_bson;
   bson_iter_t iter;

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (!key_alt_name || !key_alt_name->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option must be non-NULL");
   }

   if (ctx->opts.key_alt_name) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option already set");
   }

   if (!_mongocrypt_binary_to_bson (key_alt_name, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid keyAltName bson object");
   }

   if (!bson_iter_init (&iter, &as_bson) || !bson_iter_next (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid bson");
   }

   if (0 != strcmp(bson_iter_key (&iter), "keyAltName")) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "keyAltName must have field 'keyAltName'");
   }

   if (!BSON_ITER_HOLDS_UTF8 (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "keyAltName expected to be UTF8");
   }

   ctx->opts.key_alt_name = bson_malloc0 (sizeof (bson_value_t));
   bson_value_copy (bson_iter_value (&iter), ctx->opts.key_alt_name);

   if (bson_iter_next (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "unrecognized field, only keyAltName expected");
   }

   return true;
}


bool
mongocrypt_ctx_setopt_algorithm (mongocrypt_ctx_t *ctx,
                                 const char *algorithm,
                                 int len)
{
   size_t calculated_len;

   BSON_ASSERT (ctx);

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "already set algorithm");
   }

   if (len < -1) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid algorithm length");
   }

   if (!algorithm) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "passed null algorithm");
   }

   calculated_len = len == -1 ? strlen (algorithm) : (size_t) len;

   if (calculated_len == ALGORITHM_DETERMINISTIC_LEN &&
       strncmp (algorithm,
                ALGORITHM_DETERMINISTIC,
                ALGORITHM_DETERMINISTIC_LEN) == 0) {
      ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;
      return true;
   }

   if (calculated_len == ALGORITHM_RANDOM_LEN &&
       strncmp (algorithm,
                ALGORITHM_RANDOM,
                ALGORITHM_RANDOM_LEN) == 0) {
      ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM;
      return true;
   }

   return _mongocrypt_ctx_fail_w_msg (ctx, "unsupported algorithm");
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
   ctx->status = mongocrypt_status_new ();
   ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE;
   ctx->state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   return ctx;
}

#define CHECK_AND_CALL(fn, ...)                                                \
   do {                                                                        \
      if (!ctx->vtable.fn) {                                                   \
         return _mongocrypt_ctx_fail_w_msg (ctx, "not applicable to context"); \
      }                                                                        \
      return ctx->vtable.fn (__VA_ARGS__);                                     \
   } while (0)

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
   if (_mongocrypt_key_broker_any_state (&ctx->kb, KEY_EMPTY)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "did not provide all keys");
   }
   return _mongocrypt_ctx_state_from_key_broker (ctx);
}

static mongocrypt_kms_ctx_t *
_next_kms_ctx (mongocrypt_ctx_t *ctx)
{
   return _mongocrypt_key_broker_next_kms (&ctx->kb);
}


static bool
_kms_done (mongocrypt_ctx_t *ctx)
{
   if (!_mongocrypt_key_broker_kms_done (&ctx->kb)) {
      BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }
   ctx->state = MONGOCRYPT_CTX_READY;
   return true;
}


bool
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   if (!out) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }

   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      CHECK_AND_CALL (mongo_op_collinfo, ctx, out);
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      CHECK_AND_CALL (mongo_op_markings, ctx, out);
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      CHECK_AND_CALL (mongo_op_keys, ctx, out);
   case MONGOCRYPT_CTX_ERROR:
      return false;
   default:
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
}


bool
mongocrypt_ctx_mongo_feed (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   if (!in) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }

   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      CHECK_AND_CALL (mongo_feed_collinfo, ctx, in);
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      CHECK_AND_CALL (mongo_feed_markings, ctx, in);
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      CHECK_AND_CALL (mongo_feed_keys, ctx, in);
   case MONGOCRYPT_CTX_ERROR:
      return false;
   default:
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
}


bool
mongocrypt_ctx_mongo_done (mongocrypt_ctx_t *ctx)
{
   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      CHECK_AND_CALL (mongo_done_collinfo, ctx);
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      CHECK_AND_CALL (mongo_done_markings, ctx);
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      CHECK_AND_CALL (mongo_done_keys, ctx);
   case MONGOCRYPT_CTX_ERROR:
      return false;
   default:
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
}


mongocrypt_ctx_state_t
mongocrypt_ctx_state (mongocrypt_ctx_t *ctx)
{
   return ctx->state;
}


mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx)
{
   if (!ctx->vtable.next_kms_ctx) {
      _mongocrypt_ctx_fail_w_msg (ctx, "not applicable to context");
      return NULL;
   }

   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_KMS:
      return ctx->vtable.next_kms_ctx (ctx);
   case MONGOCRYPT_CTX_ERROR:
      return false;
   default:
      _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
      return NULL;
   }
}


bool
mongocrypt_ctx_kms_done (mongocrypt_ctx_t *ctx)
{
   if (!ctx->vtable.kms_done) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "not applicable to context");
   }

   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_KMS:
      return ctx->vtable.kms_done (ctx);
   case MONGOCRYPT_CTX_ERROR:
      return false;
   default:
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
}


bool
mongocrypt_ctx_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   if (!out) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }

   if (!ctx->vtable.finalize) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "not applicable to context");
   }

   switch (ctx->state) {
   case MONGOCRYPT_CTX_READY:
      return ctx->vtable.finalize (ctx, out);
   case MONGOCRYPT_CTX_ERROR:
      return false;
   default:
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }
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

   /* remove any pending items from cache. */
   _mongocrypt_cache_remove_by_owner (&ctx->crypt->cache_key, ctx->id);

   if (ctx->vtable.cleanup) {
      ctx->vtable.cleanup (ctx);
   }

   bson_free (ctx->opts.masterkey_aws_region);
   bson_free (ctx->opts.masterkey_aws_cmk);
   mongocrypt_status_destroy (ctx->status);
   _mongocrypt_key_broker_cleanup (&ctx->kb);
   if (ctx->opts.key_alt_name) {
      bson_value_destroy (ctx->opts.key_alt_name);
      bson_free (ctx->opts.key_alt_name);
   }
   _mongocrypt_buffer_cleanup (&ctx->opts.key_id);
   _mongocrypt_buffer_cleanup (&ctx->opts.local_schema);
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
   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (ctx->opts.masterkey_kms_provider) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "master key already set");
   }

   if (!_mongocrypt_validate_and_copy_string (
          region, region_len, &ctx->opts.masterkey_aws_region) ||
       region_len == 0) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid region");
   }

   if (!_mongocrypt_validate_and_copy_string (
          cmk, cmk_len, &ctx->opts.masterkey_aws_cmk) ||
       cmk_len == 0) {
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
   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

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
   bson_t tmp;
   bson_error_t bson_err;

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (!schema || !mongocrypt_binary_data (schema)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "passed null schema");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.local_schema)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "already set schema");
   }

   _mongocrypt_buffer_copy_from_binary (&ctx->opts.local_schema, schema);

   /* validate bson */
   if (!_mongocrypt_buffer_to_bson (&ctx->opts.local_schema, &tmp)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid bson");
   }

   if (!bson_validate_with_error (&tmp, BSON_VALIDATE_NONE, &bson_err)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, bson_err.message);
   }

   return true;
}


uint32_t
mongocrypt_ctx_id (mongocrypt_ctx_t *ctx)
{
   return ctx->id;
}


bool
_mongocrypt_ctx_init (mongocrypt_ctx_t *ctx,
                      _mongocrypt_ctx_opts_spec_t *opts_spec)
{
   bool has_id = false, has_alt_name = false;

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot double initialized");
   }
   ctx->initialized = true;

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }
   /* Set some default functions */
   ctx->vtable.mongo_op_keys = _mongo_op_keys;
   ctx->vtable.mongo_feed_keys = _mongo_feed_keys;
   ctx->vtable.mongo_done_keys = _mongo_done_keys;
   ctx->vtable.next_kms_ctx = _next_kms_ctx;
   ctx->vtable.kms_done = _kms_done;

   /* Check that required options are included and prohibited options are not.
    */

   if (opts_spec->masterkey == OPT_REQUIRED) {
      if (!ctx->opts.masterkey_kms_provider) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "master key required");
      }
      if (!(ctx->opts.masterkey_kms_provider &
            ctx->crypt->opts.kms_providers)) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "requested kms provider not configured");
      }
   }

   if (opts_spec->masterkey == OPT_PROHIBITED &&
       ctx->opts.masterkey_kms_provider) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "master key prohibited");
   }

   if (opts_spec->schema == OPT_REQUIRED &&
       _mongocrypt_buffer_empty (&ctx->opts.local_schema)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "schema required");
   }

   if (opts_spec->schema == OPT_PROHIBITED &&
       !_mongocrypt_buffer_empty (&ctx->opts.local_schema)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "schema prohibited");
   }

   has_id = !_mongocrypt_buffer_empty (&ctx->opts.key_id);
   has_alt_name = !!(ctx->opts.key_alt_name);

   if (opts_spec->key_descriptor == OPT_REQUIRED) {

      if (!has_id && !has_alt_name) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx,
            "either key id or key alt name required");
      }

      if (has_id && has_alt_name) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx,
            "cannot have both key id and key alt name");
      }
   }

   if (opts_spec->key_descriptor == OPT_PROHIBITED && (has_id || has_alt_name)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "key id and alt name prohibited");
   }

   if (opts_spec->algorithm == OPT_REQUIRED && ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "algorithm required");
   }

   if (opts_spec->algorithm == OPT_PROHIBITED &&
       ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "algorithm prohibited");
   }

   _mongocrypt_mutex_lock (&ctx->crypt->mutex);
   ctx->id = ctx->crypt->ctx_counter++;
   _mongocrypt_mutex_unlock (&ctx->crypt->mutex);
   _mongocrypt_key_broker_init (
      &ctx->kb, ctx->id, &ctx->crypt->opts, &ctx->crypt->cache_key);
   return true;
}

uint32_t
mongocrypt_ctx_next_dependent_ctx_id (mongocrypt_ctx_t *ctx)
{
   return ctx->vtable.next_dependent_ctx_id (ctx);
}

bool
mongocrypt_ctx_wait_done (mongocrypt_ctx_t *ctx)
{
   return ctx->vtable.wait_done (ctx);
}


bool
mongocrypt_ctx_setopt_cache_noblock (mongocrypt_ctx_t *ctx)
{
   ctx->cache_noblock = true;
   return true;
}

bool
_mongocrypt_ctx_state_from_key_broker (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_key_broker_t *kb;
   mongocrypt_status_t *status;
   mongocrypt_ctx_state_t new_state;
   bool ret;

   status = ctx->status;
   kb = &ctx->kb;

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (!mongocrypt_status_ok (kb->status)) {
      _mongocrypt_status_copy_to (kb->status, status);
      new_state = MONGOCRYPT_CTX_ERROR;
      ret = false;
   } else if (kb->kb_entry == NULL) {
      /* No key entries were ever added. */
      new_state = MONGOCRYPT_CTX_NOTHING_TO_DO;
      ret = true;
   } else if (_mongocrypt_key_broker_any_state (kb, KEY_EMPTY)) {
      /* Empty keys require documents. */
      new_state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
      ret = true;
   } else if (_mongocrypt_key_broker_any_state (kb, KEY_ENCRYPTED) ||
              _mongocrypt_key_broker_any_state (kb, KEY_DECRYPTING)) {
      /* Encrypted keys need KMS. */
      new_state = MONGOCRYPT_CTX_NEED_KMS;
      ret = true;
   } else if (_mongocrypt_key_broker_any_state (kb,
                                                KEY_WAITING_FOR_OTHER_CTX)) {
      /* Keys in cache need waiting. */
      new_state = MONGOCRYPT_CTX_WAITING;
      ret = true;
   } else if (!_mongocrypt_key_broker_all_state (kb, KEY_DECRYPTED)) {
      /* All keys must be decrypted. */
      CLIENT_ERR ("key broker in invalid state");
      new_state = MONGOCRYPT_CTX_ERROR;
      ret = false;
   } else {
      new_state = MONGOCRYPT_CTX_READY;
      ret = true;
   }

   if (new_state != ctx->state) {
      /* reset the ctx_id and kms iterators on state change. */
      _mongocrypt_key_broker_reset_iterators (kb);
      ctx->state = new_state;
   }

   return ret;
}
