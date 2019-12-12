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

#include "mongocrypt-ctx-private.h"
#include "mongocrypt-key-broker-private.h"

#define ALGORITHM_DETERMINISTIC "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
#define ALGORITHM_DETERMINISTIC_LEN 43
#define ALGORITHM_RANDOM "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
#define ALGORITHM_RANDOM_LEN 36

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

/* A failure status has already been set. */
bool
_mongocrypt_ctx_fail (mongocrypt_ctx_t *ctx)
{
   if (mongocrypt_status_ok (ctx->status)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "unexpected, failing but no error status set");
   }
   ctx->state = MONGOCRYPT_CTX_ERROR;
   return false;
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
   if (!ctx) {
      return false;
   }

   if (ctx->crypt->log.trace_enabled && key_id && key_id->data) {
      char *key_id_val;
      key_id_val =
         _mongocrypt_new_string_from_bytes (key_id->data, key_id->len);
      _mongocrypt_log (&ctx->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\")",
                       BSON_FUNC,
                       "key_id",
                       key_id_val);
      bson_free (key_id_val);
   }

   return _set_binary_opt (ctx, key_id, &ctx->opts.key_id, BSON_SUBTYPE_UUID);
}


bool
mongocrypt_ctx_setopt_key_alt_name (mongocrypt_ctx_t *ctx,
                                    mongocrypt_binary_t *key_alt_name)
{
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_key_alt_name_t *new_key_alt_name;
   const char *key;

   if (!ctx) {
      return false;
   }

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (!key_alt_name || !key_alt_name->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "option must be non-NULL");
   }

   if (!_mongocrypt_binary_to_bson (key_alt_name, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid keyAltName bson object");
   }

   if (!bson_iter_init (&iter, &as_bson) || !bson_iter_next (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid bson");
   }

   key = bson_iter_key (&iter);
   BSON_ASSERT (key);
   if (0 != strcmp (key, "keyAltName")) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "keyAltName must have field 'keyAltName'");
   }

   if (!BSON_ITER_HOLDS_UTF8 (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "keyAltName expected to be UTF8");
   }

   new_key_alt_name = _mongocrypt_key_alt_name_new (bson_iter_value (&iter));

   if (ctx->opts.key_alt_names &&
       _mongocrypt_key_alt_name_intersects (ctx->opts.key_alt_names,
                                            new_key_alt_name)) {
      _mongocrypt_key_alt_name_destroy_all (new_key_alt_name);
      return _mongocrypt_ctx_fail_w_msg (ctx, "duplicate keyAltNames found");
   }
   new_key_alt_name->next = ctx->opts.key_alt_names;
   ctx->opts.key_alt_names = new_key_alt_name;

   if (bson_iter_next (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "unrecognized field, only keyAltName expected");
   }

   return true;
}


bool
mongocrypt_ctx_setopt_algorithm (mongocrypt_ctx_t *ctx,
                                 const char *algorithm,
                                 int len)
{
   size_t calculated_len;

   if (!ctx) {
      return false;
   }

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
   if (ctx->crypt->log.trace_enabled) {
      _mongocrypt_log (&ctx->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%.*s\")",
                       BSON_FUNC,
                       "algorithm",
                       (int) calculated_len,
                       algorithm);
   }

   if (calculated_len == ALGORITHM_DETERMINISTIC_LEN &&
       strncmp (algorithm,
                ALGORITHM_DETERMINISTIC,
                ALGORITHM_DETERMINISTIC_LEN) == 0) {
      ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;
      return true;
   }

   if (calculated_len == ALGORITHM_RANDOM_LEN &&
       strncmp (algorithm, ALGORITHM_RANDOM, ALGORITHM_RANDOM_LEN) == 0) {
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

   if (!crypt) {
      return NULL;
   }
   if (!crypt->initialized) {
      mongocrypt_status_t *status;

      status = crypt->status;
      CLIENT_ERR ("cannot create context from uninitialized crypt");
      return NULL;
   }
   ctx_size = sizeof (_mongocrypt_ctx_encrypt_t);
   if (sizeof (_mongocrypt_ctx_decrypt_t) > ctx_size) {
      ctx_size = sizeof (_mongocrypt_ctx_decrypt_t);
   }
   if (sizeof (_mongocrypt_ctx_datakey_t) > ctx_size) {
      ctx_size = sizeof (_mongocrypt_ctx_datakey_t);
   }
   ctx = bson_malloc0 (ctx_size);
   BSON_ASSERT (ctx);

   ctx->crypt = crypt;
   ctx->status = mongocrypt_status_new ();
   ctx->opts.algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE;
   ctx->state = MONGOCRYPT_CTX_DONE;
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
   (void) _mongocrypt_key_broker_docs_done (&ctx->kb);
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
   if (!ctx) {
      return false;
   }
   if (!ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
   }

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
   if (!ctx) {
      return false;
   }
   if (!ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
   }

   if (!in) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid NULL input");
   }

   if (ctx->crypt->log.trace_enabled) {
      char *in_val;

      in_val = _mongocrypt_new_json_string_from_binary (in);
      _mongocrypt_log (&ctx->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\")",
                       BSON_FUNC,
                       "in",
                       in_val);
      bson_free (in_val);
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
   if (!ctx) {
      return false;
   }
   if (!ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
   }

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
   if (!ctx) {
      return MONGOCRYPT_CTX_ERROR;
   }
   if (!ctx->initialized) {
      _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
      return MONGOCRYPT_CTX_ERROR;
   }

   return ctx->state;
}


mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx)
{
   if (!ctx) {
      return NULL;
   }
   if (!ctx->initialized) {
      _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
      return NULL;
   }

   if (!ctx->vtable.next_kms_ctx) {
      _mongocrypt_ctx_fail_w_msg (ctx, "not applicable to context");
      return NULL;
   }

   switch (ctx->state) {
   case MONGOCRYPT_CTX_NEED_KMS:
      return ctx->vtable.next_kms_ctx (ctx);
   case MONGOCRYPT_CTX_ERROR:
      return NULL;
   default:
      _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
      return NULL;
   }
}


bool
mongocrypt_ctx_kms_done (mongocrypt_ctx_t *ctx)
{
   if (!ctx) {
      return false;
   }
   if (!ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
   }

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
   if (!ctx) {
      return false;
   }
   if (!ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "ctx NULL or uninitialized");
   }

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
   if (!ctx) {
      return false;
   }

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
   bson_free (ctx->opts.masterkey_aws_endpoint);
   mongocrypt_status_destroy (ctx->status);
   _mongocrypt_key_broker_cleanup (&ctx->kb);
   _mongocrypt_key_alt_name_destroy_all (ctx->opts.key_alt_names);
   _mongocrypt_buffer_cleanup (&ctx->opts.key_id);
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
   if (!ctx) {
      return false;
   }
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

   if (ctx->crypt->log.trace_enabled) {
      _mongocrypt_log (&ctx->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\", %s=%d, %s=\"%s\", %s=%d)",
                       BSON_FUNC,
                       "region",
                       ctx->opts.masterkey_aws_region,
                       "region_len",
                       region_len,
                       "cmk",
                       ctx->opts.masterkey_aws_cmk,
                       "cmk_len",
                       cmk_len);
   }

   ctx->opts.masterkey_kms_provider = MONGOCRYPT_KMS_PROVIDER_AWS;
   ctx->opts.masterkey_aws_region_len = region_len;
   ctx->opts.masterkey_aws_cmk_len = cmk_len;
   return true;
}


bool
mongocrypt_ctx_setopt_masterkey_local (mongocrypt_ctx_t *ctx)
{
   if (!ctx) {
      return false;
   }
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
_mongocrypt_ctx_init (mongocrypt_ctx_t *ctx,
                      _mongocrypt_ctx_opts_spec_t *opts_spec)
{
   bool has_id = false, has_alt_name = false, has_multiple_alt_names = false;

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot double initialize");
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

   /* Check that required options are included and prohibited options are
    * not.
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

   /* Special case. key_descriptor applies to explicit encryption. It must be
    * either a key id or *one* key alt name, but not both.
    * key_alt_names applies to creating a data key. It may be one or multiple
    * key alt names.
    */
   has_id = !_mongocrypt_buffer_empty (&ctx->opts.key_id);
   has_alt_name = !!(ctx->opts.key_alt_names);
   has_multiple_alt_names = has_alt_name && !!(ctx->opts.key_alt_names->next);

   if (opts_spec->key_descriptor == OPT_REQUIRED) {
      if (!has_id && !has_alt_name) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "either key id or key alt name required");
      }

      if (has_id && has_alt_name) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "cannot have both key id and key alt name");
      }

      if (has_multiple_alt_names) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "must not specify multiple key alt names");
      }
   }

   if (opts_spec->key_descriptor == OPT_PROHIBITED) {
      /* still okay if key_alt_names are allowed and only alt names were
       * specified. */
      if ((opts_spec->key_alt_names == OPT_PROHIBITED && has_alt_name) ||
          has_id) {
         return _mongocrypt_ctx_fail_w_msg (ctx,
                                            "key id and alt name prohibited");
      }
   }

   if (opts_spec->algorithm == OPT_REQUIRED &&
       ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "algorithm required");
   }

   if (opts_spec->algorithm == OPT_PROHIBITED &&
       ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "algorithm prohibited");
   }

   if (opts_spec->endpoint == OPT_REQUIRED &&
       !ctx->opts.masterkey_aws_endpoint) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "endpoint required");
   }

   if (opts_spec->endpoint == OPT_PROHIBITED &&
       ctx->opts.masterkey_aws_endpoint) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "endpoint prohibited");
   }

   _mongocrypt_key_broker_init (&ctx->kb, ctx->crypt);
   return true;
}

bool
_mongocrypt_ctx_state_from_key_broker (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_key_broker_t *kb;
   mongocrypt_status_t *status;
   mongocrypt_ctx_state_t new_state = MONGOCRYPT_CTX_ERROR;
   bool ret = false;

   status = ctx->status;
   kb = &ctx->kb;

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }


   switch (kb->state) {
   case KB_ERROR:
      _mongocrypt_status_copy_to (kb->status, status);
      new_state = MONGOCRYPT_CTX_ERROR;
      ret = false;
      break;
   case KB_ADDING_DOCS:
      /* Require key documents from driver. */
      new_state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
      ret = true;
      break;
   case KB_DECRYPTING_KEY_MATERIAL:
      /* Encrypted keys need KMS. */
      new_state = MONGOCRYPT_CTX_NEED_KMS;
      ret = true;
      break;
   case KB_DONE:
      new_state = MONGOCRYPT_CTX_READY;
      if (kb->key_requests == NULL) {
         /* No key requests were ever added. */
         ctx->nothing_to_do = true; /* nothing to encrypt/decrypt */
      }
      ret = true;
      break;
   /* As currently implemented, we do not expect to ever be in KB_REQUESTING
    * state when calling this function. */
   case KB_REQUESTING:
      CLIENT_ERR ("key broker in unexpected state");
      new_state = MONGOCRYPT_CTX_ERROR;
      ret = false;
      break;
   }

   if (new_state != ctx->state) {
      ctx->state = new_state;
   }

   return ret;
}


bool
mongocrypt_ctx_setopt_masterkey_aws_endpoint (mongocrypt_ctx_t *ctx,
                                              const char *endpoint,
                                              int32_t endpoint_len)
{
   if (!ctx) {
      return false;
   }

   if (ctx->initialized) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot set options after init");
   }

   if (ctx->state == MONGOCRYPT_CTX_ERROR) {
      return false;
   }

   if (ctx->opts.masterkey_aws_endpoint) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "already set masterkey endpoint");
   }

   if (!_mongocrypt_validate_and_copy_string (
          endpoint, endpoint_len, &ctx->opts.masterkey_aws_endpoint)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid masterkey endpoint");
   }
   ctx->opts.masterkey_aws_endpoint_len = endpoint_len;
   return true;
}