/*
 * Copyright 2022-present MongoDB, Inc.
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

#include "mongocrypt-ctx-private.h"

#include "mc-tokens-private.h"

static void
_cleanup (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_compact_t *const cctx = (_mongocrypt_ctx_compact_t *) ctx;

   BSON_ASSERT_PARAM (ctx);

   _mongocrypt_buffer_cleanup (&cctx->result);
   mc_EncryptedFieldConfig_cleanup (&cctx->efc);
}

/* _finalize creates map of field path to ECOC token. */
static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t result_bson = BSON_INITIALIZER;
   bson_t result_compactionTokens;
   bool ret = false;
   _mongocrypt_ctx_compact_t *cctx = (_mongocrypt_ctx_compact_t *) ctx;
   mongocrypt_status_t *status = ctx->status;

   BSON_APPEND_DOCUMENT_BEGIN (
      &result_bson, "compactionTokens", &result_compactionTokens);

   mc_EncryptedField_t *ptr;
   for (ptr = cctx->efc.fields; ptr != NULL; ptr = ptr->next) {
      /* Append ECOC token. */
      _mongocrypt_buffer_t key = {0};
      _mongocrypt_buffer_t tokenkey = {0};
      mc_CollectionsLevel1Token_t *cl1t = NULL;
      mc_ECOCToken_t *ecoct = NULL;
      bool ecoc_ok = false;

      if (!_mongocrypt_key_broker_decrypted_key_by_id (
             &ctx->kb, &ptr->keyId, &key)) {
         _mongocrypt_key_broker_status (&ctx->kb, ctx->status);
         _mongocrypt_ctx_fail (ctx);
         goto ecoc_fail;
      }
      /* The last 32 bytes of the user key are the token key. */
      if (!_mongocrypt_buffer_from_subrange (&tokenkey,
                                             &key,
                                             key.len - MONGOCRYPT_TOKEN_KEY_LEN,
                                             MONGOCRYPT_TOKEN_KEY_LEN)) {
         _mongocrypt_ctx_fail_w_msg (
            ctx, "unable to get TokenKey from Data Encryption Key");
         goto ecoc_fail;
      }
      cl1t =
         mc_CollectionsLevel1Token_new (ctx->crypt->crypto, &tokenkey, status);
      if (!cl1t) {
         _mongocrypt_ctx_fail (ctx);
         goto ecoc_fail;
      }

      ecoct = mc_ECOCToken_new (ctx->crypt->crypto, cl1t, status);
      if (!ecoct) {
         _mongocrypt_ctx_fail (ctx);
         goto ecoc_fail;
      }

      const _mongocrypt_buffer_t *ecoct_buf = mc_ECOCToken_get (ecoct);

      BSON_APPEND_BINARY (&result_compactionTokens,
                          ptr->path,
                          BSON_SUBTYPE_BINARY,
                          ecoct_buf->data,
                          ecoct_buf->len);

      ecoc_ok = true;
   ecoc_fail:
      mc_ECOCToken_destroy (ecoct);
      mc_CollectionsLevel1Token_destroy (cl1t);
      _mongocrypt_buffer_cleanup (&key);
      if (!ecoc_ok) {
         goto fail;
      }
   }


   bson_append_document_end (&result_bson, &result_compactionTokens);
   _mongocrypt_buffer_steal_from_bson (&cctx->result, &result_bson);
   _mongocrypt_buffer_to_binary (&cctx->result, out);
   ret = true;
   ctx->state = MONGOCRYPT_CTX_DONE;
fail:
   if (!ret) {
      bson_destroy (&result_bson);
   }
   return ret;
}

bool
mongocrypt_ctx_compact_init (mongocrypt_ctx_t *ctx,
                             mongocrypt_binary_t *encrypted_field_config)
{
   if (!ctx) {
      return false;
   }

   if (!encrypted_field_config) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "encrypted_field_config must not be null");
   }

   _mongocrypt_ctx_opts_spec_t opts_spec;
   memset (&opts_spec, 0, sizeof (opts_spec));

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   ctx->type = _MONGOCRYPT_TYPE_COMPACT;
   ctx->state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   ctx->vtable.cleanup = _cleanup;
   ctx->vtable.finalize = _finalize;

   _mongocrypt_ctx_compact_t *cctx = (_mongocrypt_ctx_compact_t *) ctx;

   /* Parse encypted_field_config. */
   {
      bson_t efc_bson;
      if (!_mongocrypt_binary_to_bson (encrypted_field_config, &efc_bson)) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "failed to initialize bson_t from encrypted_field_config");
      }
      if (!mc_EncryptedFieldConfig_parse (&cctx->efc, &efc_bson, ctx->status)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   }

   /* Request keys from encrypted_field_config. */
   {
      mc_EncryptedField_t *ptr;
      for (ptr = cctx->efc.fields; ptr != NULL; ptr = ptr->next) {
         if (!_mongocrypt_key_broker_request_id (&ctx->kb, &ptr->keyId)) {
            _mongocrypt_key_broker_status (&ctx->kb, ctx->status);
            return _mongocrypt_ctx_fail (ctx);
         }
      }
   }

   if (!_mongocrypt_key_broker_requests_done (&ctx->kb)) {
      _mongocrypt_key_broker_status (&ctx->kb, ctx->status);
      return _mongocrypt_ctx_fail (ctx);
   }

   return _mongocrypt_ctx_state_from_key_broker (ctx);
}
