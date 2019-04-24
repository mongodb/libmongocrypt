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

#include "mongocrypt-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-ctx-private.h"


/* From BSON Binary subtype 6 specification:
struct fle_blob {
 uint8  fle_blob_subtype = (1 or 2);
 uint8  key_uuid[16];
 uint8  original_bson_type;
 uint8  ciphertext[ciphertext_length];
}
*/
static bool
_parse_ciphertext_unowned (_mongocrypt_buffer_t *in,
                           _mongocrypt_ciphertext_t *ciphertext,
                           mongocrypt_status_t *status)
{
   uint32_t offset;

   BSON_ASSERT (in);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);

   offset = 0;

   /* At a minimum, a ciphertext must be 19 bytes:
    * fle_blob_subtype (1) +
    * key_uuid (16) +
    * original_bson_type (1) +
    * ciphertext (> 0)
    */
   if (in->len < 19) {
      CLIENT_ERR ("malformed ciphertext, too small");
      return false;
   }
   ciphertext->blob_subtype = in->data[0];
   offset += 1;
   /* TODO: merge new changes. */
   if (ciphertext->blob_subtype != 1 && ciphertext->blob_subtype != 2) {
      CLIENT_ERR ("malformed ciphertext, expected blob subtype of 1 or 2");
      return false;
   }

   /* TODO: after merging CDRIVER-3003, use _mongocrypt_buffer_init. */
   memset (&ciphertext->key_id, 0, sizeof (ciphertext->key_id));
   ciphertext->key_id.data = in->data + offset;
   ciphertext->key_id.len = 16;
   ciphertext->key_id.subtype = BSON_SUBTYPE_UUID;
   offset += 16;

   ciphertext->original_bson_type = in->data[offset];
   offset += 1;

   memset (&ciphertext->data, 0, sizeof (ciphertext->data));
   ciphertext->data.data = in->data + offset;
   ciphertext->data.len = in->len - offset;

   return true;
}


static bool
_replace_ciphertext_with_plaintext (void *ctx,
                                    _mongocrypt_buffer_t *in,
                                    bson_value_t *out,
                                    mongocrypt_status_t *status)
{
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t plaintext = {0};
   _mongocrypt_buffer_t key_material;
   bson_t wrapper;
   bson_iter_t iter;
   uint32_t bytes_written;
   bool ret = false;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);

   kb = (_mongocrypt_key_broker_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      goto fail;
   }

   /* look up the key */
   if (!_mongocrypt_key_broker_decrypted_key_material_by_id (
          kb, &ciphertext.key_id, &key_material)) {
      /* We allow partial decryption, so this is not an error. */
      /* TODO: either log here and pass a mongocrypt_ctx_t instead of a key
      broker
       * or log inside the key broker (and add a pointer to mongocrypt_ctx_t
      there)
       *
      _mongocrypt_log (&dctx->parent.crypt->log,
                       MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Missing key, skipping decryption for this ciphertext");
       */
      ret = true;
      goto fail;
   }

   plaintext.len = ciphertext.data.len;
   plaintext.data = bson_malloc0 (plaintext.len);
   plaintext.owned = true;

   if (!_mongocrypt_do_decryption (NULL,
                                   &key_material,
                                   &ciphertext.data,
                                   &plaintext,
                                   &bytes_written,
                                   status)) {
      goto fail;
   }

   plaintext.len = bytes_written;

   bson_init_static (&wrapper, plaintext.data, plaintext.len);
   bson_iter_init_find (&iter, &wrapper, "");
   bson_value_copy (bson_iter_value (&iter), out);
   ret = true;

fail:
   bson_free (plaintext.data);
   return ret;
}


static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t as_bson, final_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_decrypt_t *dctx;
   bool res;

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;

   if (!dctx->explicit) {
      _mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson);
      bson_iter_init (&iter, &as_bson);
      bson_init (&final_bson);
      res = _mongocrypt_transform_binary_in_bson (
         _replace_ciphertext_with_plaintext,
         &ctx->kb,
         TRAVERSE_MATCH_CIPHERTEXT,
         &iter,
         &final_bson,
         ctx->status);
      if (!res) {
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      /* For explicit decryption, we just have a single value */
      bson_value_t value;

      if (!_replace_ciphertext_with_plaintext (
             &ctx->kb, &dctx->unwrapped_doc, &value, ctx->status)) {
         return _mongocrypt_ctx_fail (ctx);
      }

      bson_init (&final_bson);
      bson_append_value (&final_bson, MONGOCRYPT_STR_AND_LEN ("v"), &value);
      bson_value_destroy (&value);
   }

   _mongocrypt_buffer_steal_from_bson (&dctx->decrypted_doc, &final_bson);
   out->data = dctx->decrypted_doc.data;
   out->len = dctx->decrypted_doc.len;
   ctx->state = MONGOCRYPT_CTX_DONE;
   return true;
}


static bool
_collect_key_from_ciphertext (void *ctx,
                              _mongocrypt_buffer_t *in,
                              mongocrypt_status_t *status)
{
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_key_broker_t *kb;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);

   kb = (_mongocrypt_key_broker_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (kb, &ciphertext.key_id)) {
      return _mongocrypt_key_broker_status (kb, status);
   }

   return true;
}


static void
_cleanup (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_decrypt_t *dctx;

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   _mongocrypt_buffer_cleanup (&dctx->original_doc);
   _mongocrypt_buffer_cleanup (&dctx->decrypted_doc);
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
mongocrypt_ctx_explicit_decrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg)
{
   _mongocrypt_ctx_decrypt_t *dctx;
   bson_iter_t iter;
   bson_t as_bson;

   if (!msg) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg");
   }

   if (ctx->state != MONGOCRYPT_CTX_ERROR) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }

   if (ctx->opts.masterkey_aws_region || ctx->opts.masterkey_aws_cmk) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "aws masterkey options must not be set");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.key_id)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "key_id must not be set for decryption");
   }

   if (ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "algorithm must not be set for decryption");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.iv)) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "iv must not be set for decryption");
   }

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   dctx->explicit = true;
   ctx->type = _MONGOCRYPT_TYPE_DECRYPT;
   ctx->vtable.next_kms_ctx = _next_kms_ctx;
   ctx->vtable.kms_done = _kms_done;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   /* We expect these to be round-tripped from explicit encrypt,
      so they must be wrapped like { "v" : "encrypted thing" } */
   _mongocrypt_buffer_copy_from_binary (&dctx->original_doc, msg);
   _mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson);
   if (!bson_iter_init_find (&iter, &as_bson, "v")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg, must contain 'v'");
   }

   _mongocrypt_buffer_from_iter (&dctx->unwrapped_doc, &iter);

   /* Parse out our one key id */
   if (!_collect_key_from_ciphertext (
          &ctx->kb, &dctx->unwrapped_doc, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (_mongocrypt_key_broker_has (&ctx->kb, KEY_EMPTY)) {
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   } else {
      ctx->state = MONGOCRYPT_CTX_READY;
   }

   return true;
}


bool
mongocrypt_ctx_decrypt_init (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *doc)
{
   _mongocrypt_ctx_decrypt_t *dctx;
   bson_t as_bson;
   bson_iter_t iter;

   if (!_mongocrypt_ctx_init (ctx)) {
      return false;
   }

   if (!doc) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid doc");
   }

   if (ctx->state != MONGOCRYPT_CTX_ERROR) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }

   if (ctx->opts.masterkey_aws_region || ctx->opts.masterkey_aws_cmk) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "aws masterkey options must not be set");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.key_id)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "key_id must not be set for decryption");
   }

   if (ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "algorithm must not be set for decryption");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.iv)) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "iv must not be set for decryption");
   }

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_DECRYPT;
   ctx->vtable.next_kms_ctx = _next_kms_ctx;
   ctx->vtable.kms_done = _kms_done;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   _mongocrypt_buffer_copy_from_binary (&dctx->original_doc, doc);
   /* get keys. */
   _mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson);
   bson_iter_init (&iter, &as_bson);
   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_ciphertext,
                                             &ctx->kb,
                                             TRAVERSE_MATCH_CIPHERTEXT,
                                             &iter,
                                             ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (_mongocrypt_key_broker_empty (&ctx->kb)) {
      ctx->state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   } else if (_mongocrypt_key_broker_has (&ctx->kb, KEY_EMPTY)) {
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   } else {
      /* All keys were cached. */
      ctx->state = MONGOCRYPT_CTX_READY;
   }

   return true;
}
