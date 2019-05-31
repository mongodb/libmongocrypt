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

#include "mongocrypt-crypto-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-traverse-util-private.h"

static bool
_replace_ciphertext_with_plaintext (void *ctx,
                                    _mongocrypt_buffer_t *in,
                                    bson_value_t *out,
                                    mongocrypt_status_t *status)
{
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t plaintext;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_buffer_t associated_data;
   uint32_t bytes_written;
   bool ret = false;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);

   _mongocrypt_buffer_init (&plaintext);
   _mongocrypt_buffer_init (&associated_data);
   _mongocrypt_buffer_init (&key_material);
   kb = (_mongocrypt_key_broker_t *) ctx;

   if (!_mongocrypt_ciphertext_parse_unowned (in, &ciphertext, status)) {
      goto fail;
   }

   /* look up the key */
   if (!_mongocrypt_key_broker_decrypted_key_by_id (
          kb, &ciphertext.key_id, &key_material)) {
      CLIENT_ERR ("key not found");
      goto fail;
   }

   plaintext.len = ciphertext.data.len;
   plaintext.data = bson_malloc0 (plaintext.len);
   plaintext.owned = true;

   if (!_mongocrypt_ciphertext_serialize_associated_data (&ciphertext,
                                                          &associated_data)) {
      CLIENT_ERR ("could not serialize associated data");
      goto fail;
   }

   if (!_mongocrypt_do_decryption (&associated_data,
                                   &key_material,
                                   &ciphertext.data,
                                   &plaintext,
                                   &bytes_written,
                                   status)) {
      goto fail;
   }

   plaintext.len = bytes_written;

   if (!_mongocrypt_buffer_to_bson_value (
          &plaintext, ciphertext.original_bson_type, out)) {
      CLIENT_ERR ("malformed encrypted bson");
      goto fail;
   }
   ret = true;

fail:
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&key_material);
   return ret;
}


static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t as_bson, final_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_decrypt_t *dctx;
   bool res;

   if (!ctx) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "null ctx");
   }

   if (!out) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "null out parameter");
   }

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;

   if (!dctx->explicit) {
      if (ctx->nothing_to_do) {
         _mongocrypt_buffer_to_binary (&dctx->original_doc, out);
         ctx->state = MONGOCRYPT_CTX_DONE;
         return true;
      }

      if (!_mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
      }

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

   if (!_mongocrypt_ciphertext_parse_unowned (in, &ciphertext, status)) {
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


bool
mongocrypt_ctx_explicit_decrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg)
{
   _mongocrypt_ctx_decrypt_t *dctx;
   bson_iter_t iter;
   bson_t as_bson;

   _mongocrypt_ctx_opts_spec_t opts_spec = {0};

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   if (!msg || !msg->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg");
   }

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   dctx->explicit = true;
   ctx->type = _MONGOCRYPT_TYPE_DECRYPT;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;


   /* We expect these to be round-tripped from explicit encrypt,
      so they must be wrapped like { "v" : "encrypted thing" } */
   _mongocrypt_buffer_copy_from_binary (&dctx->original_doc, msg);
   if (!_mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
   }

   if (!bson_iter_init_find (&iter, &as_bson, "v")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg, must contain 'v'");
   }

   if (!_mongocrypt_buffer_from_binary_iter (&dctx->unwrapped_doc, &iter)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "invalid msg, 'v' must contain a binary");
   }

   /* Parse out our one key id */
   if (!_collect_key_from_ciphertext (
          &ctx->kb, &dctx->unwrapped_doc, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   return _mongocrypt_ctx_state_from_key_broker (ctx);
}


bool
mongocrypt_ctx_decrypt_init (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *doc)
{
   _mongocrypt_ctx_decrypt_t *dctx;
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_opts_spec_t opts_spec = {0};

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   if (!doc || !doc->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid doc");
   }

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_DECRYPT;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   _mongocrypt_buffer_copy_from_binary (&dctx->original_doc, doc);
   /* get keys. */
   if (!_mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
   }

   bson_iter_init (&iter, &as_bson);
   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_ciphertext,
                                             &ctx->kb,
                                             TRAVERSE_MATCH_CIPHERTEXT,
                                             &iter,
                                             ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   return _mongocrypt_ctx_state_from_key_broker (ctx);
}
