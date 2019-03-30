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

#include "mongocrypt.h"
#include "mongocrypt-private.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-crypto-private.h"

static void
_cleanup (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_datakey_t *dkctx;

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;
   _mongocrypt_buffer_cleanup (&dkctx->key_doc);
   _mongocrypt_kms_ctx_cleanup (&dkctx->kms);
}


static mongocrypt_kms_ctx_t *
_next_kms_ctx (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_datakey_t *dkctx;

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;
   if (dkctx->kms_returned) {
      return NULL;
   }
   dkctx->kms_returned = true;
   return &dkctx->kms;
}


static bool
_kms_done (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_datakey_t *dkctx;

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;
   if (!mongocrypt_kms_ctx_status (&dkctx->kms, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (mongocrypt_kms_ctx_bytes_needed (&dkctx->kms) != 0) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "KMS response unfinished");
   }

   ctx->state = MONGOCRYPT_CTX_READY;
   return true;
}


/* Append a UUID _id. Confer with libmongoc's `_mongoc_server_session_uuid`. */
static bool
_append_id (bson_t *bson, mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t uuid;
#define UUID_LEN 16

   _mongocrypt_buffer_init (&uuid);
   uuid.data = bson_malloc (UUID_LEN);
   uuid.len = UUID_LEN;
   uuid.subtype = BSON_SUBTYPE_UUID;
   uuid.owned = true;

   if (!_crypto_random (&uuid, status, UUID_LEN)) {
      return false;
   }

   uuid.data[6] = (uint8_t) (0x40 | (uuid.data[6] & 0xf));
   uuid.data[8] = (uint8_t) (0x80 | (uuid.data[8] & 0x3f));
   _mongocrypt_buffer_append (&uuid, bson, "_id", 3);
   _mongocrypt_buffer_cleanup (&uuid);
   return true;
}


static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_datakey_t *dkctx;
   _mongocrypt_buffer_t key_material;
   bson_t key_doc, child;
   int64_t current_time_ms;

#define BSON_CHECK(_stmt)                                                      \
   if (!(_stmt)) {                                                             \
      bson_destroy (&key_doc);                                                 \
      return _mongocrypt_ctx_fail_w_msg (ctx, "unable to construct BSON doc"); \
   }

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;
   if (!mongocrypt_kms_ctx_status (&dkctx->kms, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (!_mongocrypt_kms_ctx_result (&dkctx->kms, &key_material)) {
      BSON_ASSERT (!mongocrypt_kms_ctx_status (&dkctx->kms, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }

   /* The encrypted key material must be at least as large as the plaintext. */
   if (key_material.len < MONGOCRYPT_KEYMATERIAL_LEN) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "key material not expected length");
   }

   bson_init (&key_doc);
   if (!_append_id (&key_doc, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }
   /* TODO: CDRIVER-3057 support key alt names. Do not add an empty array if there
      are no keyAltNames since we do not want to prohibit a unique index. */
   _mongocrypt_buffer_append (&key_material, &key_doc, MONGOCRYPT_STR_AND_LEN("keyMaterial"));
   current_time_ms = bson_get_monotonic_time () * 1000;
   BSON_CHECK (
      bson_append_date_time (&key_doc, MONGOCRYPT_STR_AND_LEN("creationDate"), current_time_ms));
   BSON_CHECK (
      bson_append_date_time (&key_doc, MONGOCRYPT_STR_AND_LEN("updateDate"), current_time_ms));
   BSON_CHECK (bson_append_int32 (&key_doc, MONGOCRYPT_STR_AND_LEN("status"), 0)); /* 0 = enabled. */
   BSON_CHECK (bson_append_document_begin (&key_doc, MONGOCRYPT_STR_AND_LEN("masterKey"), &child));
   /* TODO: CDRIVER-3050 support multiple providers, don't assume AWS. */
   BSON_CHECK (bson_append_utf8 (&child, MONGOCRYPT_STR_AND_LEN("provider"), MONGOCRYPT_STR_AND_LEN("aws")));
   BSON_CHECK (bson_append_utf8 (
      &child, MONGOCRYPT_STR_AND_LEN("region"), ctx->opts.aws_region, ctx->opts.aws_region_len));
   BSON_CHECK (bson_append_utf8 (
      &child, MONGOCRYPT_STR_AND_LEN("key"), ctx->opts.aws_cmk, ctx->opts.aws_cmk_len));
   BSON_CHECK (bson_append_document_end (&key_doc, &child));
   _mongocrypt_buffer_steal_from_bson (&dkctx->key_doc, &key_doc);
   _mongocrypt_buffer_to_binary (&dkctx->key_doc, out);
   ctx->state = MONGOCRYPT_CTX_DONE;
   return true;
}


bool
mongocrypt_ctx_datakey_init (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_datakey_t *dkctx;
   _mongocrypt_buffer_t plaintext_key_material;

   if (ctx->state != MONGOCRYPT_CTX_ERROR) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }

   if (!ctx->opts.aws_region || !ctx->opts.aws_cmk) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "aws masterkey options are required");
   }

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_CREATE_DATA_KEY;
   ctx->vtable.next_kms_ctx = _next_kms_ctx;
   ctx->vtable.kms_done = _kms_done;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   _mongocrypt_buffer_init (&plaintext_key_material);
   plaintext_key_material.data = bson_malloc (MONGOCRYPT_KEYMATERIAL_LEN);
   plaintext_key_material.len = MONGOCRYPT_KEYMATERIAL_LEN;
   plaintext_key_material.owned = true;
   if (!_crypto_random (
          &plaintext_key_material, ctx->status, MONGOCRYPT_KEYMATERIAL_LEN)) {
      _mongocrypt_buffer_cleanup (&plaintext_key_material);
      return _mongocrypt_ctx_fail (ctx);
   }

   /* create the KMS message. */
   if (!_mongocrypt_kms_ctx_init_encrypt (&dkctx->kms,
                                          &ctx->crypt->opts,
                                          &ctx->opts,
                                          &plaintext_key_material,
                                          NULL)) {
      mongocrypt_kms_ctx_status (&dkctx->kms, ctx->status);
      return _mongocrypt_ctx_fail (ctx);
   }
   ctx->state = MONGOCRYPT_CTX_NEED_KMS;
   _mongocrypt_buffer_cleanup (&plaintext_key_material);
   return true;
}