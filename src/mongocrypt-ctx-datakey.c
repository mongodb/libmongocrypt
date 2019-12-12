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
   _mongocrypt_buffer_cleanup (&dkctx->encrypted_key_material);
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

   /* Store the result. */
   if (!_mongocrypt_kms_ctx_result (&dkctx->kms,
                                    &dkctx->encrypted_key_material)) {
      BSON_ASSERT (!mongocrypt_kms_ctx_status (&dkctx->kms, ctx->status));
      return _mongocrypt_ctx_fail (ctx);
   }

   /* The encrypted key material must be at least as large as the plaintext. */
   if (dkctx->encrypted_key_material.len < MONGOCRYPT_KEY_LEN) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "key material not expected length");
   }

   ctx->state = MONGOCRYPT_CTX_READY;
   return true;
}


/* Append a UUID _id. Confer with libmongoc's `_mongoc_server_session_uuid`. */
static bool
_append_id (mongocrypt_t *crypt, bson_t *bson, mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t uuid;
#define UUID_LEN 16

   _mongocrypt_buffer_init (&uuid);
   uuid.data = bson_malloc (UUID_LEN);
   BSON_ASSERT (uuid.data);

   uuid.len = UUID_LEN;
   uuid.subtype = BSON_SUBTYPE_UUID;
   uuid.owned = true;

   if (!_mongocrypt_random (crypt->crypto, &uuid, UUID_LEN, status)) {
      _mongocrypt_buffer_cleanup (&uuid);
      return false;
   }

   uuid.data[6] = (uint8_t) (0x40 | (uuid.data[6] & 0xf));
   uuid.data[8] = (uint8_t) (0x80 | (uuid.data[8] & 0x3f));
   if (!_mongocrypt_buffer_append (&uuid, bson, "_id", 3)) {
      _mongocrypt_buffer_cleanup (&uuid);
      return false;
   }

   _mongocrypt_buffer_cleanup (&uuid);

   return true;
}


static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_datakey_t *dkctx;
   bson_t key_doc, child;
   struct timeval tp;

#define BSON_CHECK(_stmt)                                                      \
   if (!(_stmt)) {                                                             \
      bson_destroy (&key_doc);                                                 \
      return _mongocrypt_ctx_fail_w_msg (ctx, "unable to construct BSON doc"); \
   }

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;

   bson_init (&key_doc);
   if (!_append_id (ctx->crypt, &key_doc, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (ctx->opts.key_alt_names) {
      _mongocrypt_key_alt_name_t *alt_name = ctx->opts.key_alt_names;
      int i;

      bson_append_array_begin (&key_doc, "keyAltNames", -1, &child);
      for (i = 0; alt_name; i++) {
         char *key = bson_strdup_printf ("%d", i);
         bson_append_value (&child, key, -1, &alt_name->value);
         bson_free (key);
         alt_name = alt_name->next;
      }
      bson_append_array_end (&key_doc, &child);
   }
   if (!_mongocrypt_buffer_append (&dkctx->encrypted_key_material,
                                   &key_doc,
                                   MONGOCRYPT_STR_AND_LEN ("keyMaterial"))) {
      bson_destroy (&key_doc);
      return _mongocrypt_ctx_fail_w_msg (ctx, "could not append keyMaterial");
   }
   bson_gettimeofday (&tp);
   BSON_CHECK (bson_append_timeval (
      &key_doc, MONGOCRYPT_STR_AND_LEN ("creationDate"), &tp));
   BSON_CHECK (bson_append_timeval (
      &key_doc, MONGOCRYPT_STR_AND_LEN ("updateDate"), &tp));
   BSON_CHECK (bson_append_int32 (
      &key_doc, MONGOCRYPT_STR_AND_LEN ("status"), 0)); /* 0 = enabled. */
   BSON_CHECK (bson_append_document_begin (
      &key_doc, MONGOCRYPT_STR_AND_LEN ("masterKey"), &child));

   if (ctx->opts.masterkey_kms_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      BSON_CHECK (bson_append_utf8 (&child,
                                    MONGOCRYPT_STR_AND_LEN ("provider"),
                                    MONGOCRYPT_STR_AND_LEN ("aws")));
      BSON_CHECK (bson_append_utf8 (&child,
                                    MONGOCRYPT_STR_AND_LEN ("region"),
                                    ctx->opts.masterkey_aws_region,
                                    ctx->opts.masterkey_aws_region_len));
      BSON_CHECK (bson_append_utf8 (&child,
                                    MONGOCRYPT_STR_AND_LEN ("key"),
                                    ctx->opts.masterkey_aws_cmk,
                                    ctx->opts.masterkey_aws_cmk_len));
      if (ctx->opts.masterkey_aws_endpoint) {
         BSON_CHECK (bson_append_utf8 (&child,
                                       MONGOCRYPT_STR_AND_LEN ("endpoint"),
                                       ctx->opts.masterkey_aws_endpoint,
                                       ctx->opts.masterkey_aws_endpoint_len))
      }
   }

   if (ctx->opts.masterkey_kms_provider == MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      BSON_CHECK (bson_append_utf8 (&child,
                                    MONGOCRYPT_STR_AND_LEN ("provider"),
                                    MONGOCRYPT_STR_AND_LEN ("local")));
   }
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
   _mongocrypt_ctx_opts_spec_t opts_spec;
   bool ret;

   if (!ctx) {
      return false;
   }
   ret = false;
   memset (&opts_spec, 0, sizeof (opts_spec));
   opts_spec.masterkey = OPT_REQUIRED;
   opts_spec.key_alt_names = OPT_OPTIONAL;
   opts_spec.endpoint = OPT_OPTIONAL;

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   dkctx = (_mongocrypt_ctx_datakey_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_CREATE_DATA_KEY;
   ctx->vtable.mongo_op_keys = NULL;
   ctx->vtable.mongo_feed_keys = NULL;
   ctx->vtable.mongo_done_keys = NULL;
   ctx->vtable.next_kms_ctx = _next_kms_ctx;
   ctx->vtable.kms_done = _kms_done;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   _mongocrypt_buffer_init (&plaintext_key_material);
   plaintext_key_material.data = bson_malloc (MONGOCRYPT_KEY_LEN);
   BSON_ASSERT (plaintext_key_material.data);

   plaintext_key_material.len = MONGOCRYPT_KEY_LEN;
   plaintext_key_material.owned = true;
   if (!_mongocrypt_random (ctx->crypt->crypto,
                            &plaintext_key_material,
                            MONGOCRYPT_KEY_LEN,
                            ctx->status)) {
      _mongocrypt_ctx_fail (ctx);
      goto done;
   }

   if (ctx->opts.masterkey_kms_provider == MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      bool crypt_ret;
      uint32_t bytes_written;
      _mongocrypt_buffer_t iv;

      if (ctx->opts.masterkey_aws_endpoint) {
         _mongocrypt_ctx_fail_w_msg (
            ctx, "endpoint not supported for local masterkey");
         goto done;
      }

      /* For a local KMS provider, the customer master key is supplied by the
       * user in mongocrypt_setopt_kms_provider_local. We use it to
       * encrypt/decrypt data keys directly. */
      dkctx->encrypted_key_material.len =
         _mongocrypt_calculate_ciphertext_len (plaintext_key_material.len);
      dkctx->encrypted_key_material.data =
         bson_malloc (dkctx->encrypted_key_material.len);
      dkctx->encrypted_key_material.owned = true;
      BSON_ASSERT (dkctx->encrypted_key_material.data);

      /* use a random IV. */
      _mongocrypt_buffer_init (&iv);
      iv.data = bson_malloc0 (MONGOCRYPT_IV_LEN);
      BSON_ASSERT (iv.data);

      iv.len = MONGOCRYPT_IV_LEN;
      iv.owned = true;
      if (!_mongocrypt_random (
             ctx->crypt->crypto, &iv, MONGOCRYPT_IV_LEN, ctx->status)) {
         _mongocrypt_ctx_fail (ctx);
         goto done;
      }

      crypt_ret = _mongocrypt_do_encryption (ctx->crypt->crypto,
                                             &iv,
                                             NULL /* associated data. */,
                                             &ctx->crypt->opts.kms_local_key,
                                             &plaintext_key_material,
                                             &dkctx->encrypted_key_material,
                                             &bytes_written,
                                             ctx->status);
      _mongocrypt_buffer_cleanup (&iv);
      if (!crypt_ret) {
         _mongocrypt_ctx_fail (ctx);
         goto done;
      }
      ctx->state = MONGOCRYPT_CTX_READY;
   }

   if (ctx->opts.masterkey_kms_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      /* For AWS provider, AWS credentials are supplied in
       * mongocrypt_setopt_kms_provider_aws. Data keys are encrypted with an
       * "encrypt" HTTP message to KMS. */
      if (!_mongocrypt_kms_ctx_init_aws_encrypt (&dkctx->kms,
                                                 &ctx->crypt->opts,
                                                 &ctx->opts,
                                                 &plaintext_key_material,
                                                 &ctx->crypt->log,
                                                 ctx->crypt->crypto)) {
         mongocrypt_kms_ctx_status (&dkctx->kms, ctx->status);
         _mongocrypt_ctx_fail (ctx);
         goto done;
      }

      ctx->state = MONGOCRYPT_CTX_NEED_KMS;
   }

   ret = true;
done:
   _mongocrypt_buffer_cleanup (&plaintext_key_material);
   return ret;
}
