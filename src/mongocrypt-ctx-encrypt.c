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
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-ctx-private.h"

/* Construct the list collections command to send. */
static bool
_mongo_op_collinfo (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *cmd;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   cmd = BCON_NEW ("name",
                   BCON_UTF8 (ectx->coll_name),
                   "options.validator.$jsonSchema",
                   "{",
                   "$exists",
                   BCON_BOOL (true),
                   "}");
   CRYPT_TRACEF (&ectx->parent.crypt->log, "constructed: %s\n", tmp_json (cmd));
   _mongocrypt_buffer_steal_from_bson (&ectx->list_collections_filter, cmd);
   out->data = ectx->list_collections_filter.data;
   out->len = ectx->list_collections_filter.len;
   return true;
}

static bool
_mongo_feed_collinfo (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   /* Parse out the schema. */
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (!bson_init_static (&as_bson, in->data, in->len)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }
   if (!bson_iter_init (&iter, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }
   if (bson_iter_find_descendant (
          &iter, "options.validator.$jsonSchema", &iter)) {
      _mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter);
   }
   /* TODO: check for validator siblings. */
   return true;
}


static bool
_mongo_done_collinfo (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (_mongocrypt_buffer_empty (&ectx->schema)) {
      ectx->parent.state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   } else {
      ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   }
   return true;
}


static bool
_mongo_op_markings (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   out->data = ectx->schema.data;
   out->len = ectx->schema.len;
   return true;
}


static bool
_collect_key_from_marking (void *ctx,
                           _mongocrypt_buffer_t *in,
                           mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_key_broker_t *kb;

   kb = (_mongocrypt_key_broker_t *) ctx;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      return false;
   }

   /* TODO: check if the key cache has the key. */
   /* TODO: CDRIVER-3057 support keyAltName. */
   if (marking.key_alt_name) {
      CLIENT_ERR ("keyAltName not supported yet");
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (kb, &marking.key_id)) {
      _mongocrypt_key_broker_status (kb, status);
      return false;
   }
   return true;
}


static bool
_mongo_feed_markings (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   /* Find keys. */
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (!_mongocrypt_binary_to_bson (in, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed BSON");
   }

   if (bson_iter_init_find (&iter, &as_bson, "schemaRequiresEncryption") &&
       !bson_iter_as_bool (&iter)) {
      /* TODO: update cache: this schema does not require encryption. */
      return true;
   }

   if (bson_iter_init_find (&iter, &as_bson, "hasEncryptedPlaceholders") &&
       !bson_iter_as_bool (&iter)) {
      return true;
   }

   if (!bson_iter_init_find (&iter, &as_bson, "result")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed marking, no 'result'");
   }

   _mongocrypt_buffer_copy_from_document_iter (&ectx->marked_cmd, &iter);

   bson_iter_recurse (&iter, &iter);
   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_marking,
                                             (void *) &ctx->kb,
                                             TRAVERSE_MATCH_MARKING,
                                             &iter,
                                             ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   return true;
}


static bool
_mongo_done_markings (mongocrypt_ctx_t *ctx)
{
   if (_mongocrypt_key_broker_empty (&ctx->kb)) {
      /* if there were no keys, i.e. no markings, no encryption is needed. */
      ctx->state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   } else {
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   }
   return true;
}


/* From BSON Binary subtype 6 specification:
struct fle_blob {
 uint8  fle_blob_subtype = (1 or 2);
 uint8  key_uuid[16];
 uint8  original_bson_type;
 uint8  ciphertext[ciphertext_length];
}
TODO CDRIVER-3001 this may not be the right home for this method.
*/
static void
_serialize_ciphertext (_mongocrypt_ciphertext_t *ciphertext,
                       _mongocrypt_buffer_t *out)
{
   uint32_t offset;

   BSON_ASSERT (ciphertext);
   BSON_ASSERT (out);
   BSON_ASSERT (ciphertext->key_id.len == 16);

   /* TODO CDRIVER-3001: relocate this logic? */
   _mongocrypt_buffer_init (out);
   offset = 0;
   out->len = 1 + ciphertext->key_id.len + 1 + ciphertext->data.len;
   out->data = bson_malloc0 (out->len);
   out->owned = true;

   out->data[offset] = ciphertext->blob_subtype;
   offset += 1;

   memcpy (out->data + offset, ciphertext->key_id.data, ciphertext->key_id.len);
   offset += ciphertext->key_id.len;

   out->data[offset] = ciphertext->original_bson_type;
   offset += 1;

   memcpy (out->data + offset, ciphertext->data.data, ciphertext->data.len);
   offset += ciphertext->data.len;
}


/* For tests to hook onto. */
void
_test_mongocrypt_serialize_ciphertext (_mongocrypt_ciphertext_t *ciphertext,
                                       _mongocrypt_buffer_t *out)
{
   _serialize_ciphertext (ciphertext, out);
}

static bool
_replace_marking_with_ciphertext (void *ctx,
                                  _mongocrypt_buffer_t *in,
                                  bson_value_t *out,
                                  mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ciphertext_t ciphertext = {{0}};
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   _mongocrypt_buffer_t plaintext = {0};
   _mongocrypt_key_broker_t *kb;
   bson_t wrapper = BSON_INITIALIZER;
   _mongocrypt_buffer_t key_material;
   bool ret = false;
   uint32_t bytes_written;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   kb = (_mongocrypt_key_broker_t *) ctx;


   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      goto fail;
   }

   if (marking.key_alt_name) {
      CLIENT_ERR ("TODO looking up key by keyAltName not yet supported");
      goto fail;
   }

   ciphertext.blob_subtype = marking.algorithm;
   ciphertext.original_bson_type = (uint8_t) bson_iter_type (&marking.v_iter);

   /* get the key for this marking. */
   if (!_mongocrypt_key_broker_decrypted_key_material_by_id (
          kb, &marking.key_id, &key_material)) {
      _mongocrypt_status_copy_to (kb->status, status);
      goto fail;
   }

   /* TODO: for simplicity, we wrap the thing we encrypt in a BSON document
    * with an empty key, i.e. { "": <thing to encrypt> }
    * CDRIVER-3021 will remove this. */
   bson_append_iter (&wrapper, "", 0, &marking.v_iter);
   plaintext.data = (uint8_t *) bson_get_data (&wrapper);
   plaintext.len = wrapper.len;

   ciphertext.data.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext.data.data = bson_malloc (ciphertext.data.len);
   ciphertext.data.owned = true;
   ret = _mongocrypt_do_encryption (&marking.iv,
                                    NULL,
                                    &key_material,
                                    &plaintext,
                                    &ciphertext.data,
                                    &bytes_written,
                                    status);
   if (!ret) {
      goto fail;
   }
   BSON_ASSERT (bytes_written == ciphertext.data.len);

   memcpy (&ciphertext.key_id, &marking.key_id, sizeof (_mongocrypt_buffer_t));
   _serialize_ciphertext (&ciphertext, &serialized_ciphertext);

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = 6;

   ret = true;

fail:
   _mongocrypt_buffer_cleanup (&ciphertext.data);
   bson_destroy (&wrapper);
   return ret;
}


static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t as_bson, converted;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   _mongocrypt_buffer_to_bson (&ectx->marked_cmd, &as_bson);
   bson_iter_init (&iter, &as_bson);
   bson_init (&converted);
   if (!_mongocrypt_transform_binary_in_bson (_replace_marking_with_ciphertext,
                                              &ctx->kb,
                                              TRAVERSE_MATCH_MARKING,
                                              &iter,
                                              &converted,
                                              ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }
   _mongocrypt_buffer_steal_from_bson (&ectx->encrypted_cmd, &converted);
   _mongocrypt_buffer_to_binary (&ectx->encrypted_cmd, out);
   ctx->state = MONGOCRYPT_CTX_DONE;
   return true;
}


static void
_cleanup (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   bson_free (ectx->ns);
   _mongocrypt_buffer_cleanup (&ectx->list_collections_filter);
   _mongocrypt_buffer_cleanup (&ectx->schema);
   _mongocrypt_buffer_cleanup (&ectx->original_cmd);
   _mongocrypt_buffer_cleanup (&ectx->marking_cmd);
   _mongocrypt_buffer_cleanup (&ectx->marked_cmd);
   _mongocrypt_buffer_cleanup (&ectx->encrypted_cmd);
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
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             uint32_t ns_len)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   if (!ns || NULL == strstr (ns, ".")) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "invalid ns. Must be <db>.<coll>");
   }

   if (ctx->state != MONGOCRYPT_CTX_ERROR) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "wrong state");
   }

   if (ctx->opts.aws_region || ctx->opts.aws_cmk) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "aws masterkey options must not be set");
   }

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->ns = bson_strdup (ns);
   ectx->coll_name = strstr (ectx->ns, ".") + 1;

   /* TODO: check if schema is cached. If we know encryption isn't needed. We
    * can avoid a needless copy. */
   ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_feed_collinfo = _mongo_feed_collinfo;
   ctx->vtable.mongo_done_collinfo = _mongo_done_collinfo;
   ctx->vtable.mongo_op_markings = _mongo_op_markings;
   ctx->vtable.mongo_feed_markings = _mongo_feed_markings;
   ctx->vtable.mongo_done_markings = _mongo_done_markings;
   ctx->vtable.next_kms_ctx = _next_kms_ctx;
   ctx->vtable.kms_done = _kms_done;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;
   return true;
}
