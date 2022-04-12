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

#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-marking-private.h"
#include "mongocrypt-traverse-util-private.h"

static bool
_fle2_append_encryptionInformation (bson_t *dst,
                                    const char *ns,
                                    bson_t *encryptedFieldConfig,
                                    mongocrypt_status_t *status)
{
   bson_t encryption_information_bson;
   bson_t schema_bson;

   if (!BSON_APPEND_DOCUMENT_BEGIN (
          dst, "encryptionInformation", &encryption_information_bson)) {
      CLIENT_ERR ("unable to begin appending 'encryptionInformation'");
      return false;
   }
   if (!BSON_APPEND_INT32 (&encryption_information_bson, "type", 1)) {
      CLIENT_ERR ("unable to append type to 'encryptionInformation'");
      return false;
   }
   if (!BSON_APPEND_DOCUMENT_BEGIN (
          &encryption_information_bson, "schema", &schema_bson)) {
      CLIENT_ERR (
         "unable to begin appending 'schema' to 'encryptionInformation'");
      return false;
   }
   if (!BSON_APPEND_DOCUMENT (&schema_bson, ns, encryptedFieldConfig)) {
      CLIENT_ERR ("unable to append 'encryptedFieldConfig' to "
                  "'encryptionInformation'.'schema'");
      return false;
   }
   if (!bson_append_document_end (&encryption_information_bson, &schema_bson)) {
      CLIENT_ERR (
         "unable to end appending 'schema' to 'encryptionInformation'");
      return false;
   }
   if (!bson_append_document_end (dst, &encryption_information_bson)) {
      CLIENT_ERR ("unable to end appending 'encryptionInformation'");
      return false;
   }
   return true;
}

/* Construct the list collections command to send. */
static bool
_mongo_op_collinfo (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *cmd;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   cmd = BCON_NEW ("name", BCON_UTF8 (ectx->coll_name));
   CRYPT_TRACEF (&ectx->parent.crypt->log, "constructed: %s\n", tmp_json (cmd));
   _mongocrypt_buffer_steal_from_bson (&ectx->list_collections_filter, cmd);
   out->data = ectx->list_collections_filter.data;
   out->len = ectx->list_collections_filter.len;
   return true;
}

static bool
_set_schema_from_collinfo (mongocrypt_ctx_t *ctx, bson_t *collinfo)
{
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;
   bool found_jsonschema = false;

   /* Parse out the schema. */
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   /* Disallow views. */
   if (bson_iter_init_find (&iter, collinfo, "type") &&
       BSON_ITER_HOLDS_UTF8 (&iter) && bson_iter_utf8 (&iter, NULL) &&
       0 == strcmp ("view", bson_iter_utf8 (&iter, NULL))) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot auto encrypt a view");
   }

   if (!bson_iter_init (&iter, collinfo)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }

   if (bson_iter_find_descendant (&iter, "options.encryptedFields", &iter)) {
      if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "options.encryptedFields is not a BSON document");
      }
      if (!_mongocrypt_buffer_copy_from_document_iter (
             &ectx->encrypted_field_config, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "unable to copy options.encryptedFields");
      }
   }

   BSON_ASSERT (bson_iter_init (&iter, collinfo));

   if (bson_iter_find_descendant (&iter, "options.validator", &iter) &&
       BSON_ITER_HOLDS_DOCUMENT (&iter)) {
      if (!bson_iter_recurse (&iter, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
      }
      while (bson_iter_next (&iter)) {
         const char *key;

         key = bson_iter_key (&iter);
         BSON_ASSERT (key);
         if (0 == strcmp ("$jsonSchema", key)) {
            if (found_jsonschema) {
               return _mongocrypt_ctx_fail_w_msg (
                  ctx, "duplicate $jsonSchema fields found");
            }
            if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->schema,
                                                             &iter)) {
               return _mongocrypt_ctx_fail_w_msg (ctx, "malformed $jsonSchema");
            }
            found_jsonschema = true;
         } else {
            ectx->collinfo_has_siblings = true;
         }
      }
   }

   if (!found_jsonschema) {
      bson_t empty = BSON_INITIALIZER;

      _mongocrypt_buffer_steal_from_bson (&ectx->schema, &empty);
   }


   return true;
}

static bool
_mongo_feed_collinfo (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   bson_t as_bson;

   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (!bson_init_static (&as_bson, in->data, in->len)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }

   /* Cache the received collinfo. */
   if (!_mongocrypt_cache_add_copy (
          &ctx->crypt->cache_collinfo, ectx->ns, &as_bson, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (!_set_schema_from_collinfo (ctx, &as_bson)) {
      return false;
   }

   return true;
}

static bool
_try_run_csfle_marking (mongocrypt_ctx_t *ctx);

static bool
_mongo_done_collinfo (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (_mongocrypt_buffer_empty (&ectx->schema)) {
      bson_t empty_collinfo = BSON_INITIALIZER;

      /* If no collinfo was fed, cache an empty collinfo. */
      if (!_mongocrypt_cache_add_copy (&ctx->crypt->cache_collinfo,
                                       ectx->ns,
                                       &empty_collinfo,
                                       ctx->status)) {
         bson_destroy (&empty_collinfo);
         return _mongocrypt_ctx_fail (ctx);
      }
      bson_destroy (&empty_collinfo);
   }

   ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   return _try_run_csfle_marking (ctx);
}


static bool
_fle2_mongo_op_markings (mongocrypt_ctx_t *ctx, bson_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t cmd_bson = BSON_INITIALIZER,
          encrypted_field_config_bson = BSON_INITIALIZER;
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   BSON_ASSERT (ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   BSON_ASSERT (!_mongocrypt_buffer_empty (&ectx->encrypted_field_config));

   if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &cmd_bson)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "unable to convert original_cmd to BSON");
   }
   bson_copy_to (&cmd_bson, out);

   if (!_mongocrypt_buffer_to_bson (&ectx->encrypted_field_config,
                                    &encrypted_field_config_bson)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "unable to convert encrypted_field_config to BSON");
   }

   if (!_fle2_append_encryptionInformation (
          out, ectx->ns, &encrypted_field_config_bson, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   return true;
}


/**
 * @brief Create the server-side command that contains information for
 * generating encryption markings via query analysis.
 *
 * @param ctx The encryption context.
 * @param out The destination of the generate BSON document
 * @return true On success
 * @return false Otherwise. Sets a failing status message in this case.
 */
static bool
_create_markings_cmd_bson (mongocrypt_ctx_t *ctx, bson_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (!_mongocrypt_buffer_empty (&ectx->encrypted_field_config)) {
      // Defer to FLE2 to generate the markings command
      return _fle2_mongo_op_markings (ctx, out);
   }

   // For FLE1:
   // Get the original command document
   bson_t bson_view = BSON_INITIALIZER;
   if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &bson_view)) {
      _mongocrypt_ctx_fail_w_msg (ctx, "invalid BSON cmd");
      return false;
   }
   // Copy the command to the output
   bson_copy_to (&bson_view, out);

   if (!_mongocrypt_buffer_empty (&ectx->schema)) {
      // We have a schema buffer. View it as BSON:
      if (!_mongocrypt_buffer_to_bson (&ectx->schema, &bson_view)) {
         _mongocrypt_ctx_fail_w_msg (ctx, "invalid BSON schema");
         return false;
      }
      // Append the jsonSchema to the output command
      BSON_APPEND_DOCUMENT (out, "jsonSchema", &bson_view);
   } else {
      bson_t empty = BSON_INITIALIZER;
      BSON_APPEND_DOCUMENT (out, "jsonSchema", &empty);
   }

   // if a local schema was not set, set isRemoteSchema=true
   BSON_APPEND_BOOL (out, "isRemoteSchema", !ectx->used_local_schema);
   return true;
}


static bool
_mongo_op_markings (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (_mongocrypt_buffer_empty (&ectx->mongocryptd_cmd)) {
      // We need to generate the command document
      bson_t cmd_bson = BSON_INITIALIZER;
      if (!_create_markings_cmd_bson (ctx, &cmd_bson)) {
         // Failed
         bson_destroy (&cmd_bson);
         return false;
      }
      // Store the generated command:
      _mongocrypt_buffer_steal_from_bson (&ectx->mongocryptd_cmd, &cmd_bson);
   }

   // If we reach here, we have a valid mongocrypt_cmd
   out->data = ectx->mongocryptd_cmd.data;
   out->len = ectx->mongocryptd_cmd.len;
   return true;
}


static bool
_collect_key_from_marking (void *ctx,
                           _mongocrypt_buffer_t *in,
                           mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking;
   _mongocrypt_key_broker_t *kb;
   bool res;

   kb = (_mongocrypt_key_broker_t *) ctx;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      _mongocrypt_marking_cleanup (&marking);
      return false;
   }

   if (marking.type == MONGOCRYPT_MARKING_FLE1_BY_ID) {
      res = _mongocrypt_key_broker_request_id (kb, &marking.key_id);
   } else if (marking.type == MONGOCRYPT_MARKING_FLE1_BY_ALTNAME) {
      res = _mongocrypt_key_broker_request_name (kb, &marking.key_alt_name);
   } else {
      BSON_ASSERT (marking.type == MONGOCRYPT_MARKING_FLE2_ENCRYPTION);
      res =
         _mongocrypt_key_broker_request_id (kb, &marking.fle2.index_key_id) &&
         _mongocrypt_key_broker_request_id (kb, &marking.fle2.user_key_id);
   }

   if (!res) {
      _mongocrypt_key_broker_status (kb, status);
      _mongocrypt_marking_cleanup (&marking);
      return false;
   }

   _mongocrypt_marking_cleanup (&marking);

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

      /* If using a local schema, warn if there are no encrypted fields. */
      if (ectx->used_local_schema) {
         _mongocrypt_log (
            &ctx->crypt->log,
            MONGOCRYPT_LOG_LEVEL_WARNING,
            "local schema used but does not have encryption specifiers");
      }
      return true;
   } else {
      /* if the schema requires encryption, but has sibling validators, error.
       */
      if (ectx->collinfo_has_siblings) {
         return _mongocrypt_ctx_fail_w_msg (ctx,
                                            "schema requires encryption, "
                                            "but collection JSON schema "
                                            "validator has siblings");
      }
   }

   if (bson_iter_init_find (&iter, &as_bson, "hasEncryptedPlaceholders") &&
       !bson_iter_as_bool (&iter)) {
      return true;
   }

   if (!bson_iter_init_find (&iter, &as_bson, "result")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed marking, no 'result'");
   }

   if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->marked_cmd, &iter)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "malformed marking, 'result' must be a document");
   }

   if (!bson_iter_recurse (&iter, &iter)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "malformed marking, could not recurse into 'result'");
   }
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
   (void) _mongocrypt_key_broker_requests_done (&ctx->kb);
   return _mongocrypt_ctx_state_from_key_broker (ctx);
}


/**
 * @brief Attempt to generate csfle markings using a csfle dynamic library.
 *
 * @param ctx A context which has state NEED_MONGO_MARKINGS
 * @return true On success
 * @return false On error.
 *
 * This should be called only when we are ready for markings in the command
 * document. This function will only do anything if the csfle dynamic library
 * is loaded, otherwise it returns success immediately and leaves the state
 * as NEED_MONGO_MARKINGS.
 *
 * If csfle is loaded, this function will request the csfle library generate a
 * marked command document based on the caller's schema. If successful, the
 * state will be changed via @ref _mongo_done_markings().
 *
 * The purpose of this function is to short-circuit the phase of encryption
 * wherein we would normally return to the driver and give them the opportunity
 * to generate the markings by passing a special command to a mongocryptd daemon
 * process. Instead, we'll do it ourselves here, if possible.
 */
static bool
_try_run_csfle_marking (mongocrypt_ctx_t *ctx)
{
   BSON_ASSERT (
      ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS &&
      "_try_run_csfle_marking() should only be called when mongocrypt is "
      "ready for markings");

   _mongocrypt_ctx_encrypt_t *ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   // We have a valid schema and just need to mark the fields for encryption
   if (!ctx->crypt->csfle.okay) {
      // We don't have a csfle library to use to obtain the markings. It's up to
      // caller to resolve them.
      return true;
   }

   _mcr_csfle_v1_vtable csfle = ctx->crypt->csfle;
   mongo_csfle_v1_lib *csfle_lib = ctx->crypt->csfle_lib;
   BSON_ASSERT (csfle_lib);
   bool okay = false;

#define CHECK_CSFLE_ERROR(Func, FailLabel)                             \
   if (1) {                                                            \
      if (csfle.status_get_error (status)) {                           \
         _mongocrypt_set_error (ctx->status,                           \
                                MONGOCRYPT_STATUS_ERROR_CSFLE,         \
                                MONGOCRYPT_GENERIC_ERROR_CODE,         \
                                "csfle " #Func                         \
                                " failed: %s [Error %d, code %d]",     \
                                csfle.status_get_explanation (status), \
                                csfle.status_get_error (status),       \
                                csfle.status_get_code (status));       \
         _mongocrypt_ctx_fail (ctx);                                   \
         goto FailLabel;                                               \
      }                                                                \
   } else                                                              \
      ((void) 0)

   mongo_csfle_v1_status *status = csfle.status_create ();
   BSON_ASSERT (status);

   // Obtain the command for markings
   bson_t cmd = BSON_INITIALIZER;
   if (!_create_markings_cmd_bson (ctx, &cmd)) {
      goto fail_create_cmd;
   }
   BSON_APPEND_UTF8 (&cmd, "$db", "csfle");

   mongo_csfle_v1_query_analyzer *qa =
      csfle.query_analyzer_create (csfle_lib, status);
   CHECK_CSFLE_ERROR ("query_analyzer_create", fail_qa_create);

   uint32_t marked_bson_len = 0;
   uint8_t *marked_bson = csfle.analyze_query (qa,
                                               bson_get_data (&cmd),
                                               ectx->ns,
                                               (uint32_t) strlen (ectx->ns),
                                               &marked_bson_len,
                                               status);
   CHECK_CSFLE_ERROR ("analyze_query", analyze_failed);

   // Copy out the marked document.
   mongocrypt_binary_t *marked =
      mongocrypt_binary_new_from_data (marked_bson, marked_bson_len);
   if (!_mongo_feed_markings (ctx, marked)) {
      _mongocrypt_ctx_fail_w_msg (
         ctx, "Consuming the generated csfle markings failed");
      goto feed_failed;
   }

   okay = _mongo_done_markings (ctx);
   if (!okay) {
      _mongocrypt_ctx_fail_w_msg (
         ctx, "Finalizing the generated csfle markings failed");
   }

feed_failed:
   mongocrypt_binary_destroy (marked);
   csfle.bson_free (marked_bson);
analyze_failed:
   csfle.query_analyzer_destroy (qa);
fail_qa_create:
fail_create_cmd:
   bson_destroy (&cmd);
   if (csfle.status_get_error (status)) {
      _mongocrypt_log (
         &ctx->crypt->log,
         MONGOCRYPT_LOG_LEVEL_WARNING,
         "Error while shutting down csfle library: %s [Error %d, code %d]",
         csfle.status_get_explanation (status),
         csfle.status_get_error (status),
         csfle.status_get_code (status));
   }
   csfle.status_destroy (status);
   return okay;
}


static bool
_marking_to_bson_value (void *ctx,
                        _mongocrypt_marking_t *marking,
                        bson_value_t *out,
                        mongocrypt_status_t *status)
{
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   bool ret = false;

   BSON_ASSERT (out);

   _mongocrypt_ciphertext_init (&ciphertext);

   if (!_mongocrypt_marking_to_ciphertext (ctx, marking, &ciphertext, status)) {
      goto fail;
   }

   if ((ciphertext.blob_subtype == MC_SUBTYPE_FLE2InsertUpdatePayload) ||
       (ciphertext.blob_subtype == MC_SUBTYPE_FLE2FindEqualityPayload)) {
      /* ciphertext_data is already a BSON object, just need to prepend
       * blob_subtype */
      _mongocrypt_buffer_init_size (&serialized_ciphertext,
                                    ciphertext.data.len + 1);
      serialized_ciphertext.data[0] = ciphertext.blob_subtype;
      memcpy (serialized_ciphertext.data + 1,
              ciphertext.data.data,
              ciphertext.data.len);

   } else if (!_mongocrypt_serialize_ciphertext (&ciphertext,
                                                 &serialized_ciphertext)) {
      CLIENT_ERR ("malformed ciphertext");
      goto fail;
   };

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = (bson_subtype_t) 6;

   ret = true;

fail:
   _mongocrypt_ciphertext_cleanup (&ciphertext);
   return ret;
}


static bool
_replace_marking_with_ciphertext (void *ctx,
                                  _mongocrypt_buffer_t *in,
                                  bson_value_t *out,
                                  mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking;
   bool ret;

   BSON_ASSERT (in);

   memset (&marking, 0, sizeof (marking));

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      _mongocrypt_marking_cleanup (&marking);
      return false;
   }

   ret = _marking_to_bson_value (ctx, &marking, out, status);
   _mongocrypt_marking_cleanup (&marking);
   return ret;
}

/* Process a call to mongocrypt_ctx_finalize when an encryptedFieldConfig is
 * associated with the command. */
static bool
_fle2_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t converted;
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t encrypted_field_config_bson;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   BSON_ASSERT (!_mongocrypt_buffer_empty (&ectx->encrypted_field_config));
   BSON_ASSERT (ctx->state == MONGOCRYPT_CTX_READY);

   if (ectx->explicit) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "explicit encryption is not yet supported. See MONGOCRYPT-409.");
   }

   if (!_mongocrypt_buffer_to_bson (&ectx->encrypted_field_config,
                                    &encrypted_field_config_bson)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "malformed bson in encrypted_field_config_bson");
   }

   /* If nothing_to_do is true, then the marked_cmd contained no markings. */
   if (ctx->nothing_to_do) {
      bson_t original_cmd_bson;

      if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd,
                                       &original_cmd_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx,
                                            "malformed bson in original_cmd");
      }

      /* Append 'encryptionInformation' to the original command. */
      bson_init (&converted);
      bson_copy_to (&original_cmd_bson, &converted);
      if (!_fle2_append_encryptionInformation (
             &converted, ectx->ns, &encrypted_field_config_bson, ctx->status)) {
         bson_destroy (&converted);
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      bson_t as_bson;
      bson_iter_t iter;

      if (!_mongocrypt_buffer_to_bson (&ectx->marked_cmd, &as_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
      }

      bson_iter_init (&iter, &as_bson);
      bson_init (&converted);
      if (!_mongocrypt_transform_binary_in_bson (
             _replace_marking_with_ciphertext,
             &ctx->kb,
             TRAVERSE_MATCH_MARKING,
             &iter,
             &converted,
             ctx->status)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   }

   _mongocrypt_buffer_steal_from_bson (&ectx->encrypted_cmd, &converted);
   _mongocrypt_buffer_to_binary (&ectx->encrypted_cmd, out);
   ctx->state = MONGOCRYPT_CTX_DONE;

   return true;
}

static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t as_bson, converted;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;
   bool res;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (!_mongocrypt_buffer_empty (&ectx->encrypted_field_config)) {
      return _fle2_finalize (ctx, out);
   }

   if (!ectx->explicit) {
      if (ctx->nothing_to_do) {
         _mongocrypt_buffer_to_binary (&ectx->original_cmd, out);
         ctx->state = MONGOCRYPT_CTX_DONE;
         return true;
      }
      if (!_mongocrypt_buffer_to_bson (&ectx->marked_cmd, &as_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
      }

      bson_iter_init (&iter, &as_bson);
      bson_init (&converted);
      if (!_mongocrypt_transform_binary_in_bson (
             _replace_marking_with_ciphertext,
             &ctx->kb,
             TRAVERSE_MATCH_MARKING,
             &iter,
             &converted,
             ctx->status)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      /* For explicit encryption, we have no marking, but we can fake one */
      _mongocrypt_marking_t marking;
      bson_value_t value;

      memset (&value, 0, sizeof (value));

      _mongocrypt_marking_init (&marking);

      if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
      }

      if (!bson_iter_init_find (&iter, &as_bson, "v")) {
         return _mongocrypt_ctx_fail_w_msg (ctx,
                                            "invalid msg, must contain 'v'");
      }


      memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));
      marking.algorithm = ctx->opts.algorithm;
      _mongocrypt_buffer_set_to (&ctx->opts.key_id, &marking.key_id);
      if (ctx->opts.key_alt_names) {
         bson_value_copy (&ctx->opts.key_alt_names->value,
                          &marking.key_alt_name);
         marking.type = MONGOCRYPT_MARKING_FLE1_BY_ALTNAME;
      }

      bson_init (&converted);
      res = _marking_to_bson_value (&ctx->kb, &marking, &value, ctx->status);
      if (res) {
         bson_append_value (&converted, MONGOCRYPT_STR_AND_LEN ("v"), &value);
      }

      bson_value_destroy (&value);
      _mongocrypt_marking_cleanup (&marking);

      if (!res) {
         bson_destroy (&converted);
         return _mongocrypt_ctx_fail (ctx);
      }
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
   bson_free (ectx->db_name);
   bson_free (ectx->coll_name);
   _mongocrypt_buffer_cleanup (&ectx->list_collections_filter);
   _mongocrypt_buffer_cleanup (&ectx->schema);
   _mongocrypt_buffer_cleanup (&ectx->encrypted_field_config);
   _mongocrypt_buffer_cleanup (&ectx->original_cmd);
   _mongocrypt_buffer_cleanup (&ectx->mongocryptd_cmd);
   _mongocrypt_buffer_cleanup (&ectx->marked_cmd);
   _mongocrypt_buffer_cleanup (&ectx->encrypted_cmd);
}


static bool
_try_schema_from_schema_map (mongocrypt_ctx_t *ctx)
{
   mongocrypt_t *crypt;
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t schema_map;
   bson_iter_t iter;

   crypt = ctx->crypt;
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (_mongocrypt_buffer_empty (&crypt->opts.schema_map)) {
      /* No schema map set. */
      return true;
   }

   if (!_mongocrypt_buffer_to_bson (&crypt->opts.schema_map, &schema_map)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed schema map");
   }

   if (bson_iter_init_find (&iter, &schema_map, ectx->ns)) {
      if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed schema map");
      }
      ectx->used_local_schema = true;
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   }

   /* No schema found in map. */
   return true;
}

/* Check if the local encrypted field config map has an entry for this
 * collection.
 * If an encrypted field config is found, the context transitions to
 * MONGOCRYPT_CTX_NEED_MONGO_MARKINGS. */
static bool
_fle2_try_encrypted_field_config_from_map (mongocrypt_ctx_t *ctx)
{
   mongocrypt_t *crypt;
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t encrypted_field_config_map;
   bson_iter_t iter;

   crypt = ctx->crypt;
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (_mongocrypt_buffer_empty (&crypt->opts.encrypted_field_config_map)) {
      /* No encrypted_field_config_map set. */
      return true;
   }

   if (!_mongocrypt_buffer_to_bson (&crypt->opts.encrypted_field_config_map,
                                    &encrypted_field_config_map)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "unable to convert encrypted_field_config_map to BSON");
   }

   if (bson_iter_init_find (&iter, &encrypted_field_config_map, ectx->ns)) {
      if (!_mongocrypt_buffer_copy_from_document_iter (
             &ectx->encrypted_field_config, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx,
            "unable to copy encrypted_field_config from "
            "encrypted_field_config_map");
      }
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   }

   /* No encrypted_field_config found in map. */
   return true;
}


static bool
_try_schema_from_cache (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *collinfo = NULL;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   /* Otherwise, we need a remote schema. Check if we have a response to
    * listCollections cached. */
   if (!_mongocrypt_cache_get (&ctx->crypt->cache_collinfo,
                               ectx->ns /* null terminated */,
                               (void **) &collinfo)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "failed to retrieve from cache");
   }

   if (collinfo) {
      if (!_set_schema_from_collinfo (ctx, collinfo)) {
         return _mongocrypt_ctx_fail (ctx);
      }
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   } else {
      /* we need to get it. */
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   }

   bson_destroy (collinfo);
   return true;
}

static bool
_permitted_for_encryption (bson_iter_t *iter,
                           mongocrypt_encryption_algorithm_t algo,
                           mongocrypt_status_t *status)
{
   bson_type_t bson_type;
   const bson_value_t *bson_value = bson_iter_value (iter);
   bool ret = false;

   if (!bson_value) {
      CLIENT_ERR ("Unknown BSON type");
      goto fail;
   }
   bson_type = bson_value->value_type;
   switch (bson_type) {
   case BSON_TYPE_NULL:
   case BSON_TYPE_MINKEY:
   case BSON_TYPE_MAXKEY:
   case BSON_TYPE_UNDEFINED:
      CLIENT_ERR ("BSON type invalid for encryption");
      goto fail;
   case BSON_TYPE_BINARY:
      if (bson_value->value.v_binary.subtype == 6) {
         CLIENT_ERR ("BSON binary subtype 6 is invalid for encryption");
         goto fail;
      }
      /* ok */
      break;
   case BSON_TYPE_DOUBLE:
   case BSON_TYPE_DOCUMENT:
   case BSON_TYPE_ARRAY:
   case BSON_TYPE_CODEWSCOPE:
   case BSON_TYPE_BOOL:
   case BSON_TYPE_DECIMAL128:
      if (algo == MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC) {
         CLIENT_ERR ("BSON type invalid for deterministic encryption");
         goto fail;
      }
      break;
   case BSON_TYPE_UTF8:
   case BSON_TYPE_OID:
   case BSON_TYPE_DATE_TIME:
   case BSON_TYPE_REGEX:
   case BSON_TYPE_DBPOINTER:
   case BSON_TYPE_CODE:
   case BSON_TYPE_SYMBOL:
   case BSON_TYPE_INT32:
   case BSON_TYPE_TIMESTAMP:
   case BSON_TYPE_INT64:
      /* ok */
      break;
   case BSON_TYPE_EOD:
   default:
      CLIENT_ERR ("invalid BSON value type 00");
      goto fail;
   }

   ret = true;
fail:
   return ret;
}

bool
mongocrypt_ctx_explicit_encrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_opts_spec_t opts_spec;

   if (!ctx) {
      return false;
   }
   memset (&opts_spec, 0, sizeof (opts_spec));
   opts_spec.key_descriptor = OPT_REQUIRED;
   opts_spec.algorithm = OPT_REQUIRED;

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->explicit = true;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   if (!msg || !msg->data) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "msg required for explicit encryption");
   }

   if (ctx->opts.key_alt_names) {
      if (!_mongocrypt_key_broker_request_name (
             &ctx->kb, &ctx->opts.key_alt_names->value)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      if (!_mongocrypt_key_broker_request_id (&ctx->kb, &ctx->opts.key_id)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   }

   _mongocrypt_buffer_init (&ectx->original_cmd);

   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, msg);
   if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "msg must be bson");
   }

   if (ctx->crypt->log.trace_enabled) {
      char *cmd_val;
      cmd_val = _mongocrypt_new_json_string_from_binary (msg);
      _mongocrypt_log (&ctx->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\")",
                       BSON_FUNC,
                       "msg",
                       cmd_val);
      bson_free (cmd_val);
   }

   if (!bson_iter_init_find (&iter, &as_bson, "v")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg, must contain 'v'");
   }

   if (!_permitted_for_encryption (&iter, ctx->opts.algorithm, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   (void) _mongocrypt_key_broker_requests_done (&ctx->kb);
   return _mongocrypt_ctx_state_from_key_broker (ctx);
}

static bool
_check_cmd_for_auto_encrypt (mongocrypt_binary_t *cmd,
                             bool *bypass,
                             char **collname,
                             mongocrypt_status_t *status)
{
   bson_t as_bson;
   bson_iter_t iter, ns_iter;
   const char *cmd_name;
   bool eligible = false;

   *bypass = false;

   if (!_mongocrypt_binary_to_bson (cmd, &as_bson) ||
       !bson_iter_init (&iter, &as_bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   /* The command name is the first key. */
   if (!bson_iter_next (&iter)) {
      CLIENT_ERR ("invalid empty BSON");
      return false;
   }

   cmd_name = bson_iter_key (&iter);
   BSON_ASSERT (cmd_name);

   /* get the collection name (or NULL if database/client command). */
   if (0 == strcmp (cmd_name, "explain")) {
      if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
         CLIENT_ERR ("explain value is not a document");
         return false;
      }
      if (!bson_iter_recurse (&iter, &ns_iter)) {
         CLIENT_ERR ("malformed BSON for encrypt command");
         return false;
      }
      if (!bson_iter_next (&ns_iter)) {
         CLIENT_ERR ("invalid empty BSON");
         return false;
      }
   } else {
      memcpy (&ns_iter, &iter, sizeof (iter));
   }

   if (BSON_ITER_HOLDS_UTF8 (&ns_iter)) {
      *collname = bson_strdup (bson_iter_utf8 (&ns_iter, NULL));
   } else {
      *collname = NULL;
   }

   /* check if command is eligible for auto encryption, bypassed, or ineligible.
    */
   if (0 == strcmp (cmd_name, "aggregate")) {
      /* collection level aggregate ok, database/client is not. */
      eligible = true;
   } else if (0 == strcmp (cmd_name, "count")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "distinct")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "delete")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "find")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "findAndModify")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "getMore")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "insert")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "update")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "authenticate")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "getnonce")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "logout")) {
      *bypass = true;
   } else if (0 == bson_strcasecmp (cmd_name, "isMaster")) {
      /* use case insensitive compare for ismaster, since some drivers send
       * "ismaster" and others send "isMaster" */
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "abortTransaction")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "commitTransaction")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "endSessions")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "startSession")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "create")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "createIndexes")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "drop")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "dropDatabase")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "dropIndexes")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "killCursors")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "listCollections")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "listDatabases")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "listIndexes")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "renameCollection")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "explain")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "ping")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "saslStart")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "saslContinue")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "killAllSessions")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "killSessions")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "killAllSessionsByPattern")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "refreshSessions")) {
      *bypass = true;
   }

   /* database/client commands are ineligible. */
   if (eligible) {
      if (!*collname) {
         CLIENT_ERR (
            "non-collection command not supported for auto encryption: %s",
            cmd_name);
         return false;
      }
      if (0 == strlen (*collname)) {
         CLIENT_ERR ("empty collection name on command: %s", cmd_name);
         return false;
      }
   }

   if (eligible || *bypass) {
      return true;
   }

   CLIENT_ERR ("command not supported for auto encryption: %s", cmd_name);
   return false;
}

bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *db,
                             int32_t db_len,
                             mongocrypt_binary_t *cmd)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   _mongocrypt_ctx_opts_spec_t opts_spec;
   bool bypass;

   if (!ctx) {
      return false;
   }
   memset (&opts_spec, 0, sizeof (opts_spec));
   opts_spec.schema = OPT_OPTIONAL;
   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->explicit = false;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_feed_collinfo = _mongo_feed_collinfo;
   ctx->vtable.mongo_done_collinfo = _mongo_done_collinfo;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_op_markings = _mongo_op_markings;
   ctx->vtable.mongo_feed_markings = _mongo_feed_markings;
   ctx->vtable.mongo_done_markings = _mongo_done_markings;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_feed_collinfo = _mongo_feed_collinfo;
   ctx->vtable.mongo_done_collinfo = _mongo_done_collinfo;


   if (!cmd || !cmd->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid command");
   }

   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, cmd);

   if (!_check_cmd_for_auto_encrypt (
          cmd, &bypass, &ectx->coll_name, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (bypass) {
      ctx->nothing_to_do = true;
      ctx->state = MONGOCRYPT_CTX_READY;
      return true;
   }

   /* if _check_cmd_for_auto_encrypt did not bypass or error, a collection name
    * must have been set. */
   if (!ectx->coll_name) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx,
         "unexpected error: did not bypass or error but no collection name");
   }

   if (!_mongocrypt_validate_and_copy_string (db, db_len, &ectx->db_name) ||
       0 == strlen (ectx->db_name)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid db");
   }

   ectx->ns = bson_strdup_printf ("%s.%s", ectx->db_name, ectx->coll_name);

   if (ctx->opts.kek.provider.aws.region || ctx->opts.kek.provider.aws.cmk) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "aws masterkey options must not be set");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.key_id)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "key_id must not be set for auto encryption");
   }

   if (ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "algorithm must not be set for auto encryption");
   }

   if (ctx->crypt->log.trace_enabled) {
      char *cmd_val;
      cmd_val = _mongocrypt_new_json_string_from_binary (cmd);
      _mongocrypt_log (&ctx->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\", %s=%d, %s=\"%s\")",
                       BSON_FUNC,
                       "db",
                       ectx->db_name,
                       "db_len",
                       db_len,
                       "cmd",
                       cmd_val);
      bson_free (cmd_val);
   }

   /* Check if there is an encrypted field config in encrypted_field_config_map
    */
   if (!_fle2_try_encrypted_field_config_from_map (ctx)) {
      return false;
   }
   if (_mongocrypt_buffer_empty (&ectx->encrypted_field_config)) {
      /* Check if we have a local schema from schema_map */
      if (!_try_schema_from_schema_map (ctx)) {
         return false;
      }

      /* If we didn't have a local schema, try the cache. */
      if (_mongocrypt_buffer_empty (&ectx->schema)) {
         if (!_try_schema_from_cache (ctx)) {
            return false;
         }
      }

      /* Otherwise, we need the the driver to fetch the schema. */
      if (_mongocrypt_buffer_empty (&ectx->schema)) {
         ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
      }
   }

   if (ctx->crypt->opts.bypass_query_analysis) {
      ctx->nothing_to_do = true;
      ctx->state = MONGOCRYPT_CTX_READY;
      return true;
   }

   if (ctx->state == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS) {
      // We're ready for markings. Try to generate them ourself.
      return _try_run_csfle_marking (ctx);
   } else {
      // Other state, return to caller.
      return true;
   }
}
