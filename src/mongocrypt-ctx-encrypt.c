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
#include "mongocrypt-marking-private.h"
#include "mongocrypt-key-broker-private.h"

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

   /* Parse out the schema. */
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   /* Disallow views. */
   if (bson_iter_init_find (&iter, collinfo, "type") &&
       BSON_ITER_HOLDS_UTF8 (&iter) &&
       0 == strcmp ("view", bson_iter_utf8 (&iter, NULL))) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot auto encrypt a view");
   }

   if (!bson_iter_init (&iter, collinfo)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }

   if (bson_iter_find_descendant (
          &iter, "options.validator.$jsonSchema", &iter)) {
      if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed JSONSchema");
      }
   }

   /* TODO CDRIVER-3096 check for validator siblings. */
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
   if (!_mongocrypt_cache_add_copy (&ctx->crypt->cache_collinfo,
                                    ectx->ns,
                                    &as_bson,
                                    ctx->id,
                                    ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (!_set_schema_from_collinfo (ctx, &as_bson)) {
      return false;
   }

   return true;
}


static bool
_mongo_done_collinfo (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   return true;
}


static bool
_mongo_op_markings (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t cmd_bson, schema_bson, mongocryptd_cmd_bson;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (_mongocrypt_buffer_empty (&ectx->mongocryptd_cmd)) {
      /* first, get the original command. */
      if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &cmd_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "invalid BSON cmd");
      }

      if (_mongocrypt_buffer_empty (&ectx->schema)) {
         bson_init (&schema_bson);
      } else if (!_mongocrypt_buffer_to_bson (&ectx->schema, &schema_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "invalid BSON schema");
      }

      bson_copy_to (&cmd_bson, &mongocryptd_cmd_bson);
      BSON_APPEND_DOCUMENT (&mongocryptd_cmd_bson, "jsonSchema", &schema_bson);
      /* TODO: CDRIVER-3149 append isRemoteSchema. */
      _mongocrypt_buffer_steal_from_bson (&ectx->mongocryptd_cmd,
                                          &mongocryptd_cmd_bson);

      bson_destroy (&cmd_bson);
      bson_destroy (&schema_bson);
   }
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
      return false;
   }

   /* TODO: check if the key cache has the key. */
   if (marking.has_alt_name) {
      res = _mongocrypt_key_broker_add_name (kb, &marking.key_alt_name);
   } else {
      res = _mongocrypt_key_broker_add_id (kb, &marking.key_id);
   }

   if (!res) {
      _mongocrypt_key_broker_status (kb, status);
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
      if (!_mongocrypt_buffer_empty (&ctx->opts.local_schema)) {
         _mongocrypt_log (
            &ctx->crypt->log,
            MONGOCRYPT_LOG_LEVEL_WARNING,
            "local schema used but does not have encryption specifiers");
      }
      return true;
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
   return _mongocrypt_ctx_state_from_key_broker (ctx);
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

   _mongocrypt_serialize_ciphertext (&ciphertext, &serialized_ciphertext);

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = 6;

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
   _mongocrypt_marking_t marking = {0};

   BSON_ASSERT (in);

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      return false;
   }

   return _marking_to_bson_value (ctx, &marking, out, status);
}

static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t as_bson, converted;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;
   bool res = true;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (!ectx->explicit) {
      _mongocrypt_buffer_to_bson (&ectx->marked_cmd, &as_bson);
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

      _mongocrypt_marking_init (&marking);

      _mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson);
      if (!bson_iter_init_find (&iter, &as_bson, "v")) {
         return _mongocrypt_ctx_fail_w_msg (ctx,
                                            "invalid msg, must contain 'v'");
      }


      memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));
      marking.algorithm = ctx->opts.algorithm;
      _mongocrypt_buffer_set_to (&ctx->opts.key_id, &marking.key_id);

      bson_init (&converted);
      res = _marking_to_bson_value (&ctx->kb, &marking, &value, ctx->status);
      if (res) {
         bson_append_value (&converted, MONGOCRYPT_STR_AND_LEN ("v"), &value);
      }

      bson_value_destroy (&value);
      _mongocrypt_marking_cleanup (&marking);

      if (!res) {
         return false;
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

   /* Removing any pending cache entries in the cache this context
    * is responsible for fetching. */
   _mongocrypt_cache_remove_by_owner (&ctx->crypt->cache_collinfo, ctx->id);

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   bson_free (ectx->ns);
   bson_free (ectx->db_name);
   bson_free (ectx->coll_name);
   _mongocrypt_buffer_cleanup (&ectx->list_collections_filter);
   _mongocrypt_buffer_cleanup (&ectx->schema);
   _mongocrypt_buffer_cleanup (&ectx->original_cmd);
   _mongocrypt_buffer_cleanup (&ectx->mongocryptd_cmd);
   _mongocrypt_buffer_cleanup (&ectx->marked_cmd);
   _mongocrypt_buffer_cleanup (&ectx->encrypted_cmd);
}


static bool
_try_collinfo_from_cache (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *collinfo = NULL;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   /* reset */
   ectx->collinfo_owner = 0;
   ectx->collinfo_state = CACHE_PAIR_PENDING;
   ectx->waiting_for_collinfo = false;

   /* Otherwise, we need a remote schema. Check if we have a response to
      * listCollections cached. */
   _mongocrypt_cache_get_or_create (&ctx->crypt->cache_collinfo,
                                    ectx->ns /* null terminated */,
                                    (void **) &collinfo,
                                    &ectx->collinfo_state,
                                    ctx->id,
                                    &ectx->collinfo_owner);

   if (ectx->collinfo_state == CACHE_PAIR_DONE) {
      if (!_set_schema_from_collinfo (ctx, collinfo)) {
         return _mongocrypt_ctx_fail (ctx);
      }
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   } else if (ectx->collinfo_owner == ctx->id) {
      /* we need to get it. */
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   } else {
      /* waiting on another context. */
      ectx->waiting_for_collinfo = true;
      ctx->state = MONGOCRYPT_CTX_WAITING;
   }

   bson_destroy (collinfo);
   return true;
}


static bool
_wait_done (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (ectx->waiting_for_collinfo) {
      if (ctx->cache_noblock) {
         return _try_collinfo_from_cache (ctx);
      }
      if (!_mongocrypt_cache_wait (&ctx->crypt->cache_collinfo, ctx->status)) {
         return _mongocrypt_ctx_fail (ctx);
      }
      return _try_collinfo_from_cache (ctx);
   } else {
      if (!_mongocrypt_key_broker_check_cache_and_wait (&ctx->kb,
                                                        !ctx->cache_noblock)) {
         BSON_ASSERT (!_mongocrypt_key_broker_status (&ctx->kb, ctx->status));
         return _mongocrypt_ctx_fail (ctx);
      }
      return _mongocrypt_ctx_state_from_key_broker (ctx);
   }
}


static uint32_t
_next_dependent_ctx_id (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (ectx->waiting_for_collinfo) {
      uint32_t tmp;

      tmp = ectx->collinfo_owner;
      ectx->collinfo_owner = 0;
      return tmp;
   } else {
      return _mongocrypt_key_broker_next_ctx_id (&ctx->kb);
   }
}


bool
mongocrypt_ctx_explicit_encrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t as_bson;
   bson_iter_t iter;

   _mongocrypt_ctx_opts_spec_t opts_spec = {0};

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
   ctx->vtable.wait_done = _wait_done;
   ctx->vtable.next_dependent_ctx_id = _next_dependent_ctx_id;

   if (!msg || !msg->data) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "msg required for explicit encryption");
   }

   if (ctx->opts.key_alt_name) {
      if (!_mongocrypt_key_broker_add_name (&ctx->kb, ctx->opts.key_alt_name)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      if (!_mongocrypt_key_broker_add_id (&ctx->kb, &ctx->opts.key_id)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   }

   _mongocrypt_buffer_init (&ectx->original_cmd);

   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, msg);
   if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "msg must be bson");
   }

   if (!bson_iter_init_find (&iter, &as_bson, "v")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg, must contain 'v'");
   }

   return _mongocrypt_ctx_state_from_key_broker (ctx);
}


static bool
_check_cmd_for_auto_encrypt (mongocrypt_binary_t *cmd,
                             bool *bypass,
                             char **collname,
                             mongocrypt_status_t *status)
{
   bson_t as_bson;
   bson_iter_t iter;
   const char *cmd_name;

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

   if (BSON_ITER_HOLDS_UTF8 (&iter)) {
      *collname = bson_strdup (bson_iter_utf8 (&iter, NULL));
   } else {
      *collname = bson_strdup ("");
   }

   /* aggregate ok only for collections, ie aggregate:"coll", not aggregate:1 */
   if (0 == strcmp (cmd_name, "aggregate") && BSON_ITER_HOLDS_UTF8 (&iter)) {
      return true;
   } else if (0 == strcmp (cmd_name, "count")) {
      return true;
   } else if (0 == strcmp (cmd_name, "distinct")) {
      return true;
   } else if (0 == strcmp (cmd_name, "delete")) {
      return true;
   } else if (0 == strcmp (cmd_name, "find")) {
      return true;
   } else if (0 == strcmp (cmd_name, "findAndModify")) {
      return true;
   } else if (0 == strcmp (cmd_name, "getMore")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "insert")) {
      return true;
   } else if (0 == strcmp (cmd_name, "update")) {
      return true;
   } else if (0 == strcmp (cmd_name, "authenticate")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "getnonce")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "logout")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "isMaster")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "abortTransaction")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "commitTransaction")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "endSessions")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "startSession")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "create")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "createIndexes")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "drop")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "dropDatabase")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "dropIndexes")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "killCursors")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "listCollections")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "listDatabases")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "listIndexes")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "renameCollection")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "explain")) {
      return true;
   } else if (0 == strcmp (cmd_name, "ping")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "saslStart")) {
      *bypass = true;
      return true;
   } else if (0 == strcmp (cmd_name, "saslContinue")) {
      *bypass = true;
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
   _mongocrypt_ctx_opts_spec_t opts_spec = {0};
   bool bypass;

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
   ctx->vtable.wait_done = _wait_done;
   ctx->vtable.next_dependent_ctx_id = _next_dependent_ctx_id;


   if (!cmd || !cmd->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid command");
   }

   if (!_check_cmd_for_auto_encrypt (
          cmd, &bypass, &ectx->coll_name, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (bypass) {
      ctx->state = MONGOCRYPT_CTX_NOTHING_TO_DO;
      return true;
   }

   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, cmd);

   if (!_mongocrypt_validate_and_copy_string (db, db_len, &ectx->db_name)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid db");
   }

   ectx->ns = bson_strdup_printf ("%s.%s", ectx->db_name, ectx->coll_name);

   if (ctx->opts.masterkey_aws_region || ctx->opts.masterkey_aws_cmk) {
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

   /* Check if a local schema was provided. */
   if (!_mongocrypt_buffer_empty (&ctx->opts.local_schema)) {
      _mongocrypt_buffer_steal (&ectx->schema, &ctx->opts.local_schema);
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   } else {
      return _try_collinfo_from_cache (ctx);
   }
   return true;
}
