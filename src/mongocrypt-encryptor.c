/*
 * Copyright 2018-present MongoDB, Inc.
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
#include "mongocrypt-binary-private.h"
#include "mongocrypt-encryptor-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-schema-cache-private.h"
#include "mongocrypt-crypto-private.h"

static bool
_check_state (mongocrypt_encryptor_t *encryptor,
              mongocrypt_encryptor_state_t state)
{
   mongocrypt_status_t *status;
   const char *state_names[] = {"ERROR",
                                "NEED_NS",
                                "NEED_SCHEMA",
                                "NEED_MARKINGS",
                                "NEED_KEYS",
                                "NEED_KEYS_DECRYPTED",
                                "NEED_ENCRYPTION",
                                "NO_ENCRYPTION_NEEDED",
                                "ENCRYPTED"};

   status = encryptor->status;

   if (encryptor->state != state) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      CLIENT_ERR ("Expected state %s, but in state %s",
                  state_names[state],
                  state_names[encryptor->state]);
      return false;
   }
   return true;
}

mongocrypt_encryptor_t *
mongocrypt_encryptor_new (mongocrypt_t *crypt)
{
   mongocrypt_encryptor_t *encryptor;

   encryptor = (mongocrypt_encryptor_t *) bson_malloc0 (sizeof *encryptor);
   encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS;
   encryptor->crypt = crypt;
   encryptor->status = mongocrypt_status_new ();
   _mongocrypt_key_broker_init (&encryptor->kb);

   return encryptor;
}

mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_ns (mongocrypt_encryptor_t *encryptor, const char *ns)
{
   _mongocrypt_schema_cache_t *cache;
   _mongocrypt_schema_handle_t *handle;
   mongocrypt_status_t *status;

   status = encryptor->status;

   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS)) {
      return encryptor->state;
   }

   if (!ns || !strstr (ns, ".")) {
      CLIENT_ERR ("invalid namespace");
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      return encryptor->state;
   }

   encryptor->ns = ns;

   cache = encryptor->crypt->schema_cache;
   /* TODO reader lock while using the schema handle */
   handle = _mongocrypt_schema_cache_lookup_ns (cache, ns);

   if (handle) {
      /* If we already have a cached schema, proceed to mongocryptd
    if we need to, otherwise done if we don't need encryption. */
      if (handle->needs_encryption) {
         encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS;
      } else {
         encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
      }
   } else {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA;
   }

   return encryptor->state;
}

mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_collection_info (
   mongocrypt_encryptor_t *encryptor,
   const mongocrypt_binary_t *collection_info)
{
   bson_t reply;
   bson_iter_t iter, validator_iter;
   bool found_schema, validator_has_siblings;
   mongocrypt_status_t *status;

   BSON_ASSERT (encryptor);
   status = encryptor->status;

   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA)) {
      return encryptor->state;
   }

   if (!collection_info || !collection_info->data) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
      return encryptor->state;
   }

   /* Append the schema to the encryptor, but don't add it to the cache
      until we know whether or not it requires encryption. */
   found_schema = false;
   /* TODO: use validator_has_siblings. We should error if there are siblings
    * and the schema has encrypted fields per the spec, since we only accept
    * one $jsonSchema in the validators. */
   validator_has_siblings = false;

   BSON_ASSERT (
      bson_init_static (&reply, collection_info->data, collection_info->len));
   bson_iter_init (&iter, &reply);
   if (bson_iter_find_descendant (&iter, "options.validator", &iter)) {
      bson_iter_recurse (&iter, &iter);
      memcpy (&validator_iter, &iter, sizeof (iter));

      if (bson_iter_find (&iter, "$jsonSchema") &&
          BSON_ITER_HOLDS_DOCUMENT (&iter)) {
         found_schema = true;
         _mongocrypt_buffer_copy_from_document_iter (&encryptor->schema, &iter);
      }

      while (bson_iter_next (&validator_iter)) {
         if (0 != strcmp ("$jsonSchema", bson_iter_key (&validator_iter))) {
            validator_has_siblings = true;
            break;
         }
      }
   }

   if (found_schema) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS;
      return encryptor->state;
   }

   encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
   return encryptor->state;
}

mongocrypt_binary_t *
mongocrypt_encryptor_get_schema (mongocrypt_encryptor_t *encryptor)
{
   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS)) {
      return NULL;
   }

   return _mongocrypt_buffer_to_binary (&encryptor->schema);
}


static bool
_collect_key_from_marking (void *ctx, _mongocrypt_buffer_t *in)
{
   mongocrypt_status_t *status;
   _mongocrypt_marking_t marking = {0};
   mongocrypt_encryptor_t *encryptor;

   encryptor = (mongocrypt_encryptor_t *) ctx;
   status = encryptor->status;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, encryptor->status)) {
      return false;
   }

   /* TODO: check if the key cache has the key. */
   /* TODO: support keyAltName. */
   if (marking.key_alt_name) {
      CLIENT_ERR ("keyAltName not supported yet");
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (&encryptor->kb, &marking.key_id)) {
      mongocrypt_status_copy_to (encryptor->kb.status, encryptor->status);
      return false;
   }
   return true;
}


mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_markings (mongocrypt_encryptor_t *encryptor,
                                   const mongocrypt_binary_t *marked_reply)
{
   mongocrypt_status_t *status;
   bson_iter_t iter;
   bson_t parsed_reply;
   bool has_encrypted_placeholders;

   BSON_ASSERT (encryptor);
   status = encryptor->status;

   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS)) {
      return encryptor->state;
   }

   if (!marked_reply) {
      CLIENT_ERR ("invalid markings");
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      goto done;
   }

   _mongocrypt_binary_to_bson (marked_reply, &parsed_reply);

   /* TODO: move this parsing logic to mongocrypt-parsing.c and parse into a
    * struct. */
   // TODO also check that the reply wasn't an error.
   if (!bson_iter_init_find (&iter, &parsed_reply, "ok") ||
       !BSON_ITER_HOLDS_INT (&iter)) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      CLIENT_ERR ("malformatted mongocryptd reply");
      goto done;
   }

   if (bson_iter_init_find (&iter, &parsed_reply, "schemaRequiresEncryption")) {
      if (!BSON_ITER_HOLDS_BOOL (&iter)) {
         encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
         CLIENT_ERR ("malformatted schemaRequiredEncryption field");
         goto done;
      }
      /* TODO add the schema to the schema cache */
   }

   /* If we don't need to encrypt, we're done. */
   has_encrypted_placeholders = false;
   if (bson_iter_init_find (&iter, &parsed_reply, "hasEncryptedPlaceholders")) {
      if (BSON_ITER_HOLDS_BOOL (&iter)) {
         has_encrypted_placeholders = bson_iter_bool (&iter);
      } else {
         encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
         CLIENT_ERR ("malformed hasEncryptedPlaceholders field");
         goto done;
      }
   }

   if (!has_encrypted_placeholders) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
      goto done;
   }

   if (!bson_iter_init_find (&iter, &parsed_reply, "result")) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      CLIENT_ERR ("marked reply does not have 'result'");
      goto done;
   }

   _mongocrypt_buffer_from_document_iter (&encryptor->marked, &iter);

   bson_iter_recurse (&iter, &iter);
   if (!_mongocrypt_traverse_binary_in_bson (
          _collect_key_from_marking, (void *) encryptor, 0, &iter, status)) {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      goto done;
   }

   if (_mongocrypt_key_broker_empty (&encryptor->kb)) {
      /* if there were no keys, i.e. no markings, no encryption is needed. */
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
   } else {
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS;
   }

done:
   return encryptor->state;
}


mongocrypt_key_broker_t *
mongocrypt_encryptor_get_key_broker (mongocrypt_encryptor_t *encryptor)
{
   BSON_ASSERT (encryptor);

   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS)) {
      return NULL;
   }

   return &encryptor->kb;
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
void
_mongocrypt_encryptor_serialize_ciphertext (
   _mongocrypt_ciphertext_t *ciphertext, _mongocrypt_buffer_t *out)
{
   uint32_t offset;

   BSON_ASSERT (ciphertext);
   BSON_ASSERT (out);
   BSON_ASSERT (ciphertext->key_id.len == 16);

   /* TODO CDRIVER-3001: relocate this logic? */
   offset = 0;
   out->len = 1 + ciphertext->key_id.len + 1 + ciphertext->data.len;
   out->data = bson_malloc0 (out->len);

   out->data[offset] = ciphertext->blob_subtype;
   offset += 1;

   memcpy (out->data + offset, ciphertext->key_id.data, ciphertext->key_id.len);
   offset += ciphertext->key_id.len;

   out->data[offset] = ciphertext->original_bson_type;
   offset += 1;

   memcpy (out->data + offset, ciphertext->data.data, ciphertext->data.len);
   offset += ciphertext->data.len;
}


static bool
_replace_marking_with_ciphertext (void *ctx,
                                  _mongocrypt_buffer_t *in,
                                  bson_value_t *out)
{
   mongocrypt_status_t *status;
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ciphertext_t ciphertext = {0};
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   _mongocrypt_buffer_t plaintext = {0};
   mongocrypt_key_broker_t *kb;
   bson_t wrapper = BSON_INITIALIZER;
   const _mongocrypt_buffer_t *key_material;
   bool ret = false;
   uint32_t bytes_written;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   kb = (mongocrypt_key_broker_t *) ctx;
   status = kb->status;

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
   key_material =
      _mongocrypt_key_broker_decrypted_key_material_by_id (kb, &marking.key_id);
   if (!key_material) {
      mongocrypt_status_copy_to (kb->status, status);
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
                                    key_material,
                                    &plaintext,
                                    &ciphertext.data,
                                    &bytes_written,
                                    status);
   if (!ret) {
      goto fail;
   }
   BSON_ASSERT (bytes_written == ciphertext.data.len);

   memcpy (&ciphertext.key_id, &marking.key_id, sizeof (_mongocrypt_buffer_t));
   _mongocrypt_encryptor_serialize_ciphertext (&ciphertext,
                                               &serialized_ciphertext);

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = 6;

   ret = true;

fail:
   bson_free (ciphertext.data.data);
   bson_destroy (&wrapper);
   return ret;
}


mongocrypt_encryptor_state_t
mongocrypt_encryptor_key_broker_done (mongocrypt_encryptor_t *encryptor)
{
   mongocrypt_status_t *status;

   BSON_ASSERT (encryptor);
   status = encryptor->status;

   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS)) {
      return encryptor->state;
   }

   if (_mongocrypt_key_broker_has (&encryptor->kb, KEY_ENCRYPTED) ||
       _mongocrypt_key_broker_has (&encryptor->kb, KEY_EMPTY)) {
      CLIENT_ERR ("client did not provide all keys");
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      return encryptor->state;
   }

   encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION;
done:
   return encryptor->state;
}


mongocrypt_encryptor_state_t
mongocrypt_encryptor_encrypt (mongocrypt_encryptor_t *encryptor)
{
   bson_iter_t iter;
   int ret = false;
   bson_t out = BSON_INITIALIZER;
   bson_t as_bson;
   mongocrypt_status_t *status;

   BSON_ASSERT (encryptor);
   status = encryptor->status;

   if (!_check_state (encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION)) {
      return encryptor->state;
   }

   _mongocrypt_buffer_to_bson (&encryptor->marked, &as_bson);
   bson_iter_init (&iter, &as_bson);

   ret = _mongocrypt_transform_binary_in_bson (
      _replace_marking_with_ciphertext, &encryptor->kb, 0, &iter, &out, status);
   if (!ret) {
      bson_destroy (&out);
      encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      goto done;
   }

   encryptor->encrypted_cmd.data =
      bson_destroy_with_steal (&out, true, &encryptor->encrypted_cmd.len);
   encryptor->state = MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED;
done:
   return encryptor->state;
}


mongocrypt_encryptor_state_t
mongocrypt_encryptor_state (mongocrypt_encryptor_t *encryptor)
{
   BSON_ASSERT (encryptor);

   return encryptor->state;
}


mongocrypt_binary_t *
mongocrypt_encryptor_encrypted_cmd (mongocrypt_encryptor_t *encryptor)
{
   BSON_ASSERT (encryptor);

   return _mongocrypt_buffer_to_binary (&encryptor->encrypted_cmd);
}


void
mongocrypt_encryptor_destroy (mongocrypt_encryptor_t *encryptor)
{
   if (!encryptor) {
      return;
   }

   _mongocrypt_key_broker_cleanup (&encryptor->kb);

   mongocrypt_status_destroy (encryptor->status);
   bson_free (encryptor);
}


bool
mongocrypt_encryptor_status (mongocrypt_encryptor_t *encryptor,
                             mongocrypt_status_t *out)
{
   if (!mongocrypt_status_ok (encryptor->status)) {
      mongocrypt_status_copy_to (encryptor->status, out);
      return false;
   }
   mongocrypt_status_reset (out);
   return true;
}