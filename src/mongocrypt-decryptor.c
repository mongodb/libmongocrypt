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

#include "mongocrypt-binary-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-decryptor-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-schema-cache-private.h"

static bool
_check_state (mongocrypt_decryptor_t *decryptor,
              mongocrypt_decryptor_state_t state)
{
   mongocrypt_status_t *status;
   const char *state_names[] = {"NEED_DOC",
                                "NEED_KEYS",
                                "NEED_DECRYPTION",
                                "NO_DECRYPTION_NEEDED",
                                "DECRYPTED",
                                "ERROR"};

   status = decryptor->status;

   if (decryptor->state != state) {
      CLIENT_ERR (
         "Expected state %s, but in state %s", state, decryptor->state);
      return false;
   }

   return true;
}

/* TODO CDRIVER-3001 this may not be the right home for this method */
static bool
_parse_ciphertext_unowned (_mongocrypt_buffer_t *in,
                           _mongocrypt_ciphertext_t *ciphertext,
                           mongocrypt_status_t *status)
{
   uint32_t offset;
   /* TODO: serialize with respect to endianness. Move this to
    * mongocrypt-parsing.c? Check mongoc scatter/gatter for inspiration. */

   BSON_ASSERT (in);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);
   /* skip first byte */
   offset = 1;

   memcpy (&ciphertext->keyvault_alias_len, in->data + offset, 2);
   offset += 2;

   ciphertext->keyvault_alias = (char *) in->data + offset;
   offset += ciphertext->keyvault_alias_len;

   ciphertext->key_id.data = in->data + offset;
   ciphertext->key_id.len = 16;
   ciphertext->key_id.subtype = BSON_SUBTYPE_UUID;
   offset += 16;

   offset += 1; /* Original BSON type, skip for now. */

   ciphertext->iv.data = in->data + offset;
   ciphertext->iv.len = 16;
   ciphertext->iv.subtype = BSON_SUBTYPE_BINARY;
   offset += 16;

   memcpy (&ciphertext->data.len, in->data + offset, 4);
   offset += 4;

   ciphertext->data.data = in->data + offset;
   return true;
}

mongocrypt_decryptor_t *
mongocrypt_decryptor_new (mongocrypt_t *crypt, const mongocrypt_opts_t *opts)
{
   mongocrypt_decryptor_t *decryptor;

   decryptor = (mongocrypt_decryptor_t *) bson_malloc0 (sizeof *decryptor);

   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC;
   decryptor->crypt = crypt;
   decryptor->status = mongocrypt_status_new ();
   _mongocrypt_key_broker_init (&decryptor->kb);

   return decryptor;
}

static bool
_collect_key_from_ciphertext (void *ctx,
                              _mongocrypt_buffer_t *in,
                              mongocrypt_status_t *status)
{
   _mongocrypt_ciphertext_t ciphertext;
   mongocrypt_decryptor_t *decryptor;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (status);

   decryptor = (mongocrypt_decryptor_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (
          &decryptor->kb, &ciphertext.key_id, status)) {
      return false;
   }

   return true;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_add_doc (mongocrypt_decryptor_t *decryptor,
                              mongocrypt_binary_t *encrypted_doc,
                              const mongocrypt_opts_t *opts)
{
   mongocrypt_status_t *status;
   bson_iter_t iter;
   bson_t tmp;

   BSON_ASSERT (decryptor);
   status = decryptor->status;

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC)) {
      goto done;
   }

   /* TODO this is only for testing, remove */
   if (!encrypted_doc) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS;
      goto done;
   }

   decryptor->encrypted_doc = encrypted_doc;

   mongocrypt_binary_to_bson (encrypted_doc, &tmp);
   bson_iter_init (&iter, &tmp);

   if (!_mongocrypt_traverse_binary_in_bson (
          _collect_key_from_ciphertext, (void *) decryptor, 0, iter, status)) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_ERROR;
      goto done;
   }

   if (_mongocrypt_key_broker_empty (&decryptor->kb)) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED;
   } else {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS;
   }

done:
   return decryptor->state;
}


mongocrypt_key_broker_t *
mongocrypt_decryptor_get_key_broker (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS)) {
      return NULL;
   }

   return &decryptor->kb;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_key_broker_done (mongocrypt_decryptor_t *decryptor)
{
   mongocrypt_status_t *status;

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS)) {
      return decryptor->state;
   }

   if (_mongocrypt_key_broker_has (&decryptor->kb, KEY_ENCRYPTED)) {
      /* We allow partial decryption, so this is not an error. */
      _mongocrypt_log (MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Some keys are still encrypted, the decryptor"
                       "can only partially decrypt this document.");
   }

   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION;

   return decryptor->state;
}

static bool
_replace_ciphertext_with_plaintext (void *ctx,
                                    _mongocrypt_buffer_t *in,
                                    bson_value_t *out,
                                    mongocrypt_status_t *status)
{
   mongocrypt_decryptor_t *decryptor;
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t plaintext = {0};
   const _mongocrypt_buffer_t *key_material;
   bson_t wrapper;
   bson_iter_t iter;
   const _mongocrypt_key_t *key;
   uint32_t bytes_written;
   bool ret = false;

   CRYPT_ENTRY;
   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   BSON_ASSERT (status);

   decryptor = (mongocrypt_decryptor_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      goto fail;
   }

   /* look up the key */
   key_material = _mongocrypt_key_broker_decrypted_key_material_by_id (
      &decryptor->kb, &ciphertext.key_id, status);
   if (!key_material) {
      /* We allow partial decryption, so this is not an error. */
      _mongocrypt_log (MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Missing key, skipping decryption for this ciphertext");
      ret = true;
      goto fail;
   }

   plaintext.len = ciphertext.data.len;
   plaintext.data = bson_malloc0 (plaintext.len);
   plaintext.owned = true;

   if (!_mongocrypt_do_decryption (NULL,
                                   &key->data_key,
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

mongocrypt_decryptor_state_t
mongocrypt_decryptor_decrypt (mongocrypt_decryptor_t *decryptor)
{
   mongocrypt_status_t *status;
   bson_iter_t iter;
   bson_t out = BSON_INITIALIZER;
   bson_t tmp;
   bool res;

   BSON_ASSERT (decryptor);
   status = decryptor->status;

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION)) {
      goto done;
   }

   /* TODO testing, remove */
   if (!decryptor->encrypted_doc) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED;
      res = true;
      goto done;
   }

   mongocrypt_binary_to_bson (decryptor->encrypted_doc, &tmp);
   bson_iter_init (&iter, &tmp);

   /* TODO: move transform_binary out of mongocrypt-private.h */
   res = _mongocrypt_transform_binary_in_bson (
      _replace_ciphertext_with_plaintext, decryptor, 1, iter, &out, status);

   if (!res) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_ERROR;
      goto done;
   }

   decryptor->decrypted_doc->data =
      bson_destroy_with_steal (&out, true, &decryptor->decrypted_doc->len);
   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED;

done:
   return decryptor->state;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_state (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   return decryptor->state;
}


mongocrypt_status_t *
mongocrypt_decryptor_status (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   return decryptor->status;
}


mongocrypt_binary_t *
mongocrypt_decryptor_decrypted_doc (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION)) {
      return NULL;
   }

   return decryptor->decrypted_doc;
}


void
mongocrypt_decryptor_destroy (mongocrypt_decryptor_t *decryptor)
{
   if (!decryptor) {
      return;
   }

   mongocrypt_binary_destroy (decryptor->encrypted_doc);
   mongocrypt_binary_destroy (decryptor->filter);
   mongocrypt_status_destroy (decryptor->status);
   _mongocrypt_key_broker_cleanup (&decryptor->kb);

   mongocrypt_binary_destroy (decryptor->decrypted_doc);

   bson_free (decryptor);
}
