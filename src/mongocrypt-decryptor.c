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
   const char *state_names[] = {"ERROR",
                                "NEED_DOC",
                                "NEED_KEYS",
                                "NEED_DECRYPTION",
                                "NO_DECRYPTION_NEEDED",
                                "DECRYPTED"};

   status = decryptor->status;

   if (decryptor->state != state) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_ERROR;
      CLIENT_ERR ("Expected state %s, but in state %s",
                  state_names[state],
                  state_names[decryptor->state]);
      return false;
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
bool
_mongocrypt_decryptor_parse_ciphertext_unowned (
   _mongocrypt_buffer_t *in,
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

mongocrypt_decryptor_t *
mongocrypt_decryptor_new (mongocrypt_t *crypt)
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
_collect_key_from_ciphertext (void *ctx, _mongocrypt_buffer_t *in)
{
   _mongocrypt_ciphertext_t ciphertext;
   mongocrypt_decryptor_t *decryptor;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);

   decryptor = (mongocrypt_decryptor_t *) ctx;

   if (!_mongocrypt_decryptor_parse_ciphertext_unowned (
          in, &ciphertext, decryptor->status)) {
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (&decryptor->kb, &ciphertext.key_id)) {
      mongocrypt_status_copy_to (decryptor->kb.status, decryptor->status);
      return false;
   }

   return true;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_add_doc (mongocrypt_decryptor_t *decryptor,
                              mongocrypt_binary_t *encrypted_doc)
{
   mongocrypt_status_t *status;
   bson_iter_t iter;
   bson_t tmp;
   _mongocrypt_buffer_t encrypted_buf;

   BSON_ASSERT (decryptor);
   status = decryptor->status;

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC)) {
      goto done;
   }

   if (!encrypted_doc) {
      CLIENT_ERR ("malformed document");
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_ERROR;
      goto done;
   }

   _mongocrypt_buffer_from_binary (&encrypted_buf, encrypted_doc);
   _mongocrypt_buffer_to_bson (&encrypted_buf, &tmp);
   bson_iter_init (&iter, &tmp);

   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_ciphertext,
                                             (void *) decryptor,
                                             TRAVERSE_MATCH_CIPHERTEXT,
                                             &iter,
                                             decryptor->status)) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_ERROR;
      goto done;
   }

   if (_mongocrypt_key_broker_empty (&decryptor->kb)) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED;
   } else {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS;
      /* Copy the encrypted doc. We'll need it later during decryption. */
      _mongocrypt_buffer_copy_to (&encrypted_buf, &decryptor->encrypted_doc);
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
      _mongocrypt_log (&decryptor->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Some keys are still encrypted, the decryptor"
                       "can only partially decrypt this document.");
   }

   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION;

   return decryptor->state;
}

static bool
_replace_ciphertext_with_plaintext (void *ctx,
                                    _mongocrypt_buffer_t *in,
                                    bson_value_t *out)
{
   mongocrypt_decryptor_t *decryptor;
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t plaintext = {0};
   const _mongocrypt_buffer_t *key_material;
   bson_t wrapper;
   bson_iter_t iter;
   uint32_t bytes_written;
   bool ret = false;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);

   decryptor = (mongocrypt_decryptor_t *) ctx;

   if (!_mongocrypt_decryptor_parse_ciphertext_unowned (
          in, &ciphertext, decryptor->status)) {
      goto fail;
   }

   /* look up the key */
   key_material = _mongocrypt_key_broker_decrypted_key_material_by_id (
      &decryptor->kb, &ciphertext.key_id);
   if (!key_material) {
      /* We allow partial decryption, so this is not an error. */
      _mongocrypt_log (&decryptor->crypt->log,
                       MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Missing key, skipping decryption for this ciphertext");
      mongocrypt_status_reset (decryptor->kb.status);
      ret = true;
      goto fail;
   }

   plaintext.len = ciphertext.data.len;
   plaintext.data = bson_malloc0 (plaintext.len);
   plaintext.owned = true;

   if (!_mongocrypt_do_decryption (NULL,
                                   key_material,
                                   &ciphertext.data,
                                   &plaintext,
                                   &bytes_written,
                                   decryptor->status)) {
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
   if (_mongocrypt_buffer_empty (&decryptor->encrypted_doc)) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED;
      res = true;
      goto done;
   }

   _mongocrypt_buffer_to_bson (&decryptor->encrypted_doc, &tmp);
   bson_iter_init (&iter, &tmp);

   /* TODO: move transform_binary out of mongocrypt-private.h */
   res =
      _mongocrypt_transform_binary_in_bson (_replace_ciphertext_with_plaintext,
                                            decryptor,
                                            TRAVERSE_MATCH_CIPHERTEXT,
                                            &iter,
                                            &out,
                                            status);

   if (!res) {
      decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_ERROR;
      goto done;
   }

   _mongocrypt_buffer_steal_from_bson (&decryptor->decrypted_doc, &out);
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


bool
mongocrypt_decryptor_status (mongocrypt_decryptor_t *decryptor,
                             mongocrypt_status_t *out)
{
   BSON_ASSERT (decryptor);

   if (!mongocrypt_status_ok (decryptor->status)) {
      mongocrypt_status_copy_to (decryptor->status, out);
      return false;
   }
   mongocrypt_status_reset (out);
   return true;
}


mongocrypt_binary_t *
mongocrypt_decryptor_decrypted_doc (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   if (!_check_state (decryptor, MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED)) {
      return NULL;
   }

   return _mongocrypt_buffer_to_binary (&decryptor->decrypted_doc);
}


void
mongocrypt_decryptor_destroy (mongocrypt_decryptor_t *decryptor)
{
   if (!decryptor) {
      return;
   }

   _mongocrypt_buffer_cleanup (&decryptor->decrypted_doc);
   mongocrypt_status_destroy (decryptor->status);
   _mongocrypt_key_broker_cleanup (&decryptor->kb);

   bson_free (decryptor);
}
