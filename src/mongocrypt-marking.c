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
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-marking-private.h"

bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status)
{
   bson_t bson;
   bson_iter_t iter;
   bool ret = false;
   int algorithm;

   if (in->len < 5) {
      CLIENT_ERR ("invalid marking, length < 5");
      goto cleanup;
   }

   /* Confirm that this is indeed a marking */
   if (in->data[0] != 0) {
      CLIENT_ERR ("invalid marking, first byte must be 0");
      goto cleanup;
   }

   _mongocrypt_marking_init (out);

   bson_init_static (&bson, in->data + 1, in->len - 1);

   if (bson_iter_init_find (&iter, &bson, "ki")) {
      if (!_mongocrypt_buffer_from_uuid_iter (&out->key_id, &iter)) {
         CLIENT_ERR ("key id must be a UUID");
         goto cleanup;
      }
   } else if (bson_iter_init_find (&iter, &bson, "ka")) {
      /* Some bson_value types are not allowed to be key alt names */
      const bson_value_t *value;
      bson_type_t type;

      value = bson_iter_value (&iter);
      type = value->value_type;

      if (type != BSON_TYPE_UTF8) {
         CLIENT_ERR ("unsupported key alt name type");
         goto cleanup;
      }

      /* CDRIVER-3100 We must make a copy of this value;
    the result of bson_iter_value is ephemeral. */
      bson_value_copy (value, &out->key_alt_name);
      out->has_alt_name = true;
   } else {
      CLIENT_ERR ("marking must include 'ki' or 'ka'");
      goto cleanup;
   }

   if (bson_iter_init_find (&iter, &bson, "iv")) {
      if (!_mongocrypt_buffer_from_binary_iter (&out->iv, &iter)) {
         CLIENT_ERR ("invalid marking, 'iv' is not binary");
         goto cleanup;
      }

      if (out->iv.len != 16) {
         CLIENT_ERR ("iv must be 16 bytes");
         goto cleanup;
      }
   }

   if (!bson_iter_init_find (&iter, &bson, "v")) {
      CLIENT_ERR ("invalid marking, no 'v'");
      goto cleanup;
   }
   memcpy (&out->v_iter, &iter, sizeof (bson_iter_t));

   if (!bson_iter_init_find (&iter, &bson, "a")) {
      CLIENT_ERR ("invalid marking, no 'a'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_INT32 (&iter)) {
      CLIENT_ERR ("invalid marking, 'a' must be an integer");
      goto cleanup;
   }

   algorithm = bson_iter_int32 (&iter);
   switch (algorithm) {
   case 1:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;
      if (_mongocrypt_buffer_empty (&out->iv)) {
         CLIENT_ERR ("deterministic algorithm specified, but no iv present");
         goto cleanup;
      }
      break;
   case 2:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM;
      if (!_mongocrypt_buffer_empty (&out->iv)) {
         CLIENT_ERR ("randomized algorithm specified, but iv present");
         goto cleanup;
      }
      break;
   default:
      CLIENT_ERR ("invalid algorithm value %d", algorithm);
      goto cleanup;
   }

   ret = true;
cleanup:
   return ret;
}


void
_mongocrypt_marking_init (_mongocrypt_marking_t *marking)
{
   memset (marking, 0, sizeof (*marking));
}


void
_mongocrypt_marking_cleanup (_mongocrypt_marking_t *marking)
{
   bson_value_destroy (&marking->key_alt_name);
   _mongocrypt_buffer_cleanup (&marking->iv);
   _mongocrypt_buffer_cleanup (&marking->key_id);
}


bool
_mongocrypt_marking_to_ciphertext (void *ctx,
                                   _mongocrypt_marking_t *marking,
                                   _mongocrypt_ciphertext_t *ciphertext,
                                   mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t plaintext = {0};
   _mongocrypt_buffer_t iv = {0};
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_buffer_t key_material;
   bool ret = false;
   bool key_found;
   uint32_t bytes_written;

   BSON_ASSERT (marking);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);
   BSON_ASSERT (ctx);

   kb = (_mongocrypt_key_broker_t *) ctx;

   _mongocrypt_ciphertext_init (ciphertext);
   ciphertext->original_bson_type = (uint8_t) bson_iter_type (&marking->v_iter);

   /* Get the decrypted key for this marking. */
   if (marking->has_alt_name) {
      key_found = _mongocrypt_key_broker_decrypted_key_by_name (
         kb, &marking->key_alt_name, &key_material);
   } else if (!_mongocrypt_buffer_empty (&marking->key_id)) {
      key_found = _mongocrypt_key_broker_decrypted_key_by_id (
         kb, &marking->key_id, &key_material);
   } else {
      CLIENT_ERR ("marking must have either key_id or key_alt_name");
      goto fail;
   }

   if (!key_found) {
      _mongocrypt_status_copy_to (kb->status, status);
      goto fail;
   }

   _mongocrypt_buffer_from_iter (&plaintext, &marking->v_iter);
   ciphertext->data.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext->data.data = bson_malloc (ciphertext->data.len);
   ciphertext->data.owned = true;

   switch (marking->algorithm) {
   case MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC:
      /* Use deterministic encryption.
       * In this case, we can use the iv parsed out of the marking. */
      ret = _mongocrypt_do_encryption (&marking->iv,
                                       NULL,
                                       &key_material,
                                       &plaintext,
                                       &ciphertext->data,
                                       &bytes_written,
                                       status);
      break;
   case MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM:
      /* Use randomized encryption.
       * In this case, we must generate a new, random iv. */
      _mongocrypt_buffer_resize (&iv, MONGOCRYPT_IV_LEN);
      _mongocrypt_random (&iv, status, MONGOCRYPT_IV_LEN);
      ret = _mongocrypt_do_encryption (&iv,
                                       NULL,
                                       &key_material,
                                       &plaintext,
                                       &ciphertext->data,
                                       &bytes_written,
                                       status);
      break;
   default:
      /* Error. */
      CLIENT_ERR ("Unsupported value for encryption algorithm");
      goto fail;
   }

   if (!ret) {
      goto fail;
   }

   ciphertext->blob_subtype = marking->algorithm;

   BSON_ASSERT (bytes_written == ciphertext->data.len);

   _mongocrypt_buffer_copy_to (&marking->key_id, &ciphertext->key_id);

   ret = true;

fail:
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&plaintext);
   return ret;
}
