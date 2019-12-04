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
   bool has_ki = false, has_ka = false, has_a = false, has_v = false;

   _mongocrypt_marking_init (out);

   if (in->len < 5) {
      CLIENT_ERR ("invalid marking, length < 5");
      return false;
   }

   if (in->data[0] != 0) {
      CLIENT_ERR ("invalid marking, first byte must be 0");
      return false;
   }

   if (!bson_init_static (&bson, in->data + 1, in->len - 1)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   if (!bson_validate (&bson, BSON_VALIDATE_NONE, NULL) ||
       !bson_iter_init (&iter, &bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   while (bson_iter_next (&iter)) {
      const char *field;

      field = bson_iter_key (&iter);
      BSON_ASSERT (field);
      if (0 == strcmp ("ki", field)) {
         has_ki = true;
         if (!_mongocrypt_buffer_from_uuid_iter (&out->key_id, &iter)) {
            CLIENT_ERR ("key id must be a UUID");
            return false;
         }
         continue;
      }

      if (0 == strcmp ("ka", field)) {
         has_ka = true;
         /* Some bson_value types are not allowed to be key alt names */
         const bson_value_t *value;

         value = bson_iter_value (&iter);

         if (!BSON_ITER_HOLDS_UTF8 (&iter)) {
            CLIENT_ERR ("key alt name must be a UTF8");
            return false;
         }
         /* CDRIVER-3100 We must make a copy of this value; the result of
          * bson_iter_value is ephemeral. */
         bson_value_copy (value, &out->key_alt_name);
         out->has_alt_name = true;
         continue;
      }

      if (0 == strcmp ("v", field)) {
         has_v = true;
         memcpy (&out->v_iter, &iter, sizeof (bson_iter_t));
         continue;
      }


      if (0 == strcmp ("a", field)) {
         int32_t algorithm;

         has_a = true;
         if (!BSON_ITER_HOLDS_INT32 (&iter)) {
            CLIENT_ERR ("invalid marking, 'a' must be an int32");
            return false;
         }
         algorithm = bson_iter_int32 (&iter);
         if (algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC &&
             algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM) {
            CLIENT_ERR ("invalid algorithm value: %d", algorithm);
            return false;
         }
         out->algorithm = (mongocrypt_encryption_algorithm_t) algorithm;
         continue;
      }

      CLIENT_ERR ("unrecognized field '%s'", field);
      return false;
   }

   if (!has_v) {
      CLIENT_ERR ("no 'v' specified");
      return false;
   }

   if (!has_ki && !has_ka) {
      CLIENT_ERR ("neither 'ki' nor 'ka' specified");
      return false;
   }

   if (has_ki && has_ka) {
      CLIENT_ERR ("both 'ki' and 'ka' specified");
      return false;
   }

   if (!has_a) {
      CLIENT_ERR ("no 'a' specified");
      return false;
   }

   return true;
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
   _mongocrypt_buffer_cleanup (&marking->key_id);
}


bool
_mongocrypt_marking_to_ciphertext (void *ctx,
                                   _mongocrypt_marking_t *marking,
                                   _mongocrypt_ciphertext_t *ciphertext,
                                   mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t plaintext;
   _mongocrypt_buffer_t iv;
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_buffer_t associated_data;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_buffer_t key_id;
   bool ret = false;
   bool key_found;
   uint32_t bytes_written;

   BSON_ASSERT (marking);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);
   BSON_ASSERT (ctx);

   _mongocrypt_buffer_init (&plaintext);
   _mongocrypt_buffer_init (&associated_data);
   _mongocrypt_buffer_init (&iv);
   _mongocrypt_buffer_init (&key_id);
   _mongocrypt_buffer_init (&key_material);

   kb = (_mongocrypt_key_broker_t *) ctx;

   /* Get the decrypted key for this marking. */
   if (marking->has_alt_name) {
      key_found = _mongocrypt_key_broker_decrypted_key_by_name (
         kb, &marking->key_alt_name, &key_material, &key_id);
   } else if (!_mongocrypt_buffer_empty (&marking->key_id)) {
      key_found = _mongocrypt_key_broker_decrypted_key_by_id (
         kb, &marking->key_id, &key_material);
      _mongocrypt_buffer_copy_to (&marking->key_id, &key_id);
   } else {
      CLIENT_ERR ("marking must have either key_id or key_alt_name");
      goto fail;
   }

   if (!key_found) {
      _mongocrypt_status_copy_to (kb->status, status);
      goto fail;
   }

   _mongocrypt_ciphertext_init (ciphertext);
   ciphertext->original_bson_type = (uint8_t) bson_iter_type (&marking->v_iter);
   ciphertext->blob_subtype = marking->algorithm;
   _mongocrypt_buffer_copy_to (&key_id, &ciphertext->key_id);
   if (!_mongocrypt_ciphertext_serialize_associated_data (ciphertext,
                                                          &associated_data)) {
      CLIENT_ERR ("could not serialize associated data");
      goto fail;
   }

   _mongocrypt_buffer_from_iter (&plaintext, &marking->v_iter);
   ciphertext->data.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext->data.data = bson_malloc (ciphertext->data.len);
   BSON_ASSERT (ciphertext->data.data);

   ciphertext->data.owned = true;

   switch (marking->algorithm) {
   case MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC:
      /* Use deterministic encryption. */
      _mongocrypt_buffer_resize (&iv, MONGOCRYPT_IV_LEN);
      ret = _mongocrypt_calculate_deterministic_iv (kb->crypt->crypto,
                                                    &key_material,
                                                    &plaintext,
                                                    &associated_data,
                                                    &iv,
                                                    status);
      if (!ret) {
         goto fail;
      }

      ret = _mongocrypt_do_encryption (kb->crypt->crypto,
                                       &iv,
                                       &associated_data,
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
      if (!_mongocrypt_random (
             kb->crypt->crypto, &iv, MONGOCRYPT_IV_LEN, status)) {
         goto fail;
      }
      ret = _mongocrypt_do_encryption (kb->crypt->crypto,
                                       &iv,
                                       &associated_data,
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

   BSON_ASSERT (bytes_written == ciphertext->data.len);

   ret = true;

fail:
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&key_id);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&key_material);
   return ret;
}
