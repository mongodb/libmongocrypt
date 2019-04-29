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
      if (!BSON_ITER_HOLDS_BINARY (&iter)) {
         CLIENT_ERR ("key id must be a binary type");
      }
      _mongocrypt_buffer_from_iter (&out->key_id, &iter);
      if (out->key_id.subtype != BSON_SUBTYPE_UUID) {
         CLIENT_ERR ("key id must be a UUID");
         goto cleanup;
      }
   } else if (bson_iter_init_find (&iter, &bson, "ka")) {
      out->key_alt_name = bson_iter_value (&iter);
   } else {
      CLIENT_ERR ("marking must include 'ki' or 'ka'");
      goto cleanup;
   }

   /* CDRIVER-3097 fix this for randomized encryption */
   if (!bson_iter_init_find (&iter, &bson, "iv")) {
      CLIENT_ERR ("'iv' not part of marking. C driver does not support "
                  "generating iv yet. (TODO)");
      goto cleanup;
   } else if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      CLIENT_ERR ("invalid marking, 'iv' is not binary");
      goto cleanup;
   }
   _mongocrypt_buffer_from_iter (&out->iv, &iter);

   if (out->iv.len != 16) {
      CLIENT_ERR ("iv must be 16 bytes");
      goto cleanup;
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
   case 0:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE;
      break;
   case 1:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;
      break;
   case 2:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM;
      break;
   default:
      CLIENT_ERR ("invalid algorithm value %d", algorithm);
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
   _mongocrypt_buffer_cleanup (&marking->iv);
   _mongocrypt_buffer_cleanup (&marking->key_id);
}

void
_set_plaintext (_mongocrypt_buffer_t *plaintext, bson_iter_t *iter)
{
   bson_t wrapper = BSON_INITIALIZER;
   int32_t offset = INT32_LEN        /* skips document size */
                    + TYPE_LEN       /* element type */
                    + NULL_BYTE_LEN; /* and the key's null byte terminator */

   uint8_t *wrapper_data = ((uint8_t *) bson_get_data (&wrapper));

   bson_append_iter (&wrapper, "", 0, iter);
   plaintext->len =
      wrapper.len - offset - NULL_BYTE_LEN; /* the final null byte */
   plaintext->data = bson_malloc (plaintext->len);
   plaintext->owned = true;
   memcpy (plaintext->data, wrapper_data + offset, plaintext->len);
   bson_destroy (&wrapper);
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
   uint32_t bytes_written;

   BSON_ASSERT (marking);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);
   BSON_ASSERT (ctx);

   kb = (_mongocrypt_key_broker_t *) ctx;

   if (marking->key_alt_name) {
      CLIENT_ERR ("TODO looking up key by keyAltName not yet supported");
      goto fail;
   }

   _mongocrypt_ciphertext_init (ciphertext);
   ciphertext->original_bson_type = (uint8_t) bson_iter_type (&marking->v_iter);

   /* get the key for this marking. */
   if (!_mongocrypt_key_broker_decrypted_key_material_by_id (
          kb, &marking->key_id, &key_material)) {
      _mongocrypt_status_copy_to (kb->status, status);
      goto fail;
   }

   _set_plaintext (&plaintext, &marking->v_iter);
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
