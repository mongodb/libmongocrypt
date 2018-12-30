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

#include <mongoc/mongoc.h>
#include "mongocrypt-private.h"

/* TODO: be very careful. Audit this.
 * Consider if copying is potentially worth the easier debuggability?
 * I think the marking + encrypted parse should explicitly say "unowned".
 * Parsing does not copy, but requires the BSON to be around.
 */

/* TODO: actually make this code consistent. */
void
mongoc_crypt_binary_from_iter_unowned (bson_iter_t *iter, mongoc_crypt_binary_t *out)
{
   bson_iter_binary (iter, &out->subtype, &out->len, (const uint8_t**)&out->data);
   out->owned = false;
}


/* copies */
void
mongoc_crypt_binary_from_iter (bson_iter_t *iter, mongoc_crypt_binary_t *out) {
   const uint8_t* data;
   bson_iter_binary (iter, &out->subtype, &out->len, &data);
   out->data = bson_malloc(out->len);
   memcpy(out->data, data, out->len);
   out->owned = true;
}


void
mongoc_crypt_binary_cleanup (mongoc_crypt_binary_t* binary) {
   if (binary->owned) {
      bson_free (binary->data);
   }
}


void
mongoc_crypt_bson_append_binary (bson_t *bson,
                                 const char *key,
                                 uint32_t key_len,
                                 mongoc_crypt_binary_t *in)
{
   bson_append_binary (bson, key, key_len, in->subtype, in->data, in->len);
}


/* out should be zeroed */
bool
_mongoc_crypt_marking_parse_unowned (const bson_t *bson,
                             mongoc_crypt_marking_t *out,
                             mongoc_crypt_error_t *error)
{
   bson_iter_t iter;
   bool ret = false;

   if (!bson_iter_init_find (&iter, bson, "k")) {
      SET_CRYPT_ERR ("invalid marking, no 'k'");
      goto cleanup;
   } else if (BSON_ITER_HOLDS_UTF8 (&iter)) {
      out->key_alt_name = bson_iter_utf8 (&iter, NULL);
   } else if (BSON_ITER_HOLDS_BINARY (&iter)) {
      mongoc_crypt_binary_from_iter_unowned (&iter, &out->key_id);
      if (out->key_id.subtype != BSON_SUBTYPE_UUID) {
         SET_CRYPT_ERR ("key id must be a UUID");
         goto cleanup;
      }
   } else {
      SET_CRYPT_ERR ("invalid marking, no 'k' is not utf8 or UUID");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, bson, "iv")) {
      SET_CRYPT_ERR ("'iv' not part of marking. C driver does not support "
                     "generating iv yet. (TODO)");
      goto cleanup;
   } else if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      SET_CRYPT_ERR ("invalid marking, 'iv' is not binary");
      goto cleanup;
   }
   mongoc_crypt_binary_from_iter_unowned (&iter, &out->iv);

   if (out->iv.len != 16) {
      SET_CRYPT_ERR ("iv must be 16 bytes");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, bson, "v")) {
      SET_CRYPT_ERR ("invalid marking, no 'v'");
      goto cleanup;
   } else {
      memcpy (&out->v_iter, &iter, sizeof (bson_iter_t));
   }

   /* TODO: parse "a" and "u" */

   ret = true;
cleanup:
   return ret;
}


bool
_mongoc_crypt_encrypted_parse_unowned (const bson_t *bson,
                               mongoc_crypt_encrypted_t *out,
                               mongoc_crypt_error_t *error)
{
   bson_iter_t iter;
   bool ret = false;

   if (!bson_iter_init_find (&iter, bson, "k")) {
      SET_CRYPT_ERR ("invalid marking, no 'k'");
      goto cleanup;
   } else if (BSON_ITER_HOLDS_BINARY (&iter)) {
      mongoc_crypt_binary_from_iter_unowned (&iter, &out->key_id);
      if (out->key_id.subtype != BSON_SUBTYPE_UUID) {
         SET_CRYPT_ERR ("key id must be a UUID");
         goto cleanup;
      }
   } else {
      SET_CRYPT_ERR ("invalid marking, no 'k' is not UUID");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, bson, "iv")) {
      SET_CRYPT_ERR ("'iv' not part of marking. C driver does not support "
                     "generating iv yet. (TODO)");
      goto cleanup;
   } else if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      SET_CRYPT_ERR ("invalid marking, 'iv' is not binary");
      goto cleanup;
   }
   mongoc_crypt_binary_from_iter_unowned (&iter, &out->iv);

   if (out->iv.len != 16) {
      SET_CRYPT_ERR ("iv must be 16 bytes");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, bson, "e")) {
      SET_CRYPT_ERR ("invalid marking, no 'e'");
      goto cleanup;
   } else {
      mongoc_crypt_binary_from_iter (&iter, &out->e);
   }

   ret = true;
cleanup:
   return ret;
}


/* Takes ownership of all fields. */
bool
_mongoc_crypt_key_parse (const bson_t *bson,
                         mongoc_crypt_key_t *out,
                         mongoc_crypt_error_t *error)
{
   bson_iter_t iter;
   bool ret = false;

   if (!bson_iter_init_find (&iter, bson, "_id")) {
      SET_CRYPT_ERR ("invalid key, no '_id'");
      goto cleanup;
   } else if (BSON_ITER_HOLDS_BINARY (&iter)) {
      mongoc_crypt_binary_from_iter (&iter, &out->id);
      if (out->id.subtype != BSON_SUBTYPE_UUID) {
         SET_CRYPT_ERR ("key id must be a UUID");
         goto cleanup;
      }
   } else {
      SET_CRYPT_ERR ("invalid key, no 'k' is not binary");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, bson, "keyMaterial")) {
      SET_CRYPT_ERR ("invalid key, no 'keyMaterial'");
      goto cleanup;
   } else if (BSON_ITER_HOLDS_BINARY (&iter)) {
      mongoc_crypt_binary_from_iter (&iter, &out->key_material);
      if (out->key_material.subtype != BSON_SUBTYPE_BINARY) {
         SET_CRYPT_ERR ("key material must be a binary");
         goto cleanup;
      }
   } else {
      SET_CRYPT_ERR ("invalid key material is not binary");
      goto cleanup;
   }

   ret = true;
cleanup:
   return ret;
}

void
mongoc_crypt_key_cleanup (mongoc_crypt_key_t* key) {
   mongoc_crypt_binary_cleanup (&key->id);
   mongoc_crypt_binary_cleanup (&key->key_material);
   mongoc_crypt_binary_cleanup (&key->data_key);
}