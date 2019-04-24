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
#include "mongocrypt-key-private.h"

/* Takes ownership of all fields. */
bool
_mongocrypt_key_parse_owned (const bson_t *bson,
                             _mongocrypt_key_doc_t *out,
                             mongocrypt_status_t *status)
{
   bson_iter_t iter, subiter;
   bool ret = false;

   memset (out, 0, sizeof (_mongocrypt_key_doc_t));

   /* _id */
   if (!bson_iter_init_find (&iter, bson, "_id")) {
      CLIENT_ERR ("invalid key, no '_id'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      CLIENT_ERR ("invalid key, 'k' is not binary");
      goto cleanup;
   }

   _mongocrypt_buffer_copy_from_iter (&out->id, &iter);
   if (out->id.subtype != BSON_SUBTYPE_UUID) {
      CLIENT_ERR ("key id must be a UUID");
      goto cleanup;
   }

   /* keyMaterial */
   if (!bson_iter_init_find (&iter, bson, "keyMaterial")) {
      CLIENT_ERR ("invalid key, no 'keyMaterial'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      CLIENT_ERR ("invalid key material is not binary");
      goto cleanup;
   }

   _mongocrypt_buffer_copy_from_iter (&out->key_material, &iter);
   if (out->key_material.subtype != BSON_SUBTYPE_BINARY) {
      CLIENT_ERR ("key material must be a binary");
      goto cleanup;
   }

   /* masterKey */
   if (!bson_iter_init_find (&iter, bson, "masterKey")) {
      CLIENT_ERR ("invalid key, no 'masterKey'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
      CLIENT_ERR ("invalid 'masterKey', expected document");
      goto cleanup;
   }

   if (!bson_iter_recurse (&iter, &subiter)) {
      CLIENT_ERR ("invalid 'masterKey', malformed BSON");
      goto cleanup;
   }

   if (!bson_iter_find (&subiter, "provider")) {
      CLIENT_ERR ("invalid 'masterKey', expected 'provider'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
      CLIENT_ERR ("invalid 'masterKey.provider', expected string");
      goto cleanup;
   }

   if (0 == strcmp (bson_iter_utf8 (&subiter, NULL), "aws")) {
      out->masterkey_provider = MONGOCRYPT_KMS_PROVIDER_AWS;
   } else if (0 == strcmp (bson_iter_utf8 (&subiter, NULL), "local")) {
      out->masterkey_provider = MONGOCRYPT_KMS_PROVIDER_LOCAL;
   } else {
      CLIENT_ERR ("invalid 'masterKey.provider', expected 'aws' or 'local'");
      goto cleanup;
   }

   if (!bson_iter_recurse (&iter, &subiter)) {
      CLIENT_ERR ("invalid 'masterKey', malformed BSON");
      goto cleanup;
   }
   if (bson_iter_find (&subiter, "region")) {
      if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
         CLIENT_ERR ("invalid 'masterKey.region', expected string");
         goto cleanup;
      }
      out->masterkey_region = bson_strdup (bson_iter_utf8 (&subiter, NULL));
   }


   ret = true;
cleanup:
   return ret;
}


void
_mongocrypt_key_cleanup (_mongocrypt_key_doc_t *key)
{
   _mongocrypt_buffer_cleanup (&key->id);
   _mongocrypt_buffer_cleanup (&key->key_material);
   bson_free (key->masterkey_region);
}
