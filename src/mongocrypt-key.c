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

   /* keyAltName (optional) */
   if (bson_iter_init_find (&iter, bson, "keyAltNames")) {
      /* CDRIVER-3100 We must make a copy here */
      bson_value_copy (bson_iter_value (&iter), &out->key_alt_names);
      out->has_alt_names = true;
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


_mongocrypt_key_doc_t *
_mongocrypt_key_new ()
{
   _mongocrypt_key_doc_t *key_doc;

   key_doc = (_mongocrypt_key_doc_t *) bson_malloc0 (sizeof *key_doc);

   return key_doc;
}


bool
_mongocrypt_key_equal (const _mongocrypt_key_doc_t *a,
                       const _mongocrypt_key_doc_t *b)
{
   if (_mongocrypt_buffer_cmp (&a->id, &b->id) != 0) {
      return false;
   }

   if (a->has_alt_names != b->has_alt_names) {
      return false;
   }

   if (a->has_alt_names) {
      BSON_ASSERT (a->key_alt_names.value_type == BSON_TYPE_UTF8);
      BSON_ASSERT (b->key_alt_names.value_type == BSON_TYPE_UTF8);
      if (0 != strcmp (a->key_alt_names.value.v_utf8.str,
                       b->key_alt_names.value.v_utf8.str)) {
         return false;
      }
   }

   if (0 != _mongocrypt_buffer_cmp (&a->key_material, &b->key_material)) {
      return false;
   }

   if (a->masterkey_provider != b->masterkey_provider) {
      return false;
   }

   if (0 != strcmp (a->masterkey_region, b->masterkey_region)) {
      return false;
   }

   if (a->masterkey_cmk && b->masterkey_cmk) {
      if (0 != strcmp (a->masterkey_cmk, b->masterkey_cmk)) {
         return false;
      }
   }

   return true;
}


void
_mongocrypt_key_destroy (_mongocrypt_key_doc_t *key)
{
   if (!key) {
      return;
   }

   _mongocrypt_buffer_cleanup (&key->id);
   if (key->has_alt_names) {
      bson_value_destroy (&key->key_alt_names);
   }
   _mongocrypt_buffer_cleanup (&key->key_material);
   bson_free (key->masterkey_region);
   bson_free (key->masterkey_cmk);
   bson_free (key);
}


void
_mongocrypt_key_doc_copy_to (_mongocrypt_key_doc_t *src,
                             _mongocrypt_key_doc_t *dst)
{
   BSON_ASSERT (src);
   BSON_ASSERT (dst);

   _mongocrypt_buffer_copy_to (&src->id, &dst->id);
   _mongocrypt_buffer_copy_to (&src->key_material, &dst->key_material);
   dst->masterkey_provider = src->masterkey_provider;
   dst->masterkey_region = bson_strdup (src->masterkey_region);
   dst->masterkey_cmk = bson_strdup (src->masterkey_cmk);
}
