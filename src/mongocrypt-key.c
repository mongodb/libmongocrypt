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

static bool
_parse_masterkey (bson_iter_t *iter,
                  _mongocrypt_key_doc_t *out,
                  mongocrypt_status_t *status)
{
   bson_iter_t subiter;
   bool has_cmk = false, has_region = false, has_provider = false;

   if (!BSON_ITER_HOLDS_DOCUMENT (iter)) {
      CLIENT_ERR ("invalid 'masterKey', expected document");
      return false;
   }

   if (!bson_iter_recurse (iter, &subiter)) {
      CLIENT_ERR ("invalid 'masterKey', malformed BSON");
      return false;
   }

   while (bson_iter_next (&subiter)) {
      const char *field;

      field = bson_iter_key (&subiter);
      if (0 == strcmp ("provider", field)) {
         const char *provider;

         has_provider = true;
         if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
            CLIENT_ERR ("invalid 'masterKey.provider', expected string");
            return false;
         }
         provider = bson_iter_utf8 (&subiter, NULL);
         if (0 == strcmp (provider, "aws")) {
            out->masterkey_provider = MONGOCRYPT_KMS_PROVIDER_AWS;
         } else if (0 == strcmp (provider, "local")) {
            out->masterkey_provider = MONGOCRYPT_KMS_PROVIDER_LOCAL;
         } else {
            CLIENT_ERR (
               "invalid 'masterKey.provider', expected 'aws' or 'local'");
            return false;
         }
         continue;
      }

      if (0 == strcmp ("region", field)) {
         has_region = true;
         if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
            CLIENT_ERR ("invalid 'masterKey.region', expected string");
            return false;
         }
         out->masterkey_region = bson_strdup (bson_iter_utf8 (&subiter, NULL));
         continue;
      }

      if (0 == strcmp ("key", field)) {
         /* Don't need the CMK. Check that it's present and ignore it. */
         has_cmk = true;
         continue;
      }

      if (0 == strcmp ("endpoint", field)) {
         if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
            CLIENT_ERR ("invalid 'masterKey.endpoint', expected string");
            return false;
         }
         out->endpoint = bson_strdup (bson_iter_utf8 (&subiter, NULL));
         continue;
      }

      CLIENT_ERR ("unrecognized provider field '%s'", field);
      return false;
   }

   /* Check that required fields were set. */
   if (!has_provider) {
      CLIENT_ERR ("invalid 'masterKey', no 'provider'");
      return false;
   }

   if (out->masterkey_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      if (!has_region) {
         CLIENT_ERR ("invalid 'masterKey', no 'region'");
         return false;
      }

      if (!has_cmk) {
         CLIENT_ERR ("invalid 'masterKey', no 'key'");
         return false;
      }
   }
   return true;
}

/* Takes ownership of all fields. */
bool
_mongocrypt_key_parse_owned (const bson_t *bson,
                             _mongocrypt_key_doc_t *out,
                             mongocrypt_status_t *status)
{
   bson_iter_t iter;
   bool has_id = false, has_key_material = false, has_status = false,
        has_creation_date = false, has_update_date = false,
        has_master_key = false;

   memset (out, 0, sizeof (_mongocrypt_key_doc_t));

   if (!bson_validate (bson, BSON_VALIDATE_NONE, NULL) ||
       !bson_iter_init (&iter, bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   while (bson_iter_next (&iter)) {
      const char *field;

      field = bson_iter_key (&iter);
      if (0 == strcmp ("_id", field)) {
         has_id = true;
         if (!_mongocrypt_buffer_copy_from_uuid_iter (&out->id, &iter)) {
            CLIENT_ERR ("invalid key, '_id' is not a UUID");
            return false;
         }
         continue;
      }

      /* keyAltName (optional) */
      if (0 == strcmp ("keyAltNames", field)) {
         /* CDRIVER-3100 We must make a copy here */
         bson_value_copy (bson_iter_value (&iter), &out->key_alt_names);
         out->has_alt_names = true;
      }

      if (0 == strcmp ("keyMaterial", field)) {
         has_key_material = true;
         if (!_mongocrypt_buffer_copy_from_binary_iter (&out->key_material,
                                                        &iter)) {
            CLIENT_ERR ("invalid 'keyMaterial', expected binary");
            return false;
         }
         if (out->key_material.subtype != BSON_SUBTYPE_BINARY) {
            CLIENT_ERR ("invalid 'keyMaterial', expected subtype 0");
            return false;
         }
         continue;
      }

      if (0 == strcmp ("masterKey", field)) {
         has_master_key = true;
         if (!_parse_masterkey (&iter, out, status)) {
            return false;
         }
         continue;
      }

      if (0 == strcmp ("version", field)) {
         if (!BSON_ITER_HOLDS_INT (&iter)) {
            CLIENT_ERR ("invalid 'version', expect int");
            return false;
         }
         if (bson_iter_as_int64 (&iter) != 0) {
            CLIENT_ERR (
               "unsupported key document version, only supports version=0");
            return false;
         }
         continue;
      }

      if (0 == strcmp ("status", field)) {
         /* Don't need status. Check that it's present and ignore it. */
         has_status = true;
         continue;
      }

      if (0 == strcmp ("creationDate", field)) {
         has_creation_date = true;

         if (!BSON_ITER_HOLDS_DATE_TIME (&iter)) {
            CLIENT_ERR ("invalid 'creationDate', expect datetime");
            return false;
         }

         out->creation_date = bson_iter_date_time (&iter);
         continue;
      }

      if (0 == strcmp ("updateDate", field)) {
         has_update_date = true;

         if (!BSON_ITER_HOLDS_DATE_TIME (&iter)) {
            CLIENT_ERR ("invalid 'updateDate', expect datetime");
            return false;
         }

         out->update_date = bson_iter_date_time (&iter);
         continue;
      }

      if (0 == strcmp ("keyAltNames", field)) {
         /* TODO: after rebasing on key alt name, add that parsing code here. */
         continue;
      }

      CLIENT_ERR ("unrecognized field '%s'", field);
      return false;
   }

   /* Check that required fields were set. */
   if (!has_id) {
      CLIENT_ERR ("invalid key, no '_id'");
      return false;
   }

   if (!has_master_key) {
      CLIENT_ERR ("invalid key, no 'masterKey'");
      return false;
   }

   if (!has_key_material) {
      CLIENT_ERR ("invalid key, no 'keyMaterial'");
      return false;
   }

   if (!has_status) {
      CLIENT_ERR ("invalid key, no 'status'");
      return false;
   }

   if (!has_creation_date) {
      CLIENT_ERR ("invalid key, no 'creationDate'");
      return false;
   }

   if (!has_update_date) {
      CLIENT_ERR ("invalid key, no 'updateDate'");
      return false;
   }

   return true;
}


_mongocrypt_key_doc_t *
_mongocrypt_key_new ()
{
   _mongocrypt_key_doc_t *key_doc;

   key_doc = (_mongocrypt_key_doc_t *) bson_malloc0 (sizeof *key_doc);

   return key_doc;
}


/* TODO CDRIVER-3154 instead of comparing all parsed fields, just compare
 * the original BSON document. */
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
      bson_t a_alt_names, b_alt_names;

      BSON_ASSERT (a->key_alt_names.value_type == BSON_TYPE_ARRAY);
      BSON_ASSERT (b->key_alt_names.value_type == BSON_TYPE_ARRAY);

      bson_init_static (&a_alt_names,
                        a->key_alt_names.value.v_doc.data,
                        a->key_alt_names.value.v_doc.data_len);

      bson_init_static (&b_alt_names,
                        b->key_alt_names.value.v_doc.data,
                        b->key_alt_names.value.v_doc.data_len);

      if (!bson_equal (&a_alt_names, &b_alt_names)) {
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


   if ((a->masterkey_cmk && b->masterkey_cmk == NULL) ||
       (a->masterkey_cmk == NULL && b->masterkey_cmk)) {
      return false;
   }

   if (a->masterkey_cmk && b->masterkey_cmk) {
      if (0 != strcmp (a->masterkey_cmk, b->masterkey_cmk)) {
         return false;
      }
   }

   if ((a->endpoint && b->endpoint == NULL) ||
       (a->endpoint == NULL && b->endpoint)) {
      return false;
   }

   if (a->endpoint && b->endpoint) {
      if (0 != strcmp (a->endpoint, b->endpoint)) {
         return false;
      }
   }

   if (a->creation_date != b->creation_date) {
      return false;
   }

   if (a->creation_date != b->creation_date) {
      return false;
   }

   if (a->update_date != b->update_date) {
      return false;
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
   bson_free (key->endpoint);
   bson_free (key);
}


void
_mongocrypt_key_doc_copy_to (_mongocrypt_key_doc_t *src,
                             _mongocrypt_key_doc_t *dst)
{
   BSON_ASSERT (src);
   BSON_ASSERT (dst);

   memset (dst, 0, sizeof (*dst));
   _mongocrypt_buffer_copy_to (&src->id, &dst->id);
   _mongocrypt_buffer_copy_to (&src->key_material, &dst->key_material);
   if (src->has_alt_names) {
      bson_value_copy (&src->key_alt_names, &dst->key_alt_names);
      dst->has_alt_names = true;
   }
   dst->masterkey_provider = src->masterkey_provider;
   dst->masterkey_region = bson_strdup (src->masterkey_region);
   dst->masterkey_cmk = bson_strdup (src->masterkey_cmk);
}

_mongocrypt_key_alt_name_t *
_mongocrypt_key_alt_name_copy_all (_mongocrypt_key_alt_name_t *ptr)
{
   _mongocrypt_key_alt_name_t *ptr_copy = NULL, *head = NULL;

   while (ptr) {
      _mongocrypt_key_alt_name_t *copied;
      copied = bson_malloc0 (sizeof (*copied));
      bson_value_copy (&ptr->value, &copied->value);

      if (!ptr_copy) {
         ptr_copy = copied;
         head = ptr_copy;
      } else {
         ptr_copy->next = copied;
         ptr_copy = ptr_copy->next;
      }
      ptr = ptr->next;
   }
   return head;
}

void
_mongocrypt_key_alt_name_destroy_all (_mongocrypt_key_alt_name_t *ptr)
{
   _mongocrypt_key_alt_name_t *next;
   while (ptr) {
      next = ptr->next;
      bson_value_destroy (&ptr->value);
      bson_free (ptr);
      ptr = next;
   }
}

bool
_mongocrypt_key_alt_name_intersects (_mongocrypt_key_alt_name_t *ptr_a,
                                     _mongocrypt_key_alt_name_t *ptr_b)
{
   _mongocrypt_key_alt_name_t *orig_ptr_b = ptr_b;
   for (; ptr_a; ptr_a = ptr_a->next) {
      for (ptr_b = orig_ptr_b; ptr_b; ptr_b = ptr_b->next) {
         BSON_ASSERT (ptr_a->value.value_type == BSON_TYPE_UTF8);
         BSON_ASSERT (ptr_b->value.value_type == BSON_TYPE_UTF8);
         if (0 == strcmp (ptr_a->value.value.v_utf8.str,
                          ptr_b->value.value.v_utf8.str)) {
            return true;
         }
      }
   }
   return false;
}


_mongocrypt_key_alt_name_t *
_mongocrypt_key_alt_name_create (const char *name, ...)
{
   va_list args;
   const char *arg_ptr;
   _mongocrypt_key_alt_name_t *head, *prev;

   head = NULL;
   prev = NULL;
   va_start (args, name);
   arg_ptr = name;
   while (arg_ptr) {
      _mongocrypt_key_alt_name_t *curr;

      curr = bson_malloc0 (sizeof (*curr));
      curr->value.value_type = BSON_TYPE_UTF8;
      curr->value.value.v_utf8.str = bson_strdup (arg_ptr);
      curr->value.value.v_utf8.len = strlen (arg_ptr);
      if (!prev) {
         head = curr;
      } else {
         prev->next = curr;
      }

      arg_ptr = va_arg (args, const char *);
      prev = curr;
   }
   va_end (args);

   return head;
}

_mongocrypt_key_alt_name_t *
_mongocrypt_key_alt_name_new (const bson_value_t *value)
{
   _mongocrypt_key_alt_name_t *name = bson_malloc0 (sizeof (*name));
   bson_value_copy (value, &name->value);
   return name;
}