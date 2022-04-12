/*
 * Copyright 2022-present MongoDB, Inc.
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


#include "mc-efc-private.h"

#include "mongocrypt-private.h"

/* _parse_field parses and prepends one field document to efc->fields. */
static bool
_parse_field (mc_EncryptedFieldConfig_t *efc,
              bson_t *field,
              mongocrypt_status_t *status)
{
   bson_iter_t field_iter;
   if (!bson_iter_init_find (&field_iter, field, "keyId")) {
      CLIENT_ERR ("unable to find 'keyId' in 'field' document");
      return false;
   }
   if (!BSON_ITER_HOLDS_BINARY (&field_iter)) {
      CLIENT_ERR ("expected 'fields[].keyId' to be type binary, got: %d",
                  bson_iter_type (&field_iter));
      return false;
   }
   _mongocrypt_buffer_t field_keyid;
   if (!_mongocrypt_buffer_from_uuid_iter (&field_keyid, &field_iter)) {
      CLIENT_ERR ("unable to parse uuid key from 'fields[].keyId'");
      return false;
   }

   const char *field_path;
   if (!bson_iter_init_find (&field_iter, field, "path")) {
      CLIENT_ERR ("unable to find 'path' in 'field' document");
      return false;
   }
   if (!BSON_ITER_HOLDS_UTF8 (&field_iter)) {
      CLIENT_ERR ("expected 'fields[].path' to be type UTF-8, got: %d",
                  bson_iter_type (&field_iter));
      return false;
   }
   field_path = bson_iter_utf8 (&field_iter, NULL /* length */);

   /* Prepend a new mc_EncryptedField_t */
   mc_EncryptedField_t *ef = bson_malloc0 (sizeof (mc_EncryptedField_t));
   _mongocrypt_buffer_copy_to (&field_keyid, &ef->keyId);
   ef->path = bson_strdup (field_path);
   ef->next = efc->fields;
   efc->fields = ef;

   return true;
}

bool
mc_EncryptedFieldConfig_parse (mc_EncryptedFieldConfig_t *efc,
                               const bson_t *efc_bson,
                               mongocrypt_status_t *status)
{
   memset (efc, 0, sizeof (*efc));
   bson_iter_t iter;
   if (!bson_iter_init_find (&iter, efc_bson, "fields")) {
      CLIENT_ERR ("unable to find 'fields' in encrypted_field_config");
      return false;
   }
   if (!BSON_ITER_HOLDS_ARRAY (&iter)) {
      CLIENT_ERR ("expected 'fields' to be type array, got: %d",
                  bson_iter_type (&iter));
      return false;
   }
   if (!bson_iter_recurse (&iter, &iter)) {
      CLIENT_ERR ("unable to recurse into encrypted_field_config 'fields'");
      return false;
   }
   while (bson_iter_next (&iter)) {
      if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
         CLIENT_ERR ("expected 'fields[]' to be type document, got: %d",
                     bson_iter_type (&iter));
         return false;
      }
      bson_t field;
      const uint8_t *field_data;
      uint32_t field_len;
      bson_iter_document (&iter, &field_len, &field_data);
      if (!bson_init_static (&field, field_data, field_len)) {
         CLIENT_ERR ("unable to initialize 'fields[]' value as document");
         return false;
      }
      if (!_parse_field (efc, &field, status)) {
         return false;
      }
   }
   return true;
}

void
mc_EncryptedFieldConfig_cleanup (mc_EncryptedFieldConfig_t *efc)
{
   if (!efc) {
      return;
   }
   mc_EncryptedField_t *ptr = efc->fields;
   while (ptr != NULL) {
      mc_EncryptedField_t *ptr_next = ptr->next;
      _mongocrypt_buffer_cleanup (&ptr->keyId);
      bson_free ((char *) ptr->path);
      bson_free (ptr);
      ptr = ptr_next;
   }
}
