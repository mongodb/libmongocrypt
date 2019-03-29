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


#include <bson/bson.h>

#include "kms_message/kms_b64.h"

#include "mongocrypt.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"

struct __mongocrypt_key_broker_entry_t {
   mongocrypt_status_t *status;
   _mongocrypt_key_state_t state;
   _mongocrypt_buffer_t key_id;
   _mongocrypt_key_doc_t key_returned;
   mongocrypt_kms_ctx_t kms;
   _mongocrypt_buffer_t decrypted_key_material;
   struct __mongocrypt_key_broker_entry_t *next;
};


/* TODO: CDRIVER-3044 instead of err_on_missing keys, provide API for checking
 * if
 * keys are incomplete (i.e. not encrypted or decrypted) */
void
_mongocrypt_key_broker_init (_mongocrypt_key_broker_t *kb,
                             bool err_on_missing_keys,
                             _mongocrypt_opts_t *opts)
{
   memset (kb, 0, sizeof (*kb));
   kb->err_on_missing_keys = err_on_missing_keys; /* TODO: use this. */
   kb->all_keys_added = false;
   kb->status = mongocrypt_status_new ();
   kb->crypt_opts = opts;
}


bool
_mongocrypt_key_broker_has (_mongocrypt_key_broker_t *kb,
                            _mongocrypt_key_state_t state)
{
   _mongocrypt_key_broker_entry_t *ptr;

   for (ptr = kb->kb_entry; ptr != NULL; ptr = ptr->next) {
      if (ptr->state == state) {
         return true;
      }
   }
   return false;
}


bool
_mongocrypt_key_broker_empty (_mongocrypt_key_broker_t *kb)
{
   return kb->kb_entry == NULL;
}


bool
_mongocrypt_key_broker_add_id (_mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id)
{
   _mongocrypt_key_broker_entry_t *kbe;

   for (kbe = kb->kb_entry; kbe; kbe = kbe->next) {
      if (0 == _mongocrypt_buffer_cmp (&kbe->key_id, key_id)) {
         return true;
      }
   }

   /* TODO CDRIVER-2951 check if we have this key cached. */
   kbe = bson_malloc0 (sizeof (*kbe));
   _mongocrypt_buffer_copy_to (key_id, &kbe->key_id);
   kbe->state = KEY_EMPTY;
   kbe->next = kb->kb_entry;
   kb->kb_entry = kbe;
   kb->decryptor_iter = kbe;
   return true;
}


bool
_mongocrypt_key_broker_add_doc (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc)
{
   mongocrypt_status_t *status;
   bson_t doc_bson;
   _mongocrypt_key_doc_t key = {0};
   _mongocrypt_key_broker_entry_t *kbe;
   bool ret;

   BSON_ASSERT (kb);
   ret = false;
   status = kb->status;

   if (!doc) {
      CLIENT_ERR ("invalid key");
      goto done;
   }

   /* 1. parse the key doc
    * 2. check which _id/keyAltName this key doc matches.
    * 3. copy the key doc, set the entry to KEY_ENCRYPTED. */
   _mongocrypt_buffer_to_bson (doc, &doc_bson);
   if (!_mongocrypt_key_parse_owned (&doc_bson, &key, status)) {
      goto done;
   }

   /* find which _id/keyAltName this key doc matches. */
   for (kbe = kb->kb_entry; kbe != NULL; kbe = kbe->next) {
      /* TODO: CDRIVER-3057 support keyAltName. */
      if (0 == _mongocrypt_buffer_cmp (&kbe->key_id, &key.id)) {
         /* take ownership of the key document. */
         memcpy (&kbe->key_returned, &key, sizeof (key));
         memset (&key, 0, sizeof (key));
         kbe->state = KEY_ENCRYPTED;

         if (!_mongocrypt_kms_ctx_init_decrypt (
                &kbe->kms, kb->crypt_opts, &kbe->key_returned, kbe)) {
            mongocrypt_kms_ctx_status (&kbe->kms, status);
            goto done;
         }
         ret = true;
         goto done;
      }
   }
   CLIENT_ERR ("no key matching passed ID");
   ret = false;
done:
   if (!ret) {
      _mongocrypt_key_cleanup (&key);
   }
   return ret;
}


bool
_mongocrypt_key_broker_done_adding_docs (_mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);
   status = kb->status;

   if (_mongocrypt_key_broker_has (kb, KEY_EMPTY)) {
      /* TODO: not an error if err_on_missing == false. */
      CLIENT_ERR ("client did not provide all keys");
      return false;
   }

   kb->all_keys_added = true;

   return true;
}


mongocrypt_kms_ctx_t *
_mongocrypt_key_broker_next_kms (_mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);

   kbe = kb->decryptor_iter;

   while (kbe && kbe->state != KEY_ENCRYPTED) {
      kbe = kbe->next;
   }

   if (kbe) {
      kbe->state = KEY_DECRYPTING;
      kb->decryptor_iter = kbe->next;
      return &kbe->kms;
   } else {
      kb->decryptor_iter = NULL;
      return NULL;
   }
}


bool
_mongocrypt_key_broker_kms_done (_mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbe;
   _mongocrypt_buffer_t tmp;

   status = kb->status;
   for (kbe = kb->kb_entry; kbe != NULL; kbe = kbe->next) {
      if (kbe->state != KEY_DECRYPTING) {
         /* TODO: don't error based on err_on_missing flag. */
         CLIENT_ERR ("key not decrypted");
         return false;
      }

      if (!_mongocrypt_kms_ctx_result (&kbe->kms, &tmp)) {
         /* Always fatal. Key attempted to decrypt but failed. */
         mongocrypt_kms_ctx_status (&kbe->kms, status);
         return false;
      }
      kbe->state = KEY_DECRYPTED;
   }
   return true;
}


bool
_mongocrypt_key_broker_decrypted_key_material_by_id (
   _mongocrypt_key_broker_t *kb,
   _mongocrypt_buffer_t *key_id,
   _mongocrypt_buffer_t *out)
{
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);
   status = kb->status;

   for (kbe = kb->kb_entry; kbe != NULL; kbe = kbe->next) {
      if (0 != _mongocrypt_buffer_cmp (&kbe->key_id, key_id)) {
         continue;
      }
      if (kbe->state != KEY_DECRYPTED) {
         CLIENT_ERR ("key found, but material not decrypted");
         return false;
      }
      return _mongocrypt_kms_ctx_result (&kbe->kms, out);
   }
   CLIENT_ERR ("no matching key found");
   return false;
}


bool
_mongocrypt_key_broker_filter (_mongocrypt_key_broker_t *kb,
                               mongocrypt_binary_t *out)
{
   _mongocrypt_key_broker_entry_t *iter;
   int i = 0;
   bson_t filter, _id, _id_in;

   BSON_ASSERT (kb);

   if (!_mongocrypt_buffer_empty (&kb->filter)) {
      _mongocrypt_buffer_to_binary (&kb->filter, out);
      return true;
   }

   if (!_mongocrypt_key_broker_has (kb, KEY_EMPTY)) {
      /* no keys need to be fetched. */
      /* TODO: double check this is what we want to do here. */
      out->data = NULL;
      out->len = 0;
      return true;
   }

   bson_init (&filter);
   bson_append_document_begin (&filter, MONGOCRYPT_STR_AND_LEN("_id"), &_id);
   bson_append_array_begin (&_id, MONGOCRYPT_STR_AND_LEN("$in"), &_id_in);

   for (iter = kb->kb_entry; iter != NULL; iter = iter->next) {
      char *key_str;

      if (iter->state != KEY_EMPTY) {
         continue;
      }

      key_str = bson_strdup_printf ("%d", i++);
      _mongocrypt_buffer_append (
         &iter->key_id, &_id_in, key_str, (uint32_t) strlen (key_str));

      bson_free (key_str);
   }

   bson_append_array_end (&_id, &_id_in);
   bson_append_document_end (&filter, &_id);

   _mongocrypt_buffer_steal_from_bson (&kb->filter, &filter);
   _mongocrypt_buffer_to_binary (&kb->filter, out);
   return true;
}


bool
_mongocrypt_key_broker_status (_mongocrypt_key_broker_t *kb,
                               mongocrypt_status_t *out)
{
   BSON_ASSERT (kb);

   if (!mongocrypt_status_ok (kb->status)) {
      _mongocrypt_status_copy_to (kb->status, out);
      return false;
   }

   return true;
}

void
_mongocrypt_key_broker_cleanup (_mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbe, *tmp;

   if (!kb) {
      return;
   }

   kbe = kb->kb_entry;

   while (kbe) {
      tmp = kbe->next;
      mongocrypt_status_destroy (kbe->status);
      _mongocrypt_buffer_cleanup (&kbe->key_id);
      _mongocrypt_key_cleanup (&kbe->key_returned);
      _mongocrypt_kms_ctx_cleanup (&kbe->kms);
      _mongocrypt_buffer_cleanup (&kbe->decrypted_key_material);
      bson_free (kbe);
      kbe = tmp;
   }

   kb->kb_entry = NULL;

   mongocrypt_status_destroy (kb->status);
   _mongocrypt_buffer_cleanup (&kb->filter);
}
