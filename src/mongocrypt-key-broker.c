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

#include "mongocrypt-key-decryptor.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"

struct __mongocrypt_key_broker_entry_t {
   mongocrypt_status_t *status;
   _mongocrypt_key_state_t state;
   _mongocrypt_buffer_t key_id;
   _mongocrypt_key_t key_returned;
   mongocrypt_key_decryptor_t key_decryptor;
   _mongocrypt_buffer_t decrypted_key_material;
   struct __mongocrypt_key_broker_entry_t *next;
};


void
_mongocrypt_key_broker_init (mongocrypt_key_broker_t *kb)
{
   memset (kb, 0, sizeof (*kb));
   kb->all_keys_added = false;
   kb->status = mongocrypt_status_new ();
}


bool
_mongocrypt_key_broker_has (mongocrypt_key_broker_t *kb,
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
_mongocrypt_key_broker_empty (mongocrypt_key_broker_t *kb)
{
   return kb->kb_entry == NULL;
}


bool
_mongocrypt_key_broker_add_id (mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id)
{
   _mongocrypt_key_broker_entry_t *kbi;

   /* TODO CDRIVER-2951 check if we have this key cached. */
   kbi = bson_malloc0 (sizeof (*kbi));
   _mongocrypt_buffer_copy_to (key_id, &kbi->key_id);
   kbi->state = KEY_EMPTY;
   kbi->next = kb->kb_entry;
   kb->kb_entry = kbi;
   kb->decryptor_iter = kbi;
   return true;
}


bool
_mongocrypt_key_broker_filter (mongocrypt_key_broker_t *kb,
                               _mongocrypt_buffer_t *out,
                               mongocrypt_status_t *status)
{
   _mongocrypt_key_broker_entry_t *kbi;
   int i;
   bson_t filter, _id, _id_in;

   bson_init (&filter);
   bson_append_document_begin (&filter, "_id", 3, &_id);
   bson_append_array_begin (&_id, "$in", 3, &_id_in);
   i = 0;
   for (kbi = kb->kb_entry; kbi != NULL; kbi = kbi->next) {
      char *key_str;

      if (kbi->state != KEY_EMPTY) {
         continue;
      }
      key_str = bson_strdup_printf ("%d", i++);
      _mongocrypt_bson_append_buffer (
         &_id_in, key_str, strlen (key_str), &kbi->key_id);
      bson_free (key_str);
   }
   bson_append_array_end (&_id, &_id_in);
   bson_append_document_end (&filter, &_id);

   out->data = bson_destroy_with_steal (&filter, true, &out->len);
   out->owned = true;
   return true;
}


bool
_mongocrypt_key_broker_add_doc (mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc)
{
   mongocrypt_status_t *status;
   bson_t doc_bson;
   _mongocrypt_key_t key;
   _mongocrypt_key_broker_entry_t *kbi;

   BSON_ASSERT (kb);
   status = kb->status;

   /* 1. parse the key doc
    * 2. check which _id/keyAltName this key doc matches.
    * 3. copy the key doc, set the entry to KEY_ENCRYPTED. */
   _mongocrypt_buffer_to_unowned_bson (doc, &doc_bson);
   if (!_mongocrypt_key_parse_owned (&doc_bson, &key, status)) {
      return false;
   }

   /* find which _id/keyAltName this key doc matches. */
   for (kbi = kb->kb_entry; kbi != NULL; kbi = kbi->next) {
      /* TODO: support keyAltName. */
      if (0 == _mongocrypt_buffer_cmp (&kbi->key_id, &key.id)) {
         /* take ownership of the key document. */
         memcpy (&kbi->key_returned, &key, sizeof (key));
         kbi->state = KEY_ENCRYPTED;

         _mongocrypt_key_decryptor_init (
            &kbi->key_decryptor, &kbi->key_returned.key_material, kbi);
         return true;
      }
   }

   CLIENT_ERR ("no key matching passed ID");
   return false;
}


mongocrypt_key_decryptor_t *
_mongocrypt_key_broker_next_decryptor (mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbi;

   BSON_ASSERT (kb);

   if (_mongocrypt_key_broker_empty (kb)) {
      return NULL;
   }

   kbi = kb->decryptor_iter;

   while (kbi && kbi->state != KEY_ENCRYPTED) {
      kbi = kbi->next;
   }

   return &kbi->key_decryptor;
}


bool
_mongocrypt_key_broker_add_decrypted_key (mongocrypt_key_broker_t *kb,
                                          mongocrypt_key_decryptor_t *kd)
{
   int ret = false;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbi;
   kms_response_t *kms_response = NULL;
   const char *kms_body;
   bson_json_reader_t *reader = NULL;
   bson_error_t bson_error;
   bson_t response_body = BSON_INITIALIZER;
   bson_iter_t iter;
   char *b64_str = NULL;
   uint32_t b64_strlen;

   BSON_ASSERT (kb);
   status = kb->status;

   /* TODO: this is for testing, BSON_ASSERT (kd) */
   if (!kd) {
      bson_destroy (&response_body);
      return true;
   }

   kbi = (_mongocrypt_key_broker_entry_t *) kd->ctx;

   if (kms_response_parser_wants_bytes (kd->parser, 1)) {
      /* caller called too early. */
      kbi->state = KEY_ERROR;
      CLIENT_ERR ("Decryptor unfinished");
      goto done;
   }

   kms_response = kms_response_parser_get_response (kd->parser);
   kms_body = kms_response_get_body (kms_response);
   reader = bson_json_data_reader_new (false, 1024);
   /* TODO: extra strlen can be avoided by exposing length in kms-message. */
   bson_json_data_reader_ingest (
      reader, (const uint8_t *) kms_body, strlen (kms_body));

   ret = bson_json_reader_read (reader, &response_body, &bson_error);
   if (ret == -1) {
      CLIENT_ERR ("Error reading KMS response: %s", bson_error.message);
      goto done;
   } else if (ret == 0) {
      CLIENT_ERR ("Could not read JSON document from response");
      goto done;
   }

   if (!bson_iter_init_find (&iter, &response_body, "Plaintext")) {
      CLIENT_ERR ("KMS JSON response does not include Plaintext");
      goto done;
   }

   b64_str = (char *) bson_iter_utf8 (&iter, &b64_strlen);

   kbi->decrypted_key_material.data = bson_malloc (b64_strlen + 1);
   kbi->decrypted_key_material.len = kms_message_b64_pton (
      b64_str, kbi->decrypted_key_material.data, b64_strlen);
   kbi->state = KEY_DECRYPTED;

   /* TODO CDRIVER-2951 Add decrypted keys to the key cache */

   ret = true;
done:
   bson_destroy (&response_body);
   kms_response_destroy (kms_response);
   bson_json_reader_destroy (reader);
   return ret;
}


const _mongocrypt_buffer_t *
_mongocrypt_key_broker_decrypted_key_material_by_id (
   mongocrypt_key_broker_t *kb, _mongocrypt_buffer_t *key_id)
{
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbi;

   BSON_ASSERT (kb);
   status = kb->status;

   for (kbi = kb->kb_entry; kbi != NULL; kbi = kbi->next) {
      if (0 == _mongocrypt_buffer_cmp (&kbi->key_id, key_id)) {
         if (kbi->state != KEY_DECRYPTED) {
            CLIENT_ERR ("key found, but material not decrypted");
            return NULL;
         }
         return &kbi->decrypted_key_material;
      }
   }
   CLIENT_ERR ("no matching key found");
   return NULL;
}


const mongocrypt_binary_t *
mongocrypt_key_broker_get_key_filter (mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *iter;
   int i = 0;
   bson_t filter, _id, _id_in;

   BSON_ASSERT (kb);

   if (kb->filter) {
      return kb->filter;
   }

   bson_init (&filter);
   bson_append_document_begin (&filter, "_id", 3, &_id);
   bson_append_array_begin (&_id, "$in", 3, &_id_in);

   for (iter = kb->kb_entry; iter != NULL; iter = iter->next) {
      char *key_str;

      if (iter->state != KEY_EMPTY) {
         continue;
      }

      key_str = bson_strdup_printf ("%d", i++);
      _mongocrypt_bson_append_buffer (
         &_id_in, key_str, strlen (key_str), &iter->key_id);

      bson_free (key_str);
   }

   bson_append_array_end (&_id, &_id_in);
   bson_append_document_end (&filter, &_id);

   kb->filter = mongocrypt_binary_new ();
   kb->filter->data = bson_destroy_with_steal (&filter, true, &kb->filter->len);

   return kb->filter;
}

bool
mongocrypt_key_broker_add_key (mongocrypt_key_broker_t *kb,
                               const mongocrypt_binary_t *key)
{
   _mongocrypt_buffer_t key_buf;
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);
   status = kb->status;

   if (!key) {
      CLIENT_ERR ("attempted to add a NULL key");
      return false;
   }

   _mongocrypt_unowned_buffer_from_binary (key, &key_buf);

   return _mongocrypt_key_broker_add_doc (kb, &key_buf);
}

bool
mongocrypt_key_broker_done_adding_keys (mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);
   status = kb->status;

   if (_mongocrypt_key_broker_has (kb, KEY_EMPTY)) {
      CLIENT_ERR ("client did not provide all keys");
      return false;
   }

   kb->all_keys_added = true;

   return true;
}

mongocrypt_key_decryptor_t *
mongocrypt_key_broker_next_decryptor (mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);
   status = kb->status;

   if (!kb->all_keys_added) {
      CLIENT_ERR ("client did not provide all keys");
      return NULL;
   }

   return _mongocrypt_key_broker_next_decryptor (kb);
}

bool
mongocrypt_key_broker_add_decrypted_key (
   mongocrypt_key_broker_t *kb, mongocrypt_key_decryptor_t *key_decryptor)
{
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);
   status = kb->status;

   if (!kb->all_keys_added) {
      CLIENT_ERR ("client did not provide all keys");
      return false;
   }

   return _mongocrypt_key_broker_add_decrypted_key (kb, key_decryptor);
}

mongocrypt_status_t *
mongocrypt_key_broker_status (mongocrypt_key_broker_t *kb)
{
   BSON_ASSERT (kb);

   return kb->status;
}

void
_mongocrypt_key_broker_cleanup (mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbi, *tmp;

   if (!kb) {
      return;
   }

   kbi = kb->kb_entry;

   while (kbi) {
      tmp = kbi->next;
      mongocrypt_status_destroy (kbi->status);
      _mongocrypt_buffer_cleanup (&kbi->key_id);
      _mongocrypt_key_cleanup (&kbi->key_returned);
      _mongocrypt_key_decryptor_cleanup (&kbi->key_decryptor);
      _mongocrypt_buffer_cleanup (&kbi->decrypted_key_material);
      kbi = tmp;
   }

   kb->kb_entry = NULL;

   mongocrypt_status_destroy (kb->status);
   mongocrypt_binary_destroy (kb->filter);
}
