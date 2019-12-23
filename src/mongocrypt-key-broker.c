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

#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-private.h"

void
_mongocrypt_key_broker_init (_mongocrypt_key_broker_t *kb, mongocrypt_t *crypt)
{
   memset (kb, 0, sizeof (*kb));
   kb->crypt = crypt;
   kb->state = KB_REQUESTING;
   kb->status = mongocrypt_status_new ();
}

/*
 * Creates a new key_returned_t and prepends it to a list.
 *
 * Side effects:
 * - updates *list to point to a new head.
 */
static key_returned_t *
_key_returned_prepend (_mongocrypt_key_broker_t *kb,
                       key_returned_t **list,
                       _mongocrypt_key_doc_t *key_doc)
{
   key_returned_t *key_returned;

   BSON_ASSERT (key_doc);

   key_returned = bson_malloc0 (sizeof (*key_returned));
   BSON_ASSERT (key_returned);

   key_returned->doc = _mongocrypt_key_new ();
   _mongocrypt_key_doc_copy_to (key_doc, key_returned->doc);

   /* Prepend and update the head of the list. */
   key_returned->next = *list;
   *list = key_returned;

   /* Update the head of the decrypting iter. */
   kb->decryptor_iter = kb->keys_returned;
   return key_returned;
}

/* Find the first (if any) key_returned_t matching either a key_id or a list of
 * key_alt_names (both are NULLable) */
static key_returned_t *
_key_returned_find_one (key_returned_t *list,
                        _mongocrypt_buffer_t *key_id,
                        _mongocrypt_key_alt_name_t *key_alt_names)
{
   key_returned_t *key_returned;

   for (key_returned = list; NULL != key_returned;
        key_returned = key_returned->next) {
      if (key_id) {
         if (0 == _mongocrypt_buffer_cmp (key_id, &key_returned->doc->id)) {
            return key_returned;
         }
      }
      if (key_alt_names) {
         if (_mongocrypt_key_alt_name_intersects (
                key_alt_names, key_returned->doc->key_alt_names)) {
            return key_returned;
         }
      }
   }

   return NULL;
}

/* Find the first (if any) key_request_t in the key broker matching either a
 * key_id or a list of key_alt_names (both are NULLable) */
static key_request_t *
_key_request_find_one (_mongocrypt_key_broker_t *kb,
                       const _mongocrypt_buffer_t *key_id,
                       _mongocrypt_key_alt_name_t *key_alt_names)
{
   key_request_t *key_request;

   for (key_request = kb->key_requests; NULL != key_request;
        key_request = key_request->next) {
      if (key_id) {
         if (0 == _mongocrypt_buffer_cmp (key_id, &key_request->id)) {
            return key_request;
         }
      }
      if (key_alt_names) {
         if (_mongocrypt_key_alt_name_intersects (key_alt_names,
                                                  key_request->alt_name)) {
            return key_request;
         }
      }
   }

   return NULL;
}

static bool
_all_key_requests_satisfied (_mongocrypt_key_broker_t *kb)
{
   key_request_t *key_request;

   for (key_request = kb->key_requests; NULL != key_request;
        key_request = key_request->next) {
      if (!key_request->satisfied) {
         return false;
      }
   }
   return true;
}

static bool
_key_broker_fail_w_msg (_mongocrypt_key_broker_t *kb, const char *msg)
{
   mongocrypt_status_t *status;

   kb->state = KB_ERROR;
   status = kb->status;
   CLIENT_ERR (msg);
   return false;
}

static bool
_key_broker_fail (_mongocrypt_key_broker_t *kb)
{
   if (mongocrypt_status_ok (kb->status)) {
      return _key_broker_fail_w_msg (
         kb, "unexpected, failing but no error status set");
   }
   kb->state = KB_ERROR;
   return false;
}

static bool
_try_satisfying_from_cache (_mongocrypt_key_broker_t *kb, key_request_t *req)
{
   _mongocrypt_cache_key_attr_t *attr = NULL;
   _mongocrypt_cache_key_value_t *value = NULL;
   bool ret = false;

   if (kb->state != KB_REQUESTING) {
      _key_broker_fail_w_msg (
         kb, "trying to retrieve key from cache in invalid state");
      goto cleanup;
   }

   attr = _mongocrypt_cache_key_attr_new (&req->id, req->alt_name);
   if (!_mongocrypt_cache_get (&kb->crypt->cache_key, attr, (void **) &value)) {
      _key_broker_fail_w_msg (kb, "failed to retrieve from cache");
      goto cleanup;
   }

   if (value) {
      key_returned_t *key_returned;

      req->satisfied = true;
      if (_mongocrypt_buffer_empty (&value->decrypted_key_material)) {
         _key_broker_fail_w_msg (
            kb, "cache entry does not have decrypted key material");
         goto cleanup;
      }

      /* Add the cached key to our locally copied list.
       * Note, we deduplicate requests, but *not* keys from the cache,
       * because the state of the cache may change between each call to
       * _mongocrypt_cache_get.
       */
      key_returned =
         _key_returned_prepend (kb, &kb->keys_cached, value->key_doc);
      _mongocrypt_buffer_init (&key_returned->decrypted_key_material);
      _mongocrypt_buffer_copy_to (&value->decrypted_key_material,
                                  &key_returned->decrypted_key_material);
      key_returned->decrypted = true;
   }

   ret = true;
cleanup:
   _mongocrypt_cache_key_value_destroy (value);
   _mongocrypt_cache_key_attr_destroy (attr);
   return ret;
}

static bool
_store_to_cache (_mongocrypt_key_broker_t *kb, key_returned_t *key_returned)
{
   _mongocrypt_cache_key_value_t *value;
   _mongocrypt_cache_key_attr_t *attr;
   bool ret;

   if (!key_returned->decrypted) {
      return _key_broker_fail_w_msg (kb, "cannot cache non-decrypted key");
   }

   attr = _mongocrypt_cache_key_attr_new (&key_returned->doc->id,
                                          key_returned->doc->key_alt_names);
   if (!attr) {
      return _key_broker_fail_w_msg (kb,
                                     "could not create key cache attribute");
   }
   value = _mongocrypt_cache_key_value_new (
      key_returned->doc, &key_returned->decrypted_key_material);
   ret = _mongocrypt_cache_add_stolen (
      &kb->crypt->cache_key, attr, value, kb->status);
   _mongocrypt_cache_key_attr_destroy (attr);
   if (!ret) {
      return _key_broker_fail (kb);
   }
   return true;
}

bool
_mongocrypt_key_broker_request_id (_mongocrypt_key_broker_t *kb,
                                   const _mongocrypt_buffer_t *key_id)
{
   key_request_t *req;

   if (kb->state != KB_REQUESTING) {
      return _key_broker_fail_w_msg (
         kb, "attempting to request a key id, but in wrong state");
   }

   if (!_mongocrypt_buffer_is_uuid ((_mongocrypt_buffer_t *) key_id)) {
      return _key_broker_fail_w_msg (kb, "expected UUID for key id");
   }

   if (_key_request_find_one (kb, key_id, NULL)) {
      return true;
   }

   req = bson_malloc0 (sizeof *req);
   BSON_ASSERT (req);

   _mongocrypt_buffer_copy_to (key_id, &req->id);
   req->next = kb->key_requests;
   kb->key_requests = req;
   if (!_try_satisfying_from_cache (kb, req)) {
      return false;
   }
   return true;
}


bool
_mongocrypt_key_broker_request_name (_mongocrypt_key_broker_t *kb,
                                     const bson_value_t *key_alt_name_value)
{
   key_request_t *req;
   _mongocrypt_key_alt_name_t *key_alt_name;

   if (kb->state != KB_REQUESTING) {
      return _key_broker_fail_w_msg (
         kb, "attempting to request a key name, but in wrong state");
   }

   key_alt_name = _mongocrypt_key_alt_name_new (key_alt_name_value);

   /* Check if we already have a request for this key alt name. */
   if (_key_request_find_one (kb, NULL /* key id */, key_alt_name)) {
      _mongocrypt_key_alt_name_destroy_all (key_alt_name);
      return true;
   }

   req = bson_malloc0 (sizeof *req);
   BSON_ASSERT (req);

   req->alt_name = key_alt_name /* takes ownership */;
   req->next = kb->key_requests;
   kb->key_requests = req;
   if (!_try_satisfying_from_cache (kb, req)) {
      return false;
   }
   return true;
}

bool
_mongocrypt_key_broker_requests_done (_mongocrypt_key_broker_t *kb)
{
   if (kb->state != KB_REQUESTING) {
      return _key_broker_fail_w_msg (
         kb, "attempting to finish adding requests, but in wrong state");
   }

   if (kb->key_requests) {
      /* If all were satisfied from the cache, then we're done since those all
       * have decrypted material */
      if (_all_key_requests_satisfied (kb)) {
         kb->state = KB_DONE;
      } else {
         kb->state = KB_ADDING_DOCS;
      }
   } else {
      kb->state = KB_DONE;
   }
   return true;
}

bool
_mongocrypt_key_broker_filter (_mongocrypt_key_broker_t *kb,
                               mongocrypt_binary_t *out)
{
   key_request_t *req;
   _mongocrypt_key_alt_name_t *key_alt_name;
   int name_index = 0;
   int id_index = 0;
   bson_t ids, names;
   bson_t *filter;

   BSON_ASSERT (kb);

   if (kb->state != KB_ADDING_DOCS) {
      return _key_broker_fail_w_msg (
         kb, "attempting to retrieve filter, but in wrong state");
   }

   if (!_mongocrypt_buffer_empty (&kb->filter)) {
      _mongocrypt_buffer_to_binary (&kb->filter, out);
      return true;
   }

   bson_init (&names);
   bson_init (&ids);

   for (req = kb->key_requests; NULL != req; req = req->next) {
      if (req->satisfied) {
         continue;
      }

      if (!_mongocrypt_buffer_empty (&req->id)) {
         /* Collect key_ids in "ids" */
         char *key_str;

         key_str = bson_strdup_printf ("%d", id_index++);
         if (!key_str ||
             !_mongocrypt_buffer_append (
                &req->id, &ids, key_str, (uint32_t) strlen (key_str))) {
            bson_destroy (&ids);
            bson_destroy (&names);
            bson_free (key_str);
            return _key_broker_fail_w_msg (kb, "could not construct id list");
         }

         bson_free (key_str);
      }

      /* Collect key alt names in "names" */
      for (key_alt_name = req->alt_name; NULL != key_alt_name;
           key_alt_name = key_alt_name->next) {
         char *key_str;

         key_str = bson_strdup_printf ("%d", name_index++);
         BSON_ASSERT (key_str);
         if (!bson_append_value (&names,
                                 key_str,
                                 (uint32_t) strlen (key_str),
                                 &key_alt_name->value)) {
            bson_destroy (&ids);
            bson_destroy (&names);
            bson_free (key_str);
            return _key_broker_fail_w_msg (
               kb, "could not construct keyAltName list");
         }

         bson_free (key_str);
      }
   }

   /*
    * This is our final query:
    * { $or: [ { _id: { $in : [ids] }},
    *          { keyAltName : { $in : [names] }} ] }
    */
   filter = BCON_NEW ("$or",
                      "[",
                      "{",
                      "_id",
                      "{",
                      "$in",
                      BCON_ARRAY (&ids),
                      "}",
                      "}",
                      "{",
                      "keyAltNames",
                      "{",
                      "$in",
                      BCON_ARRAY (&names),
                      "}",
                      "}",
                      "]");

   _mongocrypt_buffer_steal_from_bson (&kb->filter, filter);
   _mongocrypt_buffer_to_binary (&kb->filter, out);
   bson_destroy (&ids);
   bson_destroy (&names);

   return true;
}

static bool
_decrypt_with_local_kms (_mongocrypt_key_broker_t *kb,
                         _mongocrypt_buffer_t *key_material,
                         _mongocrypt_buffer_t *decrypted_key_material)
{
   bool crypt_ret;
   uint32_t bytes_written;

   _mongocrypt_buffer_init (decrypted_key_material);
   decrypted_key_material->len =
      _mongocrypt_calculate_plaintext_len (key_material->len);
   decrypted_key_material->data = bson_malloc (decrypted_key_material->len);
   BSON_ASSERT (decrypted_key_material->data);

   decrypted_key_material->owned = true;

   crypt_ret = _mongocrypt_do_decryption (kb->crypt->crypto,
                                          NULL /* associated data. */,
                                          &kb->crypt->opts.kms_local_key,
                                          key_material,
                                          decrypted_key_material,
                                          &bytes_written,
                                          kb->status);
   if (!crypt_ret) {
      return _key_broker_fail (kb);
   }

   decrypted_key_material->len = bytes_written;

   if (decrypted_key_material->len != MONGOCRYPT_KEY_LEN) {
      return _key_broker_fail_w_msg (kb, "decrypted key is incorrect length");
   }
   return true;
}

bool
_mongocrypt_key_broker_add_doc (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc)
{
   bool ret = false;
   bson_t doc_bson;
   _mongocrypt_key_doc_t *key_doc = NULL;
   key_request_t *key_request;
   key_returned_t *key_returned;
   _mongocrypt_kms_provider_t masterkey_provider;

   if (kb->state != KB_ADDING_DOCS) {
      _key_broker_fail_w_msg (
         kb, "attempting to add a key doc, but in wrong state");
      goto done;
   }

   if (!doc) {
      _key_broker_fail_w_msg (kb, "invalid key");
      goto done;
   }

   /* First, parse the key document. */
   key_doc = _mongocrypt_key_new ();
   if (!_mongocrypt_buffer_to_bson (doc, &doc_bson)) {
      _key_broker_fail_w_msg (kb, "malformed BSON for key document");
      goto done;
   }

   if (!_mongocrypt_key_parse_owned (&doc_bson, key_doc, kb->status)) {
      goto done;
   }

   /* Ensure that this document matches at least one request. */
   if (!_key_request_find_one (kb, &key_doc->id, key_doc->key_alt_names)) {
      _key_broker_fail_w_msg (
         kb, "unexpected key returned, does not match any requests");
      goto done;
   }

   /* Check if there are other keys_returned with intersecting altnames or
    * equal id. This is an error. Do *not* check cached keys. */
   if (_key_returned_find_one (
          kb->keys_returned, &key_doc->id, key_doc->key_alt_names)) {
      _key_broker_fail_w_msg (
         kb, "keys returned have duplicate keyAltNames or _id");
      goto done;
   }

   key_returned = _key_returned_prepend (kb, &kb->keys_returned, key_doc);

   /* Check that the returned key doc's provider matches. */
   masterkey_provider = key_doc->masterkey_provider;
   if (0 == (masterkey_provider & kb->crypt->opts.kms_providers)) {
      _key_broker_fail_w_msg (
         kb, "client not configured with KMS provider necessary to decrypt");
      goto done;
   }

   /* If the KMS provider is local, decrypt immediately. Otherwise, create the
    * HTTP KMS request. */
   if (masterkey_provider == MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      if (!_decrypt_with_local_kms (kb,
                                    &key_returned->doc->key_material,
                                    &key_returned->decrypted_key_material)) {
         goto done;
      }
      key_returned->decrypted = true;
      if (!_store_to_cache (kb, key_returned)) {
         goto done;
      }
   } else if (masterkey_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      if (!_mongocrypt_kms_ctx_init_aws_decrypt (&key_returned->kms,
                                                 &kb->crypt->opts,
                                                 key_doc,
                                                 &kb->crypt->log,
                                                 kb->crypt->crypto)) {
         mongocrypt_kms_ctx_status (&key_returned->kms, kb->status);
         _key_broker_fail (kb);
         goto done;
      }
   } else {
      _key_broker_fail_w_msg (kb, "unrecognized kms provider");
      goto done;
   }

   /* Mark all matching key requests as satisfied. */
   for (key_request = kb->key_requests; NULL != key_request;
        key_request = key_request->next) {
      if (0 == _mongocrypt_buffer_cmp (&key_doc->id, &key_request->id)) {
         key_request->satisfied = true;
      }
      if (_mongocrypt_key_alt_name_intersects (key_doc->key_alt_names,
                                               key_request->alt_name)) {
         key_request->satisfied = true;
      }
   }

   ret = true;
done:
   _mongocrypt_key_destroy (key_doc);
   return ret;
}

bool
_mongocrypt_key_broker_docs_done (_mongocrypt_key_broker_t *kb)
{
   key_returned_t *key_returned;
   bool needs_decryption;

   if (kb->state != KB_ADDING_DOCS) {
      return _key_broker_fail_w_msg (
         kb, "attempting to finish adding docs, but in wrong state");
   }

   /* If there are any requests left unsatisfied, error. */
   if (!_all_key_requests_satisfied (kb)) {
      return _key_broker_fail_w_msg (kb,
                                     "not all keys requested were satisfied");
   }

   /* If we're using a local key provider, or every key was retrieved from the
    * cache, skip the decrypting state. */
   needs_decryption = false;
   for (key_returned = kb->keys_returned; NULL != key_returned;
        key_returned = key_returned->next) {
      if (!key_returned->decrypted) {
         needs_decryption = true;
         break;
      }
   }

   if (needs_decryption) {
      kb->state = KB_DECRYPTING_KEY_MATERIAL;
   } else {
      kb->state = KB_DONE;
   }
   return true;
}

mongocrypt_kms_ctx_t *
_mongocrypt_key_broker_next_kms (_mongocrypt_key_broker_t *kb)
{
   if (kb->state != KB_DECRYPTING_KEY_MATERIAL) {
      _key_broker_fail_w_msg (
         kb, "attempting to get KMS request, but in wrong state");
      /* TODO (CDRIVER-3327) this breaks other expectations. If the caller only
       * checks the return value they may mistake this NULL as indicating all
       * KMS requests have been iterated. */
      return NULL;
   }

   while (kb->decryptor_iter) {
      if (!kb->decryptor_iter->decrypted) {
         key_returned_t *key_returned;

         key_returned = kb->decryptor_iter;
         /* iterate before returning, so next call starts at next entry */
         kb->decryptor_iter = kb->decryptor_iter->next;
         return &key_returned->kms;
      }
      kb->decryptor_iter = kb->decryptor_iter->next;
   }

   return NULL;
}

bool
_mongocrypt_key_broker_kms_done (_mongocrypt_key_broker_t *kb)
{
   key_returned_t *key_returned;

   if (kb->state != KB_DECRYPTING_KEY_MATERIAL) {
      return _key_broker_fail_w_msg (
         kb, "attempting to complete KMS requests, but in wrong state");
   }

   for (key_returned = kb->keys_returned; NULL != key_returned;
        key_returned = key_returned->next) {
      /* Local keys were already decrypted. */
      if (key_returned->doc->masterkey_provider ==
          MONGOCRYPT_KMS_PROVIDER_AWS) {
         if (key_returned->decrypted) {
            return _key_broker_fail_w_msg (
               kb,
               "unexpected, returned keys should not be "
               "decrypted before KMS completion");
         }

         if (!key_returned->kms.req) {
            return _key_broker_fail_w_msg (
               kb, "unexpected, KMS not set on key returned");
         }

         if (!_mongocrypt_kms_ctx_result (
                &key_returned->kms, &key_returned->decrypted_key_material)) {
            /* Always fatal. Key attempted to decrypt but failed. */
            mongocrypt_kms_ctx_status (&key_returned->kms, kb->status);
            return _key_broker_fail (kb);
         }
      }

      if (key_returned->decrypted_key_material.len != MONGOCRYPT_KEY_LEN) {
         return _key_broker_fail_w_msg (kb,
                                        "decrypted key is incorrect length");
      }

      key_returned->decrypted = true;
      if (!_store_to_cache (kb, key_returned)) {
         return false;
      }
   }

   kb->state = KB_DONE;
   return true;
}


bool
_get_decrypted_key_material (_mongocrypt_key_broker_t *kb,
                             _mongocrypt_buffer_t *key_id,
                             _mongocrypt_key_alt_name_t *key_alt_name,
                             _mongocrypt_buffer_t *out,
                             _mongocrypt_buffer_t *key_id_out)
{
   key_returned_t *key_returned;

   _mongocrypt_buffer_init (out);
   if (key_id_out) {
      _mongocrypt_buffer_init (key_id_out);
   }
   /* Search both keys_returned and keys_cached. */

   key_returned =
      _key_returned_find_one (kb->keys_returned, key_id, key_alt_name);
   if (!key_returned) {
      /* Try the keys retrieved from the cache. */
      key_returned =
         _key_returned_find_one (kb->keys_cached, key_id, key_alt_name);
   }

   if (!key_returned) {
      return _key_broker_fail_w_msg (kb, "could not find key");
   }

   if (!key_returned->decrypted) {
      return _key_broker_fail_w_msg (kb, "unexpected, key not decrypted");
   }

   _mongocrypt_buffer_copy_to (&key_returned->decrypted_key_material, out);
   if (key_id_out) {
      _mongocrypt_buffer_copy_to (&key_returned->doc->id, key_id_out);
   }
   return true;
}

bool
_mongocrypt_key_broker_decrypted_key_by_id (_mongocrypt_key_broker_t *kb,
                                            const _mongocrypt_buffer_t *key_id,
                                            _mongocrypt_buffer_t *out)
{
   if (kb->state != KB_DONE) {
      return _key_broker_fail_w_msg (
         kb, "attempting retrieve decrypted key material, but in wrong state");
   }
   return _get_decrypted_key_material (kb,
                                       (_mongocrypt_buffer_t *) key_id,
                                       NULL /* key alt name */,
                                       out,
                                       NULL /* key id out */);
}

bool
_mongocrypt_key_broker_decrypted_key_by_name (
   _mongocrypt_key_broker_t *kb,
   const bson_value_t *key_alt_name_value,
   _mongocrypt_buffer_t *out,
   _mongocrypt_buffer_t *key_id_out)
{
   bool ret;
   _mongocrypt_key_alt_name_t *key_alt_name;

   if (kb->state != KB_DONE) {
      return _key_broker_fail_w_msg (
         kb, "attempting retrieve decrypted key material, but in wrong state");
   }

   key_alt_name = _mongocrypt_key_alt_name_new (key_alt_name_value);
   ret = _get_decrypted_key_material (kb, NULL, key_alt_name, out, key_id_out);
   _mongocrypt_key_alt_name_destroy_all (key_alt_name);
   return ret;
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


static void
_destroy_key_requests (key_request_t *head)
{
   key_request_t *tmp;

   while (head) {
      tmp = head->next;

      _mongocrypt_buffer_cleanup (&head->id);
      _mongocrypt_key_alt_name_destroy_all (head->alt_name);

      bson_free (head);
      head = tmp;
   }
}

static void
_destroy_keys_returned (key_returned_t *head)
{
   key_returned_t *tmp;

   while (head) {
      tmp = head->next;

      _mongocrypt_key_destroy (head->doc);
      _mongocrypt_buffer_cleanup (&head->decrypted_key_material);
      _mongocrypt_kms_ctx_cleanup (&head->kms);

      bson_free (head);
      head = tmp;
   }
}

void
_mongocrypt_key_broker_cleanup (_mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_destroy (kb->status);
   _mongocrypt_buffer_cleanup (&kb->filter);
   /* Delete all linked lists */
   _destroy_keys_returned (kb->keys_returned);
   _destroy_keys_returned (kb->keys_cached);
   _destroy_key_requests (kb->key_requests);
}

void
_mongocrypt_key_broker_add_test_key (_mongocrypt_key_broker_t *kb,
                                     const _mongocrypt_buffer_t *key_id)
{
   key_returned_t *key_returned;
   _mongocrypt_key_doc_t *key_doc;

   BSON_ASSERT (kb);
   key_doc = _mongocrypt_key_new ();
   _mongocrypt_buffer_copy_to (key_id, &key_doc->id);

   key_returned = _key_returned_prepend (kb, &kb->keys_returned, key_doc);
   key_returned->decrypted = true;
   _mongocrypt_buffer_init (&key_returned->decrypted_key_material);
   _mongocrypt_buffer_resize (&key_returned->decrypted_key_material,
                              MONGOCRYPT_KEY_LEN);
   memset (key_returned->decrypted_key_material.data, 0, MONGOCRYPT_KEY_LEN);
   _mongocrypt_key_destroy (key_doc);
   /* Hijack state and move directly to DONE. */
   kb->state = KB_DONE;
}