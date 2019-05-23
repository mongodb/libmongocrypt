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


#include <stdlib.h>

#include <bson/bson.h>

#include "kms_message/kms_b64.h"

#include "mongocrypt.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-key-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"

/* =======================
   Some utility functions.
   ======================= */

static bool
_alt_names_equal (const bson_value_t *a, const bson_value_t *b)
{
   BSON_ASSERT (a);
   BSON_ASSERT (b);

   /* We now only accept string names. */
   /* TODO CDRIVER-2988 error instead of asserting here. */
   BSON_ASSERT (a->value_type == BSON_TYPE_UTF8);
   BSON_ASSERT (b->value_type == BSON_TYPE_UTF8);

   return (0 == strcmp (a->value.v_utf8.str, b->value.v_utf8.str));
}

/* =========================================
   Key broker entry and convenience methods.
   ========================================= */

/* TODO CDRIVER-3112 consider changing the linked list impl. */

typedef struct __key_alt_name_t {
   struct __key_alt_name_t *next;
   bson_value_t value;
} _key_alt_name_t;

struct __mongocrypt_key_broker_entry_t {
   mongocrypt_status_t *status;
   _mongocrypt_key_state_t state;
   /* owner_id differs from the key broker's owning context if and only if
    * state == KEY_WAITING_FOR_OTHER_CTX. */
   uint32_t owner_id;
   bool owns_cache_entry;
   _mongocrypt_buffer_t key_id;
   _key_alt_name_t *key_alt_names;
   _mongocrypt_key_doc_t *key_returned;
   mongocrypt_kms_ctx_t kms;
   _mongocrypt_buffer_t decrypted_key_material;

   struct __mongocrypt_key_broker_entry_t *prev;
   struct __mongocrypt_key_broker_entry_t *next;
};

static _mongocrypt_key_broker_entry_t *
_kbe_new ()
{
   _mongocrypt_key_broker_entry_t *kbe = bson_malloc0 (sizeof (*kbe));
   return kbe;
}

static bool
_kbe_has_name (_mongocrypt_key_broker_entry_t *kbe, const bson_value_t *value)
{
   _key_alt_name_t *ptr;

   BSON_ASSERT (value);

   ptr = kbe->key_alt_names;
   while (ptr) {
      if (_alt_names_equal (&ptr->value, value)) {
         return true;
      }
      ptr = ptr->next;
   }

   return false;
}

static void
_kbe_add_name (_mongocrypt_key_broker_entry_t *kbe, const bson_value_t *value)
{
   _key_alt_name_t *name;

   BSON_ASSERT (value);

   /* Don't add the name if we already have it. */
   if (_kbe_has_name (kbe, value)) {
      return;
   }

   name = bson_malloc0 (sizeof (*name));
   bson_value_copy (value, &name->value);
   name->next = kbe->key_alt_names;
   kbe->key_alt_names = name;
}

static void
_kbe_set_id (_mongocrypt_key_broker_entry_t *kbe,
             const _mongocrypt_buffer_t *id)
{
   if (_mongocrypt_buffer_empty (id)) {
      return;
   }

   _mongocrypt_buffer_copy_to (id, &kbe->key_id);
}

static void
_kbe_print (_mongocrypt_key_broker_entry_t *kbe)
{
   _key_alt_name_t *ptr;

   if (!_mongocrypt_buffer_empty (&kbe->key_id)) {
      const char *id;

      id = tmp_buf (&kbe->key_id);
      fprintf (stderr, "id: %s ", id);
   }

   fprintf (stderr, "names: ");

   ptr = kbe->key_alt_names;
   while (ptr) {
      fprintf (stderr, "%s, ", ptr->value.value.v_utf8.str);
      ptr = ptr->next;
   }

   fprintf (stderr, "state: ");

   switch (kbe->state) {
   case KEY_EMPTY:
      fprintf (stderr, "KEY_EMPTY");
      break;
   case KEY_ENCRYPTED:
      fprintf (stderr, "KEY_ENCRYPTED");
      break;
   case KEY_DECRYPTING:
      fprintf (stderr, "KEY_DECRYPTING");
      break;
   case KEY_DECRYPTED:
      fprintf (stderr, "KEY_DECRYPTED");
      break;
   case KEY_WAITING_FOR_OTHER_CTX:
      fprintf (stderr, "KEY_WAITING_FOR_OTHER_CTX");
      break;
   }


   fprintf (stderr, "\n");
}


static void
_kbe_destroy (_mongocrypt_key_broker_entry_t *kbe)
{
   _key_alt_name_t *ptr;
   _key_alt_name_t *next;

   ptr = kbe->key_alt_names;
   while (ptr) {
      next = ptr->next;
      bson_value_destroy (&ptr->value);
      bson_free (ptr);
      ptr = next;
   }

   mongocrypt_status_destroy (kbe->status);
   _mongocrypt_buffer_cleanup (&kbe->key_id);
   _mongocrypt_key_destroy (kbe->key_returned);
   _mongocrypt_kms_ctx_cleanup (&kbe->kms);
   _mongocrypt_buffer_cleanup (&kbe->decrypted_key_material);

   bson_free (kbe);
}

/* ============================
   Foreach methods and helpers.
   ============================ */

typedef bool (*_condition_fn_t) (_mongocrypt_key_broker_entry_t *kbe,
                                 void *ctx);

typedef bool (*_foreach_fn_t) (_mongocrypt_key_broker_entry_t *kbe, void *ctx);

/* Iterates over the entries in the key broker and calls
   the given callback function if the condition statement returns
   true. It is safe to remove the current element in the callback.

   If the foreach callback returns false when called on a match,
   iteration stops and we return false. */
static bool
_foreach_with_condition (_mongocrypt_key_broker_t *kb,
                         _condition_fn_t condition,
                         void *condition_ctx,
                         _foreach_fn_t foreach,
                         void *foreach_ctx)
{
   _mongocrypt_key_broker_entry_t *ptr;
   _mongocrypt_key_broker_entry_t *next;

   ptr = kb->kb_entry;

   while (ptr) {
      next = ptr->next;

      if (condition (ptr, condition_ctx)) {
         if (!foreach (ptr, foreach_ctx)) {
            return false;
         }
      }

      ptr = next;
   }

   return true;
}

/* Helper for print debugging */
static bool
_always_return_true (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   return true;
}

static bool
_print_single_kbe (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _kbe_print (kbe);
   return true;
}

static void
_print_entries (_mongocrypt_key_broker_t *kb)
{
   fprintf (stderr, "=======================================\n");
   fprintf (stderr, "Key broker entries:\n");

   _foreach_with_condition (
      kb, _always_return_true, NULL, _print_single_kbe, NULL);

   fprintf (stderr, "=======================================\n");
}


typedef struct {
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_key_broker_entry_t *mega_entry;
} _deduplicate_ctx_t;


/* This method is called with _foreach_with_condition to
   remove all matching elements from the key broker and condense
   them into one mega entry with the combined data. */
static bool
_deduplicate_entries (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _deduplicate_ctx_t *dedup_ctx;
   _key_alt_name_t *ptr;

   BSON_ASSERT (kbe);
   BSON_ASSERT (ctx);

   dedup_ctx = (_deduplicate_ctx_t *) ctx;

   /* Take the id, if there is one set. */
   _kbe_set_id (dedup_ctx->mega_entry, &kbe->key_id);

   /* Take all the key names that are set. */
   ptr = kbe->key_alt_names;
   while (ptr) {
      _kbe_add_name (dedup_ctx->mega_entry, &ptr->value);
      ptr = ptr->next;
   }

   /* If this key has a decrypted key, steal it, unless we
      have a conflict, then error. */
   if (kbe->key_returned) {
      if (dedup_ctx->mega_entry->key_returned) {
         if (!_mongocrypt_key_equal (kbe->key_returned,
                                     dedup_ctx->mega_entry->key_returned)) {
            /* TODO CDRIVER-3125. For now, take the newer one. */
            _mongocrypt_key_destroy (dedup_ctx->mega_entry->key_returned);
         }
      }

      dedup_ctx->mega_entry->state = kbe->state;
      dedup_ctx->mega_entry->key_returned = kbe->key_returned;
      kbe->key_returned = NULL;
   }

   BSON_ASSERT (kbe->state != KEY_DECRYPTING);
   /* Remove the old key entry. */
   if (kbe->prev) {
      kbe->prev->next = kbe->next;
   } else {
      /* if prev is NULL, should be at the head of the list. */
      dedup_ctx->kb->kb_entry = kbe->next;
      dedup_ctx->kb->decryptor_iter = kbe->next;
   }

   if (kbe->next) {
      kbe->next->prev = kbe->prev;
   }

   _kbe_destroy (kbe);

   return true;
}

typedef struct {
   int match_count;
} _count_ctx_t;

static bool
_count_matches (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _count_ctx_t *count_ctx;

   count_ctx = (_count_ctx_t *) ctx;
   count_ctx->match_count += 1;

   return true;
}

/* =================
   Matching helpers.
   ================= */

typedef struct {
   _mongocrypt_key_doc_t *key_doc;
   bool error;
} _key_doc_match_t;

static bool
_kbe_matches_key_doc (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _key_doc_match_t *helper;
   _mongocrypt_key_doc_t *key_doc;
   bson_iter_t iter;
   bson_t names;
   bool name_match = false;
   bool id_match = false;

   helper = (_key_doc_match_t *) ctx;
   key_doc = helper->key_doc;
   BSON_ASSERT (key_doc);

   /* A key doc has an ID and may also have keyAltNames.
      An entry matches this doc if it matches the key ID
      or any of the keyAltNames.

      If the key doc matches one or more keyAltNames, but
      does NOT have the same id, this is an error. */
   if (key_doc->has_alt_names) {
      bson_init_static (&names,
                        key_doc->key_alt_names.value.v_doc.data,
                        key_doc->key_alt_names.value.v_doc.data_len);

      bson_iter_init (&iter, &names);

      while (bson_iter_next (&iter)) {
         if (_kbe_has_name (kbe, bson_iter_value (&iter))) {
            name_match = true;
            break;
         }
      }
   }

   if (name_match) {
      /* If we have a name match and a returned key doc, then
    the doc must also match our id or it is an error. */
      /* TODO CDRIVER-3125 clean this up with the logic below */
      if (kbe->key_returned) {
         if (0 !=
             _mongocrypt_buffer_cmp (&kbe->key_returned->id, &key_doc->id)) {
            helper->error = true;
            return false;
         }
      }
   }

   if (0 == _mongocrypt_buffer_cmp (&kbe->key_id, &key_doc->id)) {
      id_match = true;
   }

   /* If we match an entry with a decrypted key doc,
      it should match our new one. */
   if (name_match || id_match) {
      if (kbe->key_returned) {
         if (!_mongocrypt_key_equal (kbe->key_returned, key_doc)) {
            /* TODO CDRIVER-3125 */
         }
      }
   }

   return (name_match || id_match);
}

static bool
_kbe_matches_descriptor (_mongocrypt_key_broker_entry_t *kbe,
                         const void *key_descriptor,
                         bool is_alt_name)
{
   if (is_alt_name) {
      return _kbe_has_name (kbe, (bson_value_t *) key_descriptor);
   } else {
      _mongocrypt_buffer_t *key_id = (_mongocrypt_buffer_t *) key_descriptor;

      if (0 == _mongocrypt_buffer_cmp (&kbe->key_id, key_id)) {
         return true;
      }
   }

   return false;
}


static _mongocrypt_key_broker_entry_t *
_get_first_match_by_descriptor (_mongocrypt_key_broker_t *kb,
                                const void *key_descriptor,
                                bool is_alt_name)
{
   _mongocrypt_key_broker_entry_t *kbe;

   /* TODO CDRIVER-3113, use foreach helpers */
   for (kbe = kb->kb_entry; kbe; kbe = kbe->next) {
      if (_kbe_matches_descriptor (kbe, key_descriptor, is_alt_name)) {
         return kbe;
      }
   }

   return NULL;
}


static bool
_return_first_match (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _mongocrypt_key_broker_entry_t **out;

   out = (_mongocrypt_key_broker_entry_t **) ctx;
   *out = kbe;

   return false;
}


static _mongocrypt_key_broker_entry_t *
_get_first_match_by_key_doc (_mongocrypt_key_broker_t *kb,
                             _mongocrypt_key_doc_t *key_doc)
{
   _key_doc_match_t match_helper;
   _mongocrypt_key_broker_entry_t *kbe = NULL;

   match_helper.key_doc = key_doc;

   _foreach_with_condition (
      kb, _kbe_matches_key_doc, &match_helper, _return_first_match, &kbe);

   return kbe;
}

/* =================
   External methods.
   ================= */

void
_mongocrypt_key_broker_init (_mongocrypt_key_broker_t *kb,
                             uint32_t owner_id,
                             _mongocrypt_opts_t *opts,
                             _mongocrypt_cache_t *cache_key)
{
   memset (kb, 0, sizeof (*kb));
   kb->status = mongocrypt_status_new ();
   kb->crypt_opts = opts;
   kb->cache_key = cache_key;
   kb->owner_id = owner_id;
}


bool
_mongocrypt_key_broker_any_state (_mongocrypt_key_broker_t *kb,
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
_mongocrypt_key_broker_all_state (_mongocrypt_key_broker_t *kb,
                                  _mongocrypt_key_state_t state)
{
   _mongocrypt_key_broker_entry_t *ptr;

   for (ptr = kb->kb_entry; ptr != NULL; ptr = ptr->next) {
      if (ptr->state != state) {
         return false;
      }
   }
   return true;
}


/* Returns false on error. */
static bool
_try_retrieving_from_cache (_mongocrypt_key_broker_t *kb,
                            _mongocrypt_key_broker_entry_t *kbe)
{
   _mongocrypt_cache_key_value_t *value;
   _mongocrypt_cache_pair_state_t state;
   uint32_t pair_owner_id;
   mongocrypt_status_t *status;

   status = kb->status;

   if (kbe->state != KEY_EMPTY && kbe->state != KEY_WAITING_FOR_OTHER_CTX) {
      CLIENT_ERR ("trying to retrieve key from cache in invalid state");
      return false;
   }

   _mongocrypt_cache_get_or_create (kb->cache_key,
                                    &kbe->key_id,
                                    (void **) &value,
                                    &state,
                                    kb->owner_id,
                                    &pair_owner_id);

   switch (state) {
   case CACHE_PAIR_DONE:
      kbe->state = KEY_DECRYPTED;
      if (_mongocrypt_buffer_empty (&value->decrypted_key_material)) {
         CLIENT_ERR ("key in cache has no decrypted value");
         return false;
      }
      kbe->key_returned = _mongocrypt_key_new ();
       _mongocrypt_key_doc_copy_to (value->key_doc, kbe->key_returned);
      _mongocrypt_buffer_copy_to (&value->decrypted_key_material,
                                  &kbe->decrypted_key_material);
      _mongocrypt_cache_key_value_destroy (value);
      break;
   case CACHE_PAIR_PENDING:
      /* Either we're responsible for fetching it, or we're waiting on someone
       * else. */
      if (pair_owner_id != kb->owner_id) {
         kbe->state = KEY_WAITING_FOR_OTHER_CTX;
         kbe->owner_id = pair_owner_id;
      } else {
         /* Otherwise, we own it and need to fetch it. */
         kbe->state = KEY_EMPTY;
         kbe->owner_id = kb->owner_id;
      }
   }

   return true;
}


/*
 * Call when you've satisfied all key requests owned, or if you've waited
 * and think other dependent cache entries may be fulfilled.
 *
 * If blocking_wait is true, this function will block until one of the
 * following:
 *    - a key is discovered to be in KEY_EMPTY state (we need to fetch it)
 *    - all keys are retrieved from cache
 *    - we expire the 10 second timeout
 */
bool
_mongocrypt_key_broker_check_cache_and_wait (_mongocrypt_key_broker_t *kb,
                                             bool blocking_wait)
{
   _mongocrypt_key_broker_entry_t *kbe;
   bool some_keys_waiting, some_keys_empty;
   mongocrypt_status_t *status;

   status = kb->status;

   /* reset the ctx id iterator. */
   kb->ctx_id_iter = kb->kb_entry;

   while (true) {
      /* reset. */
      some_keys_waiting = false;
      some_keys_empty = false;

      for (kbe = kb->kb_entry; kbe != NULL; kbe = kbe->next) {
         switch (kbe->state) {
         case KEY_WAITING_FOR_OTHER_CTX:
            some_keys_waiting = true;
            _try_retrieving_from_cache (kb, kbe);
            break;
         case KEY_DECRYPTED:
            /* Nothing to do. */
            continue;
         case KEY_EMPTY:
            some_keys_empty = true;
            break;
         case KEY_ENCRYPTED:
         case KEY_DECRYPTING:
            CLIENT_ERR ("key in invalid state");
            return false;
         }
      }

      if (some_keys_empty) {
         /* We've taken ownership of some keys. */
         return true;
      }

      if (!some_keys_waiting) {
         /* Nothing to wait for. */
         return true;
      }

      if (blocking_wait) {
         /* TODO CDRIVER-2951: Only retry for a maximum of 10 seconds. */
         if (!_mongocrypt_cache_wait (kb->cache_key, kb->status)) {
            return false;
         }
      } else {
         return true;
      }
   }

   return true;
}


void
_mongocrypt_key_broker_reset_iterators (_mongocrypt_key_broker_t *kb)
{
   kb->ctx_id_iter = kb->kb_entry;
   kb->decryptor_iter = kb->kb_entry;
}


/* Call to iterate over dependent context ids. Only applicable for non-blocking
 * contexts. The iteration is reset on calls to
 * _mongocrypt_key_broker_check_cache_and_wait. */
uint32_t
_mongocrypt_key_broker_next_ctx_id (_mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);

   kbe = kb->ctx_id_iter;

   while (kbe && kbe->state != KEY_WAITING_FOR_OTHER_CTX) {
      kbe = kbe->next;
   }

   if (kbe) {
      kb->ctx_id_iter = kbe->next;
      return kbe->owner_id;
   } else {
      kb->ctx_id_iter = NULL;
      return 0;
   }
}


static bool
_store_to_cache (_mongocrypt_key_broker_t *kb,
                 _mongocrypt_key_broker_entry_t *kbe)
{
   _mongocrypt_cache_key_value_t *value;
   bool ret;

   if (kbe->state != KEY_DECRYPTED) {
      mongocrypt_status_t *status = kb->status;
      CLIENT_ERR ("cannot cache non-decrypted key");
      return false;
   }

   value = _mongocrypt_cache_key_value_new (kbe->key_returned,
                                            &kbe->decrypted_key_material);
   ret = _mongocrypt_cache_add_stolen (
      kb->cache_key, &kbe->key_id, value, kb->owner_id, kb->status);
   return ret;
}


static void
_add_new_key_entry (_mongocrypt_key_broker_t *kb,
                    _mongocrypt_key_broker_entry_t *kbe)
{
   kbe->state = KEY_EMPTY;
   if (kb->kb_entry) {
      kb->kb_entry->prev = kbe;
   }
   kbe->next = kb->kb_entry;
   kbe->prev = NULL;
   kb->kb_entry = kbe;
   kb->decryptor_iter = kbe;
   kb->ctx_id_iter = kbe;
}


bool
_mongocrypt_key_broker_add_name (_mongocrypt_key_broker_t *kb,
                                 const bson_value_t *key_alt_name)
{
   _mongocrypt_key_broker_entry_t *kbe;
   mongocrypt_status_t *status = kb->status;

   BSON_ASSERT (key_alt_name);
   if (_mongocrypt_key_broker_any_state (kb, KEY_DECRYPTING)) {
      CLIENT_ERR ("already decrypting; too late to add new keys");
      return false;
   }

   /* If we already have this key, return */
   if (_get_first_match_by_descriptor (kb, key_alt_name, true)) {
      return true;
   }

   /* TODO CDRIVER-2951 check if we have this key cached. */
   kbe = _kbe_new ();
   _kbe_add_name (kbe, key_alt_name);
   _add_new_key_entry (kb, kbe);

   return true;
}


bool
_mongocrypt_key_broker_add_id (_mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id)
{
   _mongocrypt_key_broker_entry_t *kbe = NULL;
   mongocrypt_status_t *status = kb->status;

   status = kb->status;
   if (key_id->subtype != BSON_SUBTYPE_UUID) {
      CLIENT_ERR ("expected UUID for key_id");
      return false;
   }

   if (_mongocrypt_key_broker_any_state (kb, KEY_DECRYPTING)) {
      CLIENT_ERR ("already decrypting; too late to add new keys");
      return false;
   }

   /* If we already have this key, return */
   if (_get_first_match_by_descriptor (kb, (void *) key_id, false)) {
      return true;
   }

   kbe = _kbe_new ();
   _kbe_set_id (kbe, key_id);
   _add_new_key_entry (kb, kbe);

   /* If we have a cached decrypted key for this id, add
      it to our local entry now. */
   if (!_try_retrieving_from_cache (kb, kbe)) {
      return false;
   }

   return true;
}


bool
_mongocrypt_key_broker_add_test_key (_mongocrypt_key_broker_t *kb,
                                     const _mongocrypt_buffer_t *key_id)
{
   BSON_ASSERT (kb);
   _mongocrypt_buffer_t key_material;

   if (!_mongocrypt_key_broker_add_id (kb, key_id)) {
      return false;
   }

   _mongocrypt_buffer_init (&key_material);
   _mongocrypt_buffer_resize (&key_material, MONGOCRYPT_KEY_LEN);
   memset (key_material.data, 0, MONGOCRYPT_KEY_LEN);

   /* The first entry in the list should be our new one. Modify
      it so that it is in a decrypted state for testing. Use a random 96
      byte key as the decrypted material, because it doesn't matter. */
   BSON_ASSERT (kb->kb_entry);
   kb->kb_entry->state = KEY_DECRYPTED;
   _mongocrypt_buffer_copy_to (&key_material,
                               &kb->kb_entry->decrypted_key_material);

   _mongocrypt_buffer_cleanup (&key_material);

   return true;
}


bool
_mongocrypt_key_broker_add_doc (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc)
{
   _key_doc_match_t match_helper;
   _mongocrypt_kms_provider_t masterkey_provider;
   _count_ctx_t count_ctx;
   mongocrypt_status_t *status;
   bson_t doc_bson;
   _mongocrypt_key_doc_t *key = NULL;
   _mongocrypt_key_broker_entry_t *kbe = NULL;
   bool ret;

   BSON_ASSERT (kb);
   ret = false;
   status = kb->status;

   if (_mongocrypt_key_broker_any_state (kb, KEY_DECRYPTING)) {
      CLIENT_ERR ("already decrypting; too late to add new key docs");
      return false;
   }

   if (!doc) {
      CLIENT_ERR ("invalid key");
      goto done;
   }

   /* First, parse the key document. */
   key = _mongocrypt_key_new ();
   _mongocrypt_buffer_to_bson (doc, &doc_bson);
   if (!_mongocrypt_key_parse_owned (&doc_bson, key, status)) {
      goto done;
   }

   /* Check that the returned key doc's provider matches. */
   masterkey_provider = key->masterkey_provider;
   if (0 == (masterkey_provider & kb->crypt_opts->kms_providers)) {
      CLIENT_ERR (
         "client not configured with KMS provider necessary to decrypt");
      goto done;
   }

   /* Next, ensure that we have at least one matching key broker
      entry for this key doc. */
   match_helper.key_doc = key;
   match_helper.error = false;
   count_ctx.match_count = 0;
   _foreach_with_condition (
      kb, _kbe_matches_key_doc, &match_helper, _count_matches, &count_ctx);

   if (match_helper.error) {
      CLIENT_ERR ("matching keyAltNames with non-matching id");
      goto done;
   }

   if (count_ctx.match_count == 0) {
      CLIENT_ERR ("no matching key in the key broker");
      goto done;
   }

   if (count_ctx.match_count > 1) {
      _deduplicate_ctx_t dedup_ctx;

      dedup_ctx.kb = kb;
      dedup_ctx.mega_entry = _kbe_new ();

      /* Now, deduplicate all matches by making one new entry
    that contains the id and all the collected key names. */
      _foreach_with_condition (kb,
                               _kbe_matches_key_doc,
                               &match_helper,
                               _deduplicate_entries,
                               &dedup_ctx);

      /* Then, add the mega entry back into the key broker. */
      kbe = dedup_ctx.mega_entry;
      kbe->next = kb->kb_entry;
      kbe->prev = NULL;
      kb->kb_entry = kbe;
      kb->decryptor_iter = kbe;
   } else {
      /* If we just found a single matching key, use it as-is. */
      kbe = _get_first_match_by_key_doc (kb, key);
      BSON_ASSERT (kbe);
   }

   /* If our matching entry already has a key document,
      it either came from our cache, or from deduplicating.
      Either way, use theirs, not ours (TODO CDRIVER-3125) */
   if (kbe->key_returned) {
      ret = true;
      goto done;
   }

   /* We will now take ownership of the key document. */
   kbe->key_returned = key;
   key = NULL;

   kbe->state = KEY_ENCRYPTED;

   /* Check that the mongocrypt_t was configured with the KMS
      provider needed. */
   if (masterkey_provider == MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      bool crypt_ret;
      uint32_t bytes_written;

      kbe->decrypted_key_material.len = _mongocrypt_calculate_plaintext_len (
         kbe->key_returned->key_material.len);
      kbe->decrypted_key_material.data =
         bson_malloc (kbe->decrypted_key_material.len);
      kbe->decrypted_key_material.owned = true;

      crypt_ret = _mongocrypt_do_decryption (NULL /* associated data. */,
                                             &kb->crypt_opts->kms_local_key,
                                             &kbe->key_returned->key_material,
                                             &kbe->decrypted_key_material,
                                             &bytes_written,
                                             status);
      kbe->decrypted_key_material.len = bytes_written;

      if (!crypt_ret) {
         goto done;
      }

      kbe->state = KEY_DECRYPTED;
      _store_to_cache (kb, kbe);

   } else if (masterkey_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      if (!_mongocrypt_kms_ctx_init_aws_decrypt (
             &kbe->kms, kb->crypt_opts, kbe->key_returned, kbe)) {
         mongocrypt_kms_ctx_status (&kbe->kms, status);
         goto done;
      }
   } else {
      CLIENT_ERR ("unrecognized kms provider");
      goto done;
   }

   ret = true;

done:
   _mongocrypt_key_destroy (key);

   return ret;
}


mongocrypt_kms_ctx_t *
_mongocrypt_key_broker_next_kms (_mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);

   if (!_mongocrypt_key_broker_any_state (kb, KEY_DECRYPTING)) {
      kb->decryptor_iter = kb->kb_entry;
   }

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

   status = kb->status;
   for (kbe = kb->kb_entry; kbe != NULL; kbe = kbe->next) {
      switch (kbe->state) {
      case KEY_DECRYPTED:
      case KEY_WAITING_FOR_OTHER_CTX:
         /* Nothing to do. */
         continue;
      case KEY_EMPTY:
      case KEY_ENCRYPTED:
         CLIENT_ERR ("key broker in invalid state");
         return false;
      case KEY_DECRYPTING:
         if (!_mongocrypt_kms_ctx_result (&kbe->kms,
                                          &kbe->decrypted_key_material)) {
            /* Always fatal. Key attempted to decrypt but failed. */
            mongocrypt_kms_ctx_status (&kbe->kms, status);
            return false;
         }
         kbe->state = KEY_DECRYPTED;
         _store_to_cache (kb, kbe);
         break;
      }
   }
   return true;
}


static bool
_get_decrypted_key (_mongocrypt_key_broker_t *kb,
                    const void *key_descriptor,
                    _mongocrypt_buffer_t *out,
                    bool is_alt_name,
                    _mongocrypt_buffer_t *key_id_out)
{
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);
   status = kb->status;

   kbe = _get_first_match_by_descriptor (kb, key_descriptor, is_alt_name);
   if (!kbe) {
      CLIENT_ERR ("no matching key found");
      return false;
   }

   if (kbe->state != KEY_DECRYPTED) {
      CLIENT_ERR ("key found, but material not decrypted");
      return false;
   }

   _mongocrypt_buffer_init (out);
   _mongocrypt_buffer_copy_to (&kbe->decrypted_key_material, out);

   if (key_id_out) {
      /* looking up by keyAltName may want key_id too */
      _mongocrypt_buffer_init (key_id_out);
      _mongocrypt_buffer_copy_to (&kbe->key_returned->id, key_id_out);
   }

   return true;
}


bool
_mongocrypt_key_broker_decrypted_key_by_id (_mongocrypt_key_broker_t *kb,
                                            const _mongocrypt_buffer_t *key_id,
                                            _mongocrypt_buffer_t *out)
{
   return _get_decrypted_key (kb, (void *) key_id, out, false, NULL);
}


bool
_mongocrypt_key_broker_decrypted_key_by_name (_mongocrypt_key_broker_t *kb,
                                              const bson_value_t *key_alt_name,
                                              _mongocrypt_buffer_t *out,
                                              _mongocrypt_buffer_t *key_id_out)
{
   return _get_decrypted_key (kb, key_alt_name, out, true, key_id_out);
}


bool
_mongocrypt_key_broker_filter (_mongocrypt_key_broker_t *kb,
                               mongocrypt_binary_t *out)
{
   _mongocrypt_key_broker_entry_t *iter;
   _key_alt_name_t *ptr;
   int name_index = 0;
   int id_index = 0;
   bson_t ids, names;
   bson_t *filter;
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);

   status = kb->status;
   if (!_mongocrypt_buffer_empty (&kb->filter)) {
      _mongocrypt_buffer_to_binary (&kb->filter, out);
      return true;
   }

   if (!_mongocrypt_key_broker_any_state (kb, KEY_EMPTY)) {
      CLIENT_ERR ("attempting to get filter, but no keys to fetch");
      return false;
   }

   bson_init (&names);
   bson_init (&ids);

   for (iter = kb->kb_entry; iter != NULL; iter = iter->next) {
      if (iter->state != KEY_EMPTY) {
         continue;
      }

      if (!_mongocrypt_buffer_empty (&iter->key_id)) {
         /* Collect key_ids in "ids" */
         char *key_str;

         key_str = bson_strdup_printf ("%d", id_index++);
         _mongocrypt_buffer_append (
            &iter->key_id, &ids, key_str, (uint32_t) strlen (key_str));

         bson_free (key_str);
      }

      /* Collect key alt names in "names" */
      ptr = iter->key_alt_names;
      while (ptr) {
         char *key_str;

         key_str = bson_strdup_printf ("%d", name_index++);
         bson_append_value (
            &names, key_str, (uint32_t) strlen (key_str), &ptr->value);

         bson_free (key_str);
         ptr = ptr->next;
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
      _kbe_destroy (kbe);
      kbe = tmp;
   }

   kb->kb_entry = NULL;

   mongocrypt_status_destroy (kb->status);
   _mongocrypt_buffer_cleanup (&kb->filter);
}
