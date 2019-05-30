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

#include "mongocrypt-cache-private.h"

#include "mongocrypt-private.h"

/* TODO: CDRIVER-2951 test expiration. */
/* a cache entry in PENDING state expires after: */
#define CACHE_PENDING_EXPIRATION_MS 10000
/* a cache entry in DONE state expires after: */
#define CACHE_DONE_EXPIRATION_MS 60000


/* caller must hold lock. */
static _mongocrypt_cache_pair_t *
_find_pair (_mongocrypt_cache_t *cache, void *attr)
{
   /* TODO: verify that this thread owns the cache mutex? */
   _mongocrypt_cache_pair_t *pair;

   pair = cache->pair;
   while (pair) {
      /* TODO: this is a naive O(n) lookup. Consider optimizing
         with a hash map (possibly vendor one). */
      if (0 == cache->cmp_attr (pair->attr, attr)) {
         return pair;
      }
      pair = pair->next;
   }
   return NULL;
}

/* Clear value and state. Caller must hold lock. */
static void
_pair_reinit (_mongocrypt_cache_t *cache,
              _mongocrypt_cache_pair_t *pair,
              uint32_t owner_id)
{
   cache->destroy_value (pair->value);
   pair->value = NULL;
   pair->owner_id = owner_id;
   pair->state = CACHE_PAIR_PENDING;
   pair->last_updated = bson_get_monotonic_time () / 1000;
}


/* Create a new pair on linked list. Caller must hold lock. */
static _mongocrypt_cache_pair_t *
_pair_new (_mongocrypt_cache_t *cache, void *attr, uint32_t owner_id)
{
   _mongocrypt_cache_pair_t *pair;

   pair = bson_malloc0 (sizeof (_mongocrypt_cache_pair_t));
   pair->attr = cache->copy_attr (attr);
   /* add rest of values. */
   _pair_reinit (cache, pair, owner_id);
   pair->next = cache->pair;
   cache->pair = pair;
   return pair;
}


/* Did the cache pair expire? Caller must hold lock. */
static bool
_pair_expired (_mongocrypt_cache_pair_t *pair)
{
   int64_t current;

   current = bson_get_monotonic_time () / 1000;
   switch (pair->state) {
   case CACHE_PAIR_PENDING:
      return current - pair->last_updated > CACHE_PENDING_EXPIRATION_MS;
   case CACHE_PAIR_DONE:
      return current - pair->last_updated > CACHE_DONE_EXPIRATION_MS;
   }
   return true;
}


/* Caller must hold lock. */
static void
_cache_pair_destroy (_mongocrypt_cache_t *cache, _mongocrypt_cache_pair_t *pair)
{
   cache->destroy_attr (pair->attr);
   cache->destroy_value (pair->value);
   bson_free (pair);
}


void
_mongocrypt_cache_get_or_create (_mongocrypt_cache_t *cache,
                                 void *attr,   /* attr of cache item */
                                 void **value, /* copied to. */
                                 _mongocrypt_cache_pair_state_t *state,
                                 uint32_t owner_in,
                                 uint32_t *owner_out)
{
   _mongocrypt_cache_pair_t *match;

   *value = NULL;

   _mongocrypt_mutex_lock (&cache->mutex);

   match = _find_pair (cache, attr);
   if (!match) {
      /* create a new PENDING pair. */
      match = _pair_new (cache, attr, owner_in);
   } else if (_pair_expired (match)) {
      /* TODO CDRIVER-2951: as an optimization. Don't throw this away. If the
       * key
       * hasn't changed since expiration, the key broker can save an unnecessary
       * KMS request. */
      _pair_reinit (cache, match, owner_in);
   }

   /* match is either a new entry or an existing entry. Set out params. */
   if (match->state == CACHE_PAIR_DONE) {
      *value = cache->copy_value (match->value);
   }

   *state = match->state;
   *owner_out = match->owner_id;

   _mongocrypt_mutex_unlock (&cache->mutex);
}


static bool
_cache_add (_mongocrypt_cache_t *cache,
            void *attr,
            void *value,
            uint32_t owner_id,
            mongocrypt_status_t *status,
            bool steal_value)
{
   _mongocrypt_cache_pair_t *match;

   _mongocrypt_mutex_lock (&cache->mutex);
   match = _find_pair (cache, attr);
   if (!match) {
      match = _pair_new (cache, attr, owner_id);
   } else if (match->owner_id != owner_id) {
      /* Cache pair has transferred ownership. Don't overwrite. */
      _mongocrypt_mutex_unlock (&cache->mutex);
      return true;
   } else if (match->state == CACHE_PAIR_DONE) {
      /* This is considered an error. If the owner hasn't changed, there
       * should be no situation where the same context adds the same key
       * twice. This would be a bug in our code, but don't abort. */
      CLIENT_ERR ("cache error - attempting to do an invalid overwrite");
      _mongocrypt_mutex_unlock (&cache->mutex);
      return false;
   }

   /* match is owned by us, and in PENDING state. */
   match->owner_id = 0; /* relinquish ownership. */
   match->state = CACHE_PAIR_DONE;

   if (steal_value) {
      match->value = value;
   } else {
      match->value = cache->copy_value (value);
   }
   _mongocrypt_mutex_unlock (&cache->mutex);
   return true;
}

bool
_mongocrypt_cache_add_copy (_mongocrypt_cache_t *cache,
                            void *attr,
                            void *value,
                            uint32_t owner_id,
                            mongocrypt_status_t *status)
{
   return _cache_add (cache, attr, value, owner_id, status, false);
}


bool
_mongocrypt_cache_add_stolen (_mongocrypt_cache_t *cache,
                              void *attr,
                              void *value,
                              uint32_t owner_id,
                              mongocrypt_status_t *status)
{
   return _cache_add (cache, attr, value, owner_id, status, true);
}

void
_mongocrypt_cache_cleanup (_mongocrypt_cache_t *cache)
{
   _mongocrypt_cache_pair_t *pair, *tmp;

   pair = cache->pair;
   while (pair) {
      tmp = pair->next;
      _cache_pair_destroy (cache, pair);
      pair = tmp;
   }
}

/* Print the contents of the cache (for debugging purposes) */
void
_mongocrypt_cache_dump (_mongocrypt_cache_t *cache)
{
   _mongocrypt_cache_pair_t *pair;
   int count;

   _mongocrypt_mutex_lock (&cache->mutex);
   count = 1;
   for (pair = cache->pair; pair != NULL; pair = pair->next) {
      printf ("entry:%d\n\towner_id:%d\n\tstatus:%s\n\tlast_updated:%d\n",
              count,
              (int) pair->owner_id,
              pair->state == CACHE_PAIR_PENDING ? "P" : "D",
              (int) pair->last_updated);
      count++;
   }

   _mongocrypt_mutex_unlock (&cache->mutex);
}


bool
_mongocrypt_cache_wait (_mongocrypt_cache_t *cache, mongocrypt_status_t *status)
{
   return true;
}


void
_mongocrypt_cache_remove_by_owner (_mongocrypt_cache_t *cache,
                                   uint32_t owner_in)
{
   _mongocrypt_cache_pair_t *pair, *prev, *next;

   prev = NULL;
   pair = cache->pair;
   while (pair) {
      next = pair->next;
      if (pair->owner_id == owner_in) {
         if (!prev) {
            cache->pair = next;
         } else {
            prev->next = next;
         }
         _cache_pair_destroy (cache, pair);
      } else {
         prev = pair;
      }
      pair = next;
   }
}

bool
_mongocrypt_cache_evict (_mongocrypt_cache_t *cache)
{
   /* TODO CDRIVER-2951 */
   return false;
}
