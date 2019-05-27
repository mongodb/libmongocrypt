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
#define CACHE_EXPIRATION_MS 60000


/* caller must hold lock. */
static bool
_find_pair (_mongocrypt_cache_t *cache,
            void *attr,
            _mongocrypt_cache_pair_t **out)
{
   _mongocrypt_cache_pair_t *pair;

   *out = NULL;

   pair = cache->pair;
   while (pair) {
      int res;
      /* TODO: this is a naive O(n) lookup. Consider optimizing
         with a hash map (possibly vendor one). */
      if (!cache->cmp_attr (pair->attr, attr, &res)) {
         return false;
      }

      if (res == 0) {
         *out = pair;
         return true;
      }
      pair = pair->next;
   }
   *out = NULL;
   return true;
}


/* Create a new pair on linked list. Caller must hold lock. */
static _mongocrypt_cache_pair_t *
_pair_new (_mongocrypt_cache_t *cache, void *attr)
{
   _mongocrypt_cache_pair_t *pair;

   pair = bson_malloc0 (sizeof (_mongocrypt_cache_pair_t));
   pair->attr = cache->copy_attr (attr);
   /* add rest of values. */
   pair->next = cache->pair;
   pair->last_updated = bson_get_monotonic_time () / 1000;
   cache->pair = pair;
   return pair;
}


/* Did the cache pair expire? Caller must hold lock. */
static bool
_pair_expired (_mongocrypt_cache_pair_t *pair)
{
   int64_t current;

   current = bson_get_monotonic_time () / 1000;
   return current - pair->last_updated > CACHE_EXPIRATION_MS;
}


/* Caller must hold lock. */
static void
_cache_pair_destroy (_mongocrypt_cache_t *cache, _mongocrypt_cache_pair_t *pair)
{
   cache->destroy_attr (pair->attr);
   cache->destroy_value (pair->value);
   bson_free (pair);
}


bool
_mongocrypt_cache_get (_mongocrypt_cache_t *cache,
                       void *attr, /* attr of cache item */
                       void **value /* copied to. */)
{
   _mongocrypt_cache_pair_t *match;

   *value = NULL;

   _mongocrypt_mutex_lock (&cache->mutex);

   if (!_find_pair (cache, attr, &match)) {
      return false;
   }

   if (match) {
      *value = cache->copy_value (match->value);
   }
   _mongocrypt_mutex_unlock (&cache->mutex);
   return true;
}


static bool
_cache_add (_mongocrypt_cache_t *cache,
            void *attr,
            void *value,
            mongocrypt_status_t *status,
            bool steal_value)
{
   _mongocrypt_cache_pair_t *match;

   _mongocrypt_mutex_lock (&cache->mutex);
   /* TODO CDRIVER-2951, since keys have multiple identifiers, remove all
    * matches first. */
   if (!_find_pair (cache, attr, &match)) {
      CLIENT_ERR ("error checking cache");
      return false;
   }
   if (!match) {
      match = _pair_new (cache, attr);
   } else {
      /* delete the existing value. */
      cache->destroy_value (match->value);
   }

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
                            mongocrypt_status_t *status)
{
   return _cache_add (cache, attr, value, status, false);
}


bool
_mongocrypt_cache_add_stolen (_mongocrypt_cache_t *cache,
                              void *attr,
                              void *value,
                              mongocrypt_status_t *status)
{
   return _cache_add (cache, attr, value, status, true);
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
      printf ("entry:%d\n\tlast_updated:%d\n", count, (int) pair->last_updated);
      count++;
   }

   _mongocrypt_mutex_unlock (&cache->mutex);
}


bool
_mongocrypt_cache_evict (_mongocrypt_cache_t *cache)
{
   /* TODO CDRIVER-2951 */
   return false;
}
