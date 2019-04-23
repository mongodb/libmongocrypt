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
                       void **out, /* copied to. */
                       mongocrypt_status_t *status)
{
   _mongocrypt_cache_pair_t *match;

   *out = NULL;
   _mongocrypt_mutex_lock (&cache->mutex);

   match = _find_pair (cache, attr);
   if (match) {
      *out = cache->copy_value (match->value);
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
   match = _find_pair (cache, attr);
   if (!match) {
      /* Create a new pair, add to head of list. */
      match = bson_malloc0 (sizeof (_mongocrypt_cache_pair_t));
      match->attr = cache->copy_attr (attr);
      match->next = cache->pair;
      cache->pair = match;
   } else {
      /* Clear out the existing value. */
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