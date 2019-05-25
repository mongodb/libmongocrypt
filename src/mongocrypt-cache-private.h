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
#ifndef MONGOCRYPT_CACHE_PRIVATE
#define MONGOCRYPT_CACHE_PRIVATE

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-mutex-private.h"
#include "mongocrypt-status-private.h"

/* A generic simple cache.
 * To avoid overusing the names "key" or "id", the cache contains
 * "attribute-value" pairs.
 * https://en.wikipedia.org/wiki/Attribute%E2%80%93value_pair
 */
typedef bool (*cache_compare_fn) (void *thing_a, void *thing_b, int *out);
typedef void (*cache_destroy_fn) (void *thing);
typedef void *(*cache_copy_fn) (void *thing);


typedef enum {
   CACHE_PAIR_PENDING,
   CACHE_PAIR_DONE
} _mongocrypt_cache_pair_state_t;

typedef struct __mongocrypt_cache_pair_t {
   void *attr;
   void *value;
   struct __mongocrypt_cache_pair_t *next;
   _mongocrypt_cache_pair_state_t state;
   /* if state==PENDING, then owner_id refers to the context responsible for
    * fulfilling this cache entry. if state==DONE, then owner_id is 0. */
   uint32_t owner_id;
   /* last_updated refers to the last time the state has changed in
    * milliseconds. */
   int64_t last_updated;
} _mongocrypt_cache_pair_t;

typedef struct {
   cache_compare_fn cmp_attr;
   cache_copy_fn copy_attr;
   cache_destroy_fn destroy_attr;
   cache_copy_fn copy_value;
   cache_destroy_fn destroy_value;
   _mongocrypt_cache_pair_t *pair;
   mongocrypt_mutex_t mutex; /* global lock of cache. */
} _mongocrypt_cache_t;


/* Attempt to get an entry. If it doesn't exist (or is expired and removed),
 * create one with PENDING state and owned by owner_in.
 * @param[in] attr The attribute to search for.
 * @param[out] value The output value. Set to NULL if not found or
 * state==PENDING.
 * @param[out] state The state of the cache item. If DONE, then value is set. If
 * PENDING, then owner_out indicates the context responsible for fetching.
 * @param[in] owner_in The owner id of the context attempting to get this item.
 * @param[out] owner_out Set to the owner of the entry. This may be set to
 * owner_in if ownership of the cache pair is transferred.
 * Returns boolean indicating success.
 */
bool
_mongocrypt_cache_get_or_create (_mongocrypt_cache_t *cache,
                                 void *attr,
                                 void **value,
                                 _mongocrypt_cache_pair_state_t *state,
                                 uint32_t owner_in,
                                 uint32_t *owner_out);


/* Remove a PENDING cache entry with a matching owner id */
void
_mongocrypt_cache_remove_by_owner (_mongocrypt_cache_t *cache,
                                   uint32_t owner_in);


bool
_mongocrypt_cache_add_copy (_mongocrypt_cache_t *cache,
                            void *attr,
                            void *value,
                            uint32_t owner_id,
                            mongocrypt_status_t *status);


/* Steals the value instead of copying. Caller relinquishes value when calling.
 */
bool
_mongocrypt_cache_add_stolen (_mongocrypt_cache_t *cache,
                              void *attr,
                              void *value,
                              uint32_t owner_id,
                              mongocrypt_status_t *status);


void
_mongocrypt_cache_cleanup (_mongocrypt_cache_t *cache);


/* Do a blocking wait on the cache. Blocks until an item in the cache changes
 * state. */
bool
_mongocrypt_cache_wait (_mongocrypt_cache_t *cache,
                        mongocrypt_status_t *status);

/* Evict expired entries. */
bool
_mongocrypt_cache_evict (_mongocrypt_cache_t *cache);

/* A helper debug function to dump the state of the cache. */
void
_mongocrypt_cache_dump (_mongocrypt_cache_t *cache);


#endif /* MONGOCRYPT_CACHE_PRIVATE */