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

#include "test-mongocrypt.h"
#include "mongocrypt-cache-collinfo-private.h"

void
_test_cache (_mongocrypt_tester_t *tester)
{
   _mongocrypt_cache_t cache;
   mongocrypt_status_t *status;
   bson_t *entry = BCON_NEW ("a", "b"), *entry2 = BCON_NEW ("c", "d");
   bson_t *tmp = NULL;
   _mongocrypt_cache_pair_state_t state;
   uint32_t owner_out;

   status = mongocrypt_status_new ();

   _mongocrypt_cache_collinfo_init (&cache);

   /* Test get on an empty cache. */
   _mongocrypt_cache_get_or_create (
      &cache, "1", (void **) &tmp, &state, 1, &owner_out);
   BSON_ASSERT (!tmp);
   BSON_ASSERT (state == CACHE_PAIR_PENDING);
   BSON_ASSERT (owner_out == 1);

   /* Test set + get */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry, 1, status),
                    status);
   _mongocrypt_cache_get_or_create (
      &cache, "1", (void **) &tmp, &state, 1, &owner_out);
   /* Assert we get a copy back. */
   BSON_ASSERT (entry != tmp);
   BSON_ASSERT (bson_equal (entry, tmp));
   BSON_ASSERT (state == CACHE_PAIR_DONE);
   BSON_ASSERT (owner_out == 0);
   bson_destroy (tmp);

   /* Test missing find. */
   _mongocrypt_cache_get_or_create (
      &cache, "2", (void **) &tmp, &state, 1, &owner_out);
   BSON_ASSERT (!tmp);
   BSON_ASSERT (state == CACHE_PAIR_PENDING);
   BSON_ASSERT (owner_out == 1);

   /* Test attempting to overwrite an entry. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry2, 1, status),
                    status);
   _mongocrypt_cache_get_or_create (
      &cache, "1", (void **) &tmp, &state, 1, &owner_out);
   /* Overwrite is ignored. */
   BSON_ASSERT (bson_equal (entry, tmp));
   BSON_ASSERT (state == CACHE_PAIR_DONE);
   BSON_ASSERT (owner_out == 0);
   bson_destroy (tmp);

   /* Test with two entries in the cache. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "2", entry2, 1, status),
                    status);
   _mongocrypt_cache_get_or_create (
      &cache, "2", (void **) &tmp, &state, 1, &owner_out);
   BSON_ASSERT (bson_equal (entry2, tmp));
   BSON_ASSERT (state == CACHE_PAIR_DONE);
   BSON_ASSERT (owner_out == 0);
   bson_destroy (tmp);

   /* Test stealing an entry. */
   ASSERT_OR_PRINT (
      _mongocrypt_cache_add_stolen (&cache, "3", entry, 1, status), status);
   _mongocrypt_cache_get_or_create (
      &cache, "3", (void **) &tmp, &state, 1, &owner_out);
   BSON_ASSERT (bson_equal (entry, tmp));
   BSON_ASSERT (state == CACHE_PAIR_DONE);
   BSON_ASSERT (owner_out == 0);
   bson_destroy (tmp);
   /* entry was stolen, do not free. */

   _mongocrypt_cache_cleanup (&cache);
   mongocrypt_status_destroy (status);
   bson_destroy (entry2);
}

void
_mongocrypt_tester_install_cache (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_cache);
}