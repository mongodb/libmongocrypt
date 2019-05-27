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

   status = mongocrypt_status_new ();

   _mongocrypt_cache_collinfo_init (&cache);

   /* Test get on an empty cache. */
   _mongocrypt_cache_get (&cache, "1", (void **) &tmp);
   BSON_ASSERT (!tmp);


   /* Test set + get */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry, status),
                    status);
   _mongocrypt_cache_get (&cache, "1", (void **) &tmp);
   /* Assert we get a copy back. */
   BSON_ASSERT (entry != tmp);
   BSON_ASSERT (bson_equal (entry, tmp));
   bson_destroy (tmp);

   /* Test missing find. */
   _mongocrypt_cache_get (&cache, "2", (void **) &tmp);
   BSON_ASSERT (!tmp);


   /* Test attempting to overwrite an entry. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry2, status),
                    status);
   _mongocrypt_cache_get (&cache, "1", (void **) &tmp);
   /* Overwrite is ignored. */
   BSON_ASSERT (bson_equal (entry2, tmp));
   bson_destroy (tmp);

   /* Test with two entries in the cache. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "2", entry2, status),
                    status);
   _mongocrypt_cache_get (&cache, "2", (void **) &tmp);
   BSON_ASSERT (bson_equal (entry2, tmp));
   bson_destroy (tmp);

   /* Test stealing an entry. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_stolen (&cache, "3", entry, status),
                    status);
   _mongocrypt_cache_get (&cache, "3", (void **) &tmp);
   BSON_ASSERT (bson_equal (entry, tmp));
   bson_destroy (tmp);

   _mongocrypt_cache_cleanup (&cache);
   mongocrypt_status_destroy (status);
   bson_destroy (entry2);
}

void
_mongocrypt_tester_install_cache (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_cache);
}