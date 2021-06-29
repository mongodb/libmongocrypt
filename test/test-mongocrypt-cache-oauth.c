/*
 * Copyright 2021-present MongoDB, Inc.
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
#include "mongocrypt-cache-oauth-private.h"

static void _test_cache_oauth_expiration (_mongocrypt_tester_t *tester) {
   _mongocrypt_cache_oauth_t* cache;
   char *token;
   bool ret;
   mongocrypt_status_t* status;
   
   cache = _mongocrypt_cache_oauth_new ();
   token = _mongocrypt_cache_oauth_get (cache);
   BSON_ASSERT (!token);

   status = mongocrypt_status_new ();
   ret = _mongocrypt_cache_oauth_add (cache, TMP_BSON ("{'expires_in': 0, 'access_token': 'foo'}"), status);
   ASSERT_OR_PRINT (ret, status);
   /* Attempting to get the token will purge the new token from the cache. */
   token = _mongocrypt_cache_oauth_get (cache);
   BSON_ASSERT (!token);

   /* Attempt to get again, to ensure MONGOCRYPT-321 is fixed. */
   token = _mongocrypt_cache_oauth_get (cache);
   BSON_ASSERT (!token);

   /* Add an unexpired token. */
   ret = _mongocrypt_cache_oauth_add (cache, TMP_BSON ("{'expires_in': 1000, 'access_token': 'bar'}"), status);
   ASSERT_OR_PRINT (ret, status);
   
   token = _mongocrypt_cache_oauth_get (cache);
   ASSERT_STREQUAL (token, "bar");
   bson_free (token);

   _mongocrypt_cache_oauth_destroy (cache);
   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_cache_oauth (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_cache_oauth_expiration);
}