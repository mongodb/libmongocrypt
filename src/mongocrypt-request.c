/*
 * Copyright 2018-present MongoDB, Inc.
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

#include <mongoc/mongoc.h>

#include "mongocrypt-binary.h"
#include "mongocrypt-key-cache-private.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-request-private.h"
#include "mongocrypt-log-private.h"

void
mongocrypt_request_destroy (mongocrypt_request_t *request)
{
   int i;

   if (!request) {
      return;
   }

   bson_destroy (&request->mongocryptd_reply);


   bson_free (request);
}


bool
mongocrypt_request_needs_keys (mongocrypt_request_t *request)
{
   BSON_ASSERT (request);
   return false;
}


bool
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_status_t *status)
{
   int i;

   BSON_ASSERT (request);
   BSON_ASSERT (responses);
   BSON_ASSERT (status);
   for (i = 0; i < num_responses; i++) {
      /* TODO: don't marshal and add one at a time. Each call to
       * _mongocrypt_keycache_add locks. */
      _mongocrypt_buffer_t buf = {0};
      buf.data = responses[i].data;
      buf.len = responses[i].len;
      if (!_mongocrypt_key_cache_add (
             request->crypt->key_cache, &buf, 1, status)) {
         return false;
      }
   }
   return true;
}
