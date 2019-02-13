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
#include "mongocrypt-key-query-private.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-request-private.h"

void
mongocrypt_request_destroy (mongocrypt_request_t *request)
{
   int i;

   CRYPT_ENTRY;
   if (!request) {
      return;
   }

   bson_destroy (&request->mongocryptd_reply);

   for (i = 0; i < request->num_key_queries; i++) {
      bson_destroy (&request->key_queries[i].filter);
      bson_free (&request->key_queries[i].keyvault_alias);
   }

   bson_free (request);
}


bool
mongocrypt_request_needs_keys (mongocrypt_request_t *request)
{
   CRYPT_ENTRY;
   BSON_ASSERT (request);
   return request->key_query_iter < request->num_key_queries;
}


const mongocrypt_key_query_t *
mongocrypt_request_next_key_query (mongocrypt_request_t *request,
                                   const mongocrypt_opts_t *opts)
{
   mongocrypt_key_query_t *key_query;

   CRYPT_ENTRY;
   BSON_ASSERT (request);
   key_query = &request->key_queries[request->key_query_iter];
   request->key_query_iter++;
   return key_query;
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
   CRYPT_ENTRY;
   for (i = 0; i < num_responses; i++) {
      /* TODO: don't marshal and add one at a time. Each call to
       * _mongocrypt_keycache_add locks. */
      _mongocrypt_buffer_t buf = {0};
      buf.data = responses[i].data;
      buf.len = responses[i].len;
      if (!_mongocrypt_keycache_add (request->crypt, &buf, 1, status)) {
         return false;
      }
   }
   return true;
}
