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

/* TODO CDRIVER-2951: Tests more edge cases. */


static void
_test_ctx_id (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx, *ctx2;

   crypt = _mongocrypt_tester_mongocrypt ();

   /* Two contexts should have different IDs */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_id (ctx) == 1);

   ctx2 = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx2, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_id (ctx2) == 2);

   /* Recreating a context results in a new ID */
   mongocrypt_ctx_destroy (ctx);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_id (ctx) == 3);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_ctx_destroy (ctx2);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_ctx (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_ctx_id);
}