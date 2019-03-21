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

#include <mongocrypt.h>
#include <mongocrypt-ctx-private.h>
#include <mongocrypt-key-broker-private.h>

#include "test-mongocrypt.h"


/* Test individual ctx states. */
static void
_test_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   mongocrypt_ctx_destroy (ctx);

   /* Invalid namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (ctx, "invalidnamespace", 16),
                 ctx,
                 "invalid ns");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* NULL namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_encrypt_init (ctx, NULL, 0), ctx, "invalid ns");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Wrong state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   ASSERT_FAILS (
      mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx, "wrong state");
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;

   /* Success. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with no schema. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo = _mongocrypt_tester_file (
      tester, "./test/data/collection-info-no-schema.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with NULL schema. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx, "wrong state");
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_markings (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *markings;

   /* Success. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings =
      _mongocrypt_tester_file (tester, "./test/example/mongocryptd-reply.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No placeholders. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-no-markings.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No encryption in schema. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-no-encryption-needed.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Invalid marking. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-invalid.json");
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, markings), ctx, "no 'v'");
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* NULL markings. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, markings), ctx, "wrong state");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *key;

   /* Success. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   key = _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, key), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (key);
   BSON_ASSERT (mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Did not provide all keys. */
   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_done (ctx), ctx, "did not provide all keys");
   BSON_ASSERT (mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */
}


static void
_test_encrypt_ready (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted_cmd;
   _mongocrypt_buffer_t ciphertext_buf;
   _mongocrypt_ciphertext_t ciphertext;
   bson_t as_bson;
   bson_iter_t iter;
   bool ret;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new();
   crypt = mongocrypt_new ();
   encrypted_cmd = mongocrypt_binary_new();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);
   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, encrypted_cmd), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_DONE);

   /* check that the encrypted command has a valid ciphertext. */
   _mongocrypt_binary_to_bson (encrypted_cmd, &as_bson);
   CRYPT_TRACEF (&crypt->log, "encrypted doc: %s", tmp_json (&as_bson));
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   _mongocrypt_buffer_from_iter (&ciphertext_buf, &iter);
   ret = _test_mongocrypt_ciphertext_parse_unowned (
      &ciphertext_buf, &ciphertext, status);
   ASSERT_OR_PRINT (ret, status);
   mongocrypt_binary_destroy (encrypted_cmd);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


void
_mongocrypt_tester_install_ctx_encrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_encrypt_init);
   INSTALL_TEST (_test_encrypt_need_collinfo);
   INSTALL_TEST (_test_encrypt_need_markings);
   INSTALL_TEST (_test_encrypt_need_keys);
   INSTALL_TEST (_test_encrypt_ready);
}