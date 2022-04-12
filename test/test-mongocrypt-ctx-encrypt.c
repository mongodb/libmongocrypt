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

#include <mongocrypt-marking-private.h>

#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt.h"
#include "test-mongocrypt-crypto-std-hooks.h"


static void
_test_explicit_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_binary_t *string_msg;
   mongocrypt_binary_t *no_v_msg;
   mongocrypt_binary_t *bad_name;
   mongocrypt_binary_t *name;
   mongocrypt_binary_t *msg;
   mongocrypt_binary_t *key_id;
   mongocrypt_binary_t *tmp;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   bson_t *bson_msg;
   bson_t *bson_msg_no_v;
   bson_t *bson_name;
   bson_t *bson_bad_name;

   char *random = "AEAD_AES_256_CBC_HMAC_SHA_512-Random";
   char *deterministic = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";

   bson_msg = BCON_NEW ("v", "hello");
   msg = mongocrypt_binary_new_from_data ((uint8_t *) bson_get_data (bson_msg),
                                          bson_msg->len);

   bson_msg_no_v = BCON_NEW ("a", "hello");
   no_v_msg = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_msg_no_v), bson_msg_no_v->len);

   bson_name = BCON_NEW ("keyAltName", "Rebekah");
   name = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_name), bson_name->len);

   bson_bad_name = BCON_NEW ("noAltName", "Barry");
   bad_name = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_bad_name), bson_bad_name->len);

   string_msg =
      mongocrypt_binary_new_from_data (MONGOCRYPT_DATA_AND_LEN ("hello"));
   key_id = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("2395340598345034"));

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Initting with no options will fail (need key_id). */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "either key id or key alt name required");
   mongocrypt_ctx_destroy (ctx);

   /* Initting with only key_id will not succeed, we also
      need an algorithm. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "algorithm required");
   mongocrypt_ctx_destroy (ctx);

   /* Test null msg input. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, NULL),
                 ctx,
                 "msg required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test with string msg input (no bson) */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, string_msg),
                 ctx,
                 "msg must be bson");
   mongocrypt_ctx_destroy (ctx);

   /* Test with input bson that has no "v" field */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, no_v_msg),
                 ctx,
                 "invalid msg, must contain 'v'");
   mongocrypt_ctx_destroy (ctx);

   /* Initting with RANDOM passes */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);
   BSON_ASSERT (ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
   mongocrypt_ctx_destroy (ctx);

   /* Test that bad algorithm input fails */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_setopt_algorithm (ctx, "nonexistent algorithm", -1),
      ctx,
      "unsupported algorithm");
   mongocrypt_ctx_destroy (ctx);

   /* Test with badly formatted key alt name */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_setopt_key_alt_name (ctx, bad_name),
                 ctx,
                 "must have field");
   mongocrypt_ctx_destroy (ctx);

   /* Test with key alt name */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_alt_name (ctx, name));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);

   /* After initing, we should be at NEED_KEYS */
   BSON_ASSERT (ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
   BSON_ASSERT (ctx->state == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   /* double succeeds for random. */
   tmp = TEST_BSON ("{'v': { '$double': '1.23'} }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* double fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* decimal128 succeeds for random. */
   tmp = TEST_BSON ("{'v': {'$numberDecimal': '1.23'} }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* decimal128 fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* document succeeds for random. */
   tmp = TEST_BSON ("{'v': { 'x': 1 } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* document fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* array succeeds for random. */
   tmp = TEST_BSON ("{'v': [1,2,3] }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* document fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* codewscope succeeds for random. */
   tmp = TEST_BSON ("{'v': {'$code': 'var x = 1;', '$scope': {} } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* codewscope fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* bool succeeds for random. */
   tmp = TEST_BSON ("{'v': true }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* bool fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* null fails for deterministic. */
   tmp = TEST_BSON ("{'v': null }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* null fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* minkey fails for deterministic. */
   tmp = TEST_BSON ("{'v': { '$minKey': 1 } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* minkey fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* maxkey fails for deterministic. */
   tmp = TEST_BSON ("{'v': { '$maxKey': 1 } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* maxkey fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* undefined fails for deterministic. */
   tmp = TEST_BSON ("{'v': { '$undefined': true } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* undefined fails for deterministic. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON type invalid for encryption");
   mongocrypt_ctx_destroy (ctx);


   /* dbpointer succeeds for deterministic. */
   tmp = TEST_BSON ("{'v': { '$dbPointer': {'$ref': 'ns', '$id': {'$oid': "
                    "'AAAAAAAAAAAAAAAAAAAAAAAA'} } } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* dbpointer succeeds for random. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* binary subtype 6 fails for deterministic. */
   tmp = TEST_BSON (
      "{'v': { '$binary': { 'base64': 'AAAA', 'subType': '06' } } }");
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON binary subtype 6 is invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   /* binary subtype 6 fails for random. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, tmp),
                 ctx,
                 "BSON binary subtype 6 is invalid for encryption");
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);

   mongocrypt_binary_destroy (msg);
   mongocrypt_binary_destroy (bad_name);
   mongocrypt_binary_destroy (name);
   mongocrypt_binary_destroy (string_msg);
   mongocrypt_binary_destroy (no_v_msg);
   mongocrypt_binary_destroy (key_id);
   bson_destroy (bson_bad_name);
   bson_destroy (bson_name);
   bson_destroy (bson_msg);
   bson_destroy (bson_msg_no_v);
}

/* Test individual ctx states. */
static void
_test_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   mongocrypt_ctx_destroy (ctx);

   /* NULL namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (
                    ctx, NULL, 0, TEST_FILE ("./test/example/cmd.json")),
                 ctx,
                 "invalid db");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Wrong state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (
                    ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
                 ctx,
                 "cannot double initialize");
   mongocrypt_ctx_destroy (ctx);

   /* Empty db name is an error. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (
                    ctx, "", -1, TEST_FILE ("./test/example/cmd.json")),
                 ctx,
                 "invalid db");
   mongocrypt_ctx_destroy (ctx);

   /* Empty coll name is an error. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_encrypt_init (ctx, "", -1, TEST_BSON ("{'find': ''}")),
      ctx,
      "empty collection name on command");
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/collection-info.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with no schema. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */
   /* Coll info with NULL schema. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No coll info. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   /* No call to ctx_mongo_feed. */
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/example/collection-info.json")),
                 ctx,
                 "wrong state");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_markings (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;

   bin = mongocrypt_binary_new ();

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_mongo_op (ctx, bin);
   ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
      TEST_FILE ("./test/data/mongocryptd-cmd.json"), bin);

   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/mongocryptd-reply.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Key alt name. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/mongocryptd-reply-key-alt-name.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No placeholders. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/mongocryptd-reply-no-markings.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No encryption in schema. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx,
         TEST_FILE ("./test/data/mongocryptd-reply-no-encryption-needed.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Invalid marking. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/mongocryptd-reply-invalid.json")),
      ctx,
      "no 'v'");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* NULL markings. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/example/mongocryptd-reply.json")),
                 ctx,
                 "wrong state");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_csfle_no_needs_markings (_mongocrypt_tester_t *tester)
{
   if (!TEST_MONGOCRYPT_HAVE_REAL_CSFLE) {
      fputs ("No 'real' csfle library is available. The "
             "_test_encrypt_csfle_no_needs_markings test is a no-op.",
             stderr);
      return;
   }

   /* Success. */
   mongocrypt_t *crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_WITH_CSFLE_LIB);
   mongocrypt_ctx_t *ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/key-document.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Did not provide all keys. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_done (ctx),
                 ctx,
                 "not all keys requested were satisfied");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
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

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   encrypted_cmd = mongocrypt_binary_new ();

   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, encrypted_cmd), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_DONE);

   /* check that the encrypted command has a valid ciphertext. */
   BSON_ASSERT (_mongocrypt_binary_to_bson (encrypted_cmd, &as_bson));
   CRYPT_TRACEF (&crypt->log, "encrypted doc: %s", tmp_json (&as_bson));
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   BSON_ASSERT (_mongocrypt_buffer_from_binary_iter (&ciphertext_buf, &iter));
   ret = _mongocrypt_ciphertext_parse_unowned (
      &ciphertext_buf, &ciphertext, status);
   ASSERT_OR_PRINT (ret, status);

   /* check that encrypted command matches. */
   ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
      TEST_FILE ("./test/data/encrypted-cmd.json"), encrypted_cmd);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_binary_destroy (encrypted_cmd);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_missing_region (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/data/key-document-no-region.json")),
                 ctx,
                 "expected UTF-8 region");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


/* Test that attempting to auto encrypt on a view is disallowed. */
static void
_test_view (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/data/collection-info-view.json")),
                 ctx,
                 "cannot auto encrypt a view");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

/* Check that the schema identified in the schema_map by 'ns' matches the
 * 'jsonSchema' of the mongocryptd command. */
static void
_assert_schema_compares (mongocrypt_binary_t *schema_map,
                         const char *ns,
                         mongocrypt_binary_t *mongocryptd_cmd)
{
   bson_t schema_map_bson, mongocryptd_cmd_bson, expected_schema, actual_schema;
   uint32_t len;
   const uint8_t *data;
   bson_iter_t iter;

   /* Get the schema from the map. */
   BSON_ASSERT (_mongocrypt_binary_to_bson (schema_map, &schema_map_bson));
   BSON_ASSERT (bson_iter_init_find (&iter, &schema_map_bson, ns));
   bson_iter_document (&iter, &len, &data);
   bson_init_static (&expected_schema, data, len);

   /* Get the schema from the mongocryptd command. */
   BSON_ASSERT (
      _mongocrypt_binary_to_bson (mongocryptd_cmd, &mongocryptd_cmd_bson));
   BSON_ASSERT (
      bson_iter_init_find (&iter, &mongocryptd_cmd_bson, "jsonSchema"));
   bson_iter_document (&iter, &len, &data);
   BSON_ASSERT (bson_init_static (&actual_schema, data, len));


   BSON_ASSERT (bson_equal (&expected_schema, &actual_schema));
}


static void
_test_local_schema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *schema_map, *mongocryptd_cmd;

   crypt = mongocrypt_new ();
   schema_map = TEST_FILE ("./test/data/schema-map.json");
   ASSERT_OK (
      mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1),
      crypt);
   ASSERT_OK (mongocrypt_setopt_schema_map (crypt, schema_map), crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   /* Schema map has test.test, we should jump right to NEED_MONGO_MARKINGS */
   ctx = mongocrypt_ctx_new (crypt);
   mongocryptd_cmd = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, mongocryptd_cmd), ctx);

   /* We should get back the schema we gave. */
   _assert_schema_compares (schema_map, "test.test", mongocryptd_cmd);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_binary_destroy (mongocryptd_cmd);

   /* Schema map has test.test2, we should jump right to NEED_MONGO_MARKINGS */
   ctx = mongocrypt_ctx_new (crypt);
   mongocryptd_cmd = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_BSON ("{'find': 'test2'}")),
              ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, mongocryptd_cmd), ctx);

   /* We should get back the schema we gave. */
   _assert_schema_compares (schema_map, "test.test2", mongocryptd_cmd);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_binary_destroy (mongocryptd_cmd);

   /* Database that does not match should not get from the map. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "mismatch", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   mongocrypt_ctx_destroy (ctx);

   /* Collection that does not match should not get from the map. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_BSON ("{'find': 'mismatch'}")),
              ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_caches_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   bson_t *cached_collinfo;
   mongocrypt_status_t *status;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   status = mongocrypt_status_new ();
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/collection-info.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   /* The next ctx has the schema cached. */
   BSON_ASSERT (_mongocrypt_cache_get (
      &crypt->cache_collinfo, "test.test", (void **) &cached_collinfo));
   BSON_ASSERT (cached_collinfo != NULL);
   bson_destroy (cached_collinfo);
   mongocrypt_ctx_destroy (ctx);

   /* The next context enters the NEED_MONGO_MARKINGS state immediately. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}


static void
_test_encrypt_caches_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   /* The next context skips needing keys after being supplied mark documents.
    */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/mongocryptd-reply.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_caches_keys_by_alt_name (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/mongocryptd-reply-key-alt-name.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/key-document-with-alt-name.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);

   /* The next context skips needing keys after being supplied mark documents.
    */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/mongocryptd-reply-key-alt-name.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);

   /* But a context requesting a different key alt name does not get it from the
    * cache. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/mongocryptd-reply-key-alt-name2.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/key-document-with-alt-name2.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_random (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/mongocryptd-reply-random.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_is_remote_schema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   bson_t as_bson;
   bson_iter_t iter;

   bin = mongocrypt_binary_new ();

   /* isRemoteSchema = true for a remote schema. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, bin), ctx);
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin, &as_bson));
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "isRemoteSchema"));
   BSON_ASSERT (bson_iter_bool (&iter) == true);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);

   /* isRemoteSchema = false for a local schema. */
   crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1),
      crypt);
   ASSERT_OK (mongocrypt_setopt_schema_map (
                 crypt, TEST_FILE ("./test/data/schema-map.json")),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, bin), ctx);
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin, &as_bson));
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "isRemoteSchema"));
   BSON_ASSERT (bson_iter_bool (&iter) == false);

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_init_fails (_mongocrypt_tester_t *tester, const char *json, const char *msg)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_encrypt_init (ctx, "test", -1, TEST_BSON (json)),
      ctx,
      msg);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_init_ok (_mongocrypt_tester_t *tester, const char *json)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *filter;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);

   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test", -1, TEST_BSON (json)),
              ctx);
   /* verify the collection in the filter is 'coll' */
   BSON_ASSERT (MONGOCRYPT_CTX_NEED_MONGO_COLLINFO ==
                mongocrypt_ctx_state (ctx));

   filter = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, filter), ctx);
   ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (TEST_BSON ("{'name': 'coll'}"), filter);

   mongocrypt_binary_destroy (filter);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_init_bypass (_mongocrypt_tester_t *tester, const char *json)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;

   bin = mongocrypt_binary_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test", -1, TEST_BSON (json)),
              ctx);
   BSON_ASSERT (MONGOCRYPT_CTX_READY == mongocrypt_ctx_state (ctx));
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, bin), ctx);
   ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (TEST_BSON (json), (bin));

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_init_each_cmd (_mongocrypt_tester_t *tester)
{
   /* collection aggregate is ok */
   _init_ok (tester, "{'aggregate': 'coll'}");
   /* db agg is not ok */
   _init_fails (
      tester,
      "{'aggregate': 1}",
      "non-collection command not supported for auto encryption: aggregate");
   _init_ok (tester, "{'count': 'coll'}");
   _init_ok (tester, "{'distinct': 'coll'}");
   _init_ok (tester, "{'delete': 'coll'}");
   _init_ok (tester, "{'find': 'coll'}");
   _init_ok (tester, "{'findAndModify': 'coll'}");
   _init_bypass (tester, "{'getMore': 'coll'}");
   _init_ok (tester, "{'insert': 'coll'}");
   _init_ok (tester, "{'update': 'coll'}");
   _init_bypass (tester, "{'authenticate': 1}");
   _init_bypass (tester, "{'getnonce': 1}");
   _init_bypass (tester, "{'logout': 1}");
   _init_bypass (tester, "{'isMaster': 1}");
   _init_bypass (tester, "{'abortTransaction': 1}");
   _init_bypass (tester, "{'commitTransaction': 1}");
   _init_bypass (tester, "{'endSessions': 1}");
   _init_bypass (tester, "{'startSession': 1}");
   _init_bypass (tester, "{'create': 1}");
   _init_bypass (tester, "{'createIndexes': 1}");
   _init_bypass (tester, "{'drop': 1}");
   _init_bypass (tester, "{'dropDatabase': 1}");
   _init_bypass (tester, "{'killCursors': 1}");
   _init_bypass (tester, "{'listCollections': 1}");
   _init_bypass (tester, "{'listDatabases': 1}");
   _init_bypass (tester, "{'listIndexes': 1}");
   _init_bypass (tester, "{'renameCollection': 'coll'}");
   _init_ok (tester, "{'explain': { 'find': 'coll' }}");
   _init_fails (tester, "{'explain': { } }", "invalid empty BSON");
   _init_fails (tester,
                "{'explain': { 'aggregate': 1 }}",
                "non-collection command not supported for auto encryption");
   _init_bypass (tester, "{'ping': 1}");
   _init_bypass (tester, "{'saslStart': 1}");
   _init_bypass (tester, "{'saslContinue': 1}");
   _init_fails (tester,
                "{'fakecmd': 'coll'}",
                "command not supported for auto encryption: fakecmd");
   /* fails for eligible command with no collection name. */
   _init_fails (
      tester,
      "{'insert': 1}",
      "non-collection command not supported for auto encryption: insert");
   _init_fails (tester, "{}", "invalid empty BSON");
   _init_bypass (tester, "{'isMaster': 1}");
   _init_bypass (tester, "{'ismaster': 1}");
   _init_bypass (tester, "{'killAllSessions': 1}");
   _init_bypass (tester, "{'killSessions': 1}");
   _init_bypass (tester, "{'killAllSessionsByPattern': 1}");
   _init_bypass (tester, "{'refreshSessions': 1}");
}


static void
_test_encrypt_invalid_siblings (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);

   BSON_ASSERT (MONGOCRYPT_CTX_NEED_MONGO_COLLINFO ==
                mongocrypt_ctx_state (ctx));
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/collinfo-siblings.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);

   BSON_ASSERT (MONGOCRYPT_CTX_NEED_MONGO_MARKINGS ==
                mongocrypt_ctx_state (ctx));
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/example/mongocryptd-reply.json")),
                 ctx,
                 "JSON schema validator has siblings");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_dupe_jsonschema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);

   BSON_ASSERT (MONGOCRYPT_CTX_NEED_MONGO_COLLINFO ==
                mongocrypt_ctx_state (ctx));
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_BSON ("{'options': {'validator': { '$jsonSchema': {}, "
                               "'$jsonSchema': {} } } }")),
                 ctx,
                 "duplicate $jsonSchema");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypting_with_explicit_encryption (_mongocrypt_tester_t *tester)
{
   /* Test that we do not strip existing ciphertexts when automatically
    * encrypting a document. */
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   bson_iter_t iter;
   bson_t tmp;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);

   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx,
         TEST_FILE ("./test/data/mongocryptd-reply-existing-ciphertext.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   bin = mongocrypt_binary_new ();
   mongocrypt_ctx_finalize (ctx, bin);
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin, &tmp));
   BSON_ASSERT (bson_iter_init (&iter, &tmp));
   BSON_ASSERT (
      bson_iter_find_descendant (&iter, "filter.existing_ciphertext", &iter));
   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_explicit_encryption (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   _mongocrypt_buffer_t from_key_id, from_key_altname;
   mongocrypt_binary_t *bin, *key_id;
   char *deterministic = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   ctx = mongocrypt_ctx_new (crypt);
   key_id = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("aaaaaaaaaaaaaaaa"));

   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (
      mongocrypt_ctx_explicit_encrypt_init (ctx, TEST_BSON ("{'v': 123}")),
      ctx);

   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, bin), ctx);
   _mongocrypt_buffer_copy_from_binary (&from_key_id, bin);
   mongocrypt_binary_destroy (bin);

   mongocrypt_binary_destroy (key_id);
   mongocrypt_ctx_destroy (ctx);


   ctx = mongocrypt_ctx_new (crypt);

   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_key_alt_name (
                 ctx, TEST_BSON ("{'keyAltName': 'keyDocumentName'}")),
              ctx);
   ASSERT_OK (
      mongocrypt_ctx_explicit_encrypt_init (ctx, TEST_BSON ("{'v': 123}")),
      ctx);

   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, bin), ctx);
   _mongocrypt_buffer_copy_from_binary (&from_key_altname, bin);
   mongocrypt_binary_destroy (bin);

   mongocrypt_ctx_destroy (ctx);

   BSON_ASSERT (0 == _mongocrypt_buffer_cmp (&from_key_id, &from_key_altname));

   _mongocrypt_buffer_cleanup (&from_key_id);
   _mongocrypt_buffer_cleanup (&from_key_altname);

   mongocrypt_destroy (crypt);
}

/* Test with empty AWS credentials. */
void
_test_encrypt_empty_aws (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_setopt_kms_provider_aws (crypt, "", -1, "", -1),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "db", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/example/key-document.json")),
                 ctx,
                 "failed to create KMS message");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_custom_endpoint (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_kms_ctx_t *kms_ctx;
   mongocrypt_binary_t *bin;
   const char *endpoint;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/example/key-document-custom-endpoint.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
   BSON_ASSERT (kms_ctx);
   ASSERT_OK (mongocrypt_kms_ctx_endpoint (kms_ctx, &endpoint), ctx);
   BSON_ASSERT (0 == strcmp ("example.com:443", endpoint));
   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_kms_ctx_message (kms_ctx, bin), ctx);
   BSON_ASSERT (NULL != strstr ((char *) bin->data, "Host:example.com"));

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_per_ctx_credentials (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_kms_ctx_t *kms_ctx;
   mongocrypt_binary_t *bin;
   const char *endpoint;

   /* Success. */
   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'aws': {}}"));
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   ASSERT_OK (
      mongocrypt_ctx_provide_kms_providers (ctx,
         TEST_BSON ("{'aws':{'accessKeyId': 'example',"
                            "'secretAccessKey': 'example'}}")), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/example/key-document-custom-endpoint.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
   BSON_ASSERT (kms_ctx);
   ASSERT_OK (mongocrypt_kms_ctx_endpoint (kms_ctx, &endpoint), ctx);
   BSON_ASSERT (0 == strcmp ("example.com:443", endpoint));
   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_kms_ctx_message (kms_ctx, bin), ctx);
   BSON_ASSERT (NULL != strstr ((char *) bin->data, "Host:example.com"));

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_per_ctx_credentials_local (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   /* local_kek is the KEK used to encrypt the keyMaterial in
    * ./test/data/key-document-local.json */
   const char *local_kek =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'local': {}}"));
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   ASSERT_OK (mongocrypt_ctx_provide_kms_providers (
                 ctx,
                 TEST_BSON ("{'local':{'key': { '$binary': {'base64': '%s', "
                            "'subType': '00'}}}}",
                            local_kek)),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-local.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_with_aws_session_token (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_binary_t *bin;
   mongocrypt_ctx_t *ctx;
   mongocrypt_kms_ctx_t *kms_ctx;
   char *http_req;

   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_setopt_kms_providers (
                 crypt,
                 TEST_BSON ("{'aws': {'sessionToken': 'mySessionToken', "
                            "'accessKeyId': 'myAccessKeyId', "
                            "'secretAccessKey': 'mySecretAccessKey'}}")),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);

   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
   BSON_ASSERT (NULL != kms_ctx);

   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_kms_ctx_message (kms_ctx, bin), kms_ctx);
   http_req = (char *) mongocrypt_binary_data (bin);
   ASSERT_STRCONTAINS (http_req, "X-Amz-Security-Token:mySessionToken");

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_caches_empty_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   /* Do not feed anything for collinfo. */
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);

   /* Create another encryption context on the same namespace test.test. It
    * should not transition to the MONGOCRYPT_CTX_NEED_MONGO_COLLINFO state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_caches_collinfo_without_jsonschema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/collection-info-no-validator.json")),
      ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);

   /* Create another encryption context on the same namespace test.test. It
    * should not transition to the MONGOCRYPT_CTX_NEED_MONGO_COLLINFO state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_with_encrypted_field_config_map (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (
         crypt,
         TEST_BSON (
            "{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
      crypt);
   ASSERT_OK (mongocrypt_setopt_encrypted_field_config_map (
                 crypt, TEST_BSON ("{'db.coll': {'foo': 'bar'}}")),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   /* Test encrypting a command on a collection present in the encrypted field
    * config map. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "db", -1, TEST_BSON ("{'find': 'coll'}")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   {
      mongocrypt_binary_t *cmd_to_mongocryptd;

      cmd_to_mongocryptd = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, cmd_to_mongocryptd), ctx);
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
         TEST_BSON ("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                    "'schema': { 'db.coll': {'foo': 'bar'}}}}"),
         cmd_to_mongocryptd);
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (
            ctx,
            TEST_BSON ("{'result': {'find': 'coll', 'encryptionInformation': { "
                       "'type': 1, 'schema': { 'db.coll': {'foo': 'bar'}}}}, "
                       "'hasEncryptionPlaceholders': false}")),
         ctx);
      mongocrypt_binary_destroy (cmd_to_mongocryptd);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      mongocrypt_binary_t *cmd_to_mongod;

      cmd_to_mongod = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, cmd_to_mongod), ctx);
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
         TEST_BSON ("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                    "'schema': { 'db.coll': {'foo': 'bar'}}}}"),
         cmd_to_mongod);
      mongocrypt_binary_destroy (cmd_to_mongod);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

/* Test encrypting a bypassed command on a collection present in the encrypted
 * field config map. Expect no encryptionInformation. */
static void
_test_encrypt_with_encrypted_field_config_map_bypassed (
   _mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (
         crypt,
         TEST_BSON (
            "{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
      crypt);
   ASSERT_OK (mongocrypt_setopt_encrypted_field_config_map (
                 crypt, TEST_BSON ("{'db.coll': {'foo': 'bar'}}")),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   /* 'drop' is bypassed. Expect that no 'encryptionInformation' is appended. */
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "db", -1, TEST_BSON ("{'drop': 'coll'}")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      mongocrypt_binary_t *cmd_to_mongod;

      cmd_to_mongod = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, cmd_to_mongod), ctx);
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (TEST_BSON ("{'drop': 'coll'}"),
                                           cmd_to_mongod);
      mongocrypt_binary_destroy (cmd_to_mongod);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


/* Test that an empty jsonSchema document is appended to the command sent to
 * mongocryptd when no encryptedFieldConfig or jsonSchema is found for the
 * collection.
 *
 * This is a regression test for PYTHON-3188. */
static void
_test_encrypt_no_schema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (
         ctx,
         "db",
         -1,
         TEST_BSON ("{'find': 'collection_without_schema', 'filter': {}}")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   /* Give no collection info. */
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);

   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   {
      mongocrypt_binary_t *cmd_to_mongocryptd;

      cmd_to_mongocryptd = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, cmd_to_mongocryptd), ctx);
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
         TEST_BSON ("{'find': 'collection_without_schema', 'filter': {}, "
                    "'jsonSchema': {}, 'isRemoteSchema': true}"),
         cmd_to_mongocryptd);
      mongocrypt_binary_destroy (cmd_to_mongocryptd);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_remote_encryptedfields (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (
         crypt,
         TEST_BSON (
            "{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
      crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   /* Test success. */
   {
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (mongocrypt_ctx_encrypt_init (
                    ctx, "db", -1, TEST_BSON ("{'find': 'coll'}")),
                 ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
      {
         ASSERT_OK (mongocrypt_ctx_mongo_feed (
                       ctx,
                       TEST_BSON ("{'name': 'coll', 'options': "
                                  "{'encryptedFields': {'foo': 'bar'}}}")),
                    ctx);
         ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      }

      /* Check that command to mongocryptd includes "encryptionInformation". */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
      {
         mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, cmd_to_mongocryptd), ctx);
         /* "encryptionInformation.schema" must be the document from
          * "encryptedFields" fed from MONGOCRYPT_CTX_NEED_MONGO_COLLINFO. */
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_BSON ("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                       "'schema': { 'db.coll': {'foo': 'bar'}}}}"),
            cmd_to_mongocryptd);
         mongocrypt_binary_destroy (cmd_to_mongocryptd);
         ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      }

      mongocrypt_ctx_destroy (ctx);
   }

   /* Test that the previous 'encryptedFields' is cached. */
   {
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (mongocrypt_ctx_encrypt_init (
                    ctx, "db", -1, TEST_BSON ("{'find': 'coll'}")),
                 ctx);

      /* Check that command to mongocryptd includes "encryptionInformation". */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
      {
         mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, cmd_to_mongocryptd), ctx);
         /* "encryptionInformation.schema" must be the document from
          * "encryptedFields" fed from MONGOCRYPT_CTX_NEED_MONGO_COLLINFO. */
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_BSON ("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                       "'schema': { 'db.coll': {'foo': 'bar'}}}}"),
            cmd_to_mongocryptd);
         mongocrypt_binary_destroy (cmd_to_mongocryptd);
         ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      }

      mongocrypt_ctx_destroy (ctx);
   }

   /* Test that "encryptedFields" is preferred over "$jsonSchema". */
   {
      /* Recreate crypt to clear cache. */
      mongocrypt_destroy (crypt);
      crypt = mongocrypt_new ();
      ASSERT_OK (
         mongocrypt_setopt_kms_providers (
            crypt,
            TEST_BSON (
               "{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
         crypt);
      ASSERT_OK (mongocrypt_init (crypt), crypt);
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (mongocrypt_ctx_encrypt_init (
                    ctx, "db", -1, TEST_BSON ("{'find': 'coll'}")),
                 ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
      {
         ASSERT_OK (
            mongocrypt_ctx_mongo_feed (
               ctx,
               TEST_BSON (
                  "{'name': 'coll', 'options': { 'validator': { '$jsonSchema': "
                  "{'baz': 'qux' }}, 'encryptedFields': {'foo': 'bar'}}}")),
            ctx);
         ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      }

      /* Check that command to mongocryptd includes "encryptionInformation". */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
      {
         mongocrypt_binary_t *cmd_to_mongocryptd;

         cmd_to_mongocryptd = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, cmd_to_mongocryptd), ctx);
         /* "encryptionInformation.schema" must be the document from
          * "encryptedFields" fed from MONGOCRYPT_CTX_NEED_MONGO_COLLINFO. */
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_BSON ("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                       "'schema': { 'db.coll': {'foo': 'bar'}}}}"),
            cmd_to_mongocryptd);
         mongocrypt_binary_destroy (cmd_to_mongocryptd);
         ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      }

      mongocrypt_ctx_destroy (ctx);
   }

   mongocrypt_destroy (crypt);
}

static void
_test_encrypt_with_bypassqueryanalysis (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (
         crypt,
         TEST_BSON (
            "{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
      crypt);
   ASSERT_OK (mongocrypt_setopt_encrypted_field_config_map (
                 crypt, TEST_BSON ("{'db.coll': {'foo': 'bar'}}")),
              crypt);
   mongocrypt_setopt_bypass_query_analysis (crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "db", -1, TEST_BSON ("{'find': 'coll'}")),
              ctx);

   /* Should transition directly to ready. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      mongocrypt_binary_t *cmd_to_mongod = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, cmd_to_mongod), ctx);
      /* "encryptionInformation" must be present. */
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
         TEST_BSON ("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                    "'schema': { 'db.coll': {'foo': 'bar'}}}}"),
         cmd_to_mongod);
      mongocrypt_binary_destroy (cmd_to_mongod);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_FLE2EncryptionPlaceholder_parse (_mongocrypt_tester_t *tester)
{
   mc_FLE2EncryptionPlaceholder_t placeholder;
   bson_t as_bson;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t buf;

   status = mongocrypt_status_new ();
   _mongocrypt_buffer_copy_from_hex (
      &buf,
      "03610000001074000100000010610002000000056b690010000000041234567812349876"
      "1234123456789012056b75001000000004abcdefab123498761234123456789012027600"
      "0900000076616c75653132330012636d00000000000000000000");
   ASSERT (bson_init_static (&as_bson, buf.data + 1, buf.len - 1));
   mc_FLE2EncryptionPlaceholder_init (&placeholder);
   ASSERT_OK_STATUS (
      mc_FLE2EncryptionPlaceholder_parse (&placeholder, &as_bson, status),
      status);

   ASSERT (placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT);
   ASSERT (placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_EQUALITY);
   ASSERT (BSON_ITER_HOLDS_UTF8 (&placeholder.v_iter));
   ASSERT_STREQUAL (bson_iter_utf8 (&placeholder.v_iter, NULL), "value123");

   _mongocrypt_buffer_t expect_index_key_id;
   _mongocrypt_buffer_copy_from_hex (&expect_index_key_id,
                                     "12345678123498761234123456789012");
   ASSERT_CMPBUF (placeholder.index_key_id, expect_index_key_id);
   _mongocrypt_buffer_cleanup (&expect_index_key_id);

   _mongocrypt_buffer_t expect_user_key_id;
   _mongocrypt_buffer_copy_from_hex (&expect_user_key_id,
                                     "abcdefab123498761234123456789012");
   ASSERT_CMPBUF (placeholder.user_key_id, expect_user_key_id);
   _mongocrypt_buffer_cleanup (&expect_user_key_id);

   ASSERT (placeholder.maxContentionCounter == 0);

   mc_FLE2EncryptionPlaceholder_cleanup (&placeholder);
   _mongocrypt_buffer_cleanup (&buf);
   mongocrypt_status_destroy (status);
}


#if defined(MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO) || \
   defined(MONGOCRYPT_ENABLE_CRYPTO_CNG)
static void
_test_encrypt_fle2_insert_payload (_mongocrypt_tester_t *tester)
{
   printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
           "remove once MONGOCRYPT-385 and MONGOCRYPT-386 are complete");
   return;
}
#else

// Shared implementation for insert and find tests
typedef struct {
   _mongocrypt_buffer_t buf;
   int pos;
} _test_rng_data_source;

static bool
_test_rng_source (void *ctx,
                  mongocrypt_binary_t *out,
                  uint32_t count,
                  mongocrypt_status_t *status)
{
   _test_rng_data_source *source = (_test_rng_data_source *) ctx;

   if ((source->pos + count) > source->buf.len) {
      TEST_ERROR ("Out of random data, wanted: %" PRIu32, count);
      return false;
   }

   memcpy (out->data, source->buf.data + source->pos, count);
   source->pos += count;
   return true;
}

static void
_test_encrypt_fle2_encryption_placeholder (_mongocrypt_tester_t *tester,
                                           const char *data_path,
                                           _test_rng_data_source *rng_source)
{
   mongocrypt_t *crypt;
   char pathbuf[PATH_MAX];

#define MAKE_PATH(path)                                                       \
   ASSERT (snprintf (                                                         \
              pathbuf, sizeof (pathbuf), "./test/data/%s/" path, data_path) < \
           sizeof (pathbuf))

   /* Create crypt with custom hooks. */
   {
      /* localkey_data is the KEK used to encrypt the keyMaterial
       * in ./test/data/keys/ */
      char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
      mongocrypt_binary_t *localkey;

      crypt = mongocrypt_new ();
      mongocrypt_setopt_log_handler (crypt, _mongocrypt_stdout_log_fn, NULL);
      localkey = mongocrypt_binary_new_from_data ((uint8_t *) localkey_data,
                                                  sizeof localkey_data);
      ASSERT_OK (mongocrypt_setopt_kms_provider_local (crypt, localkey), crypt);
      ASSERT_OK (mongocrypt_setopt_crypto_hooks (
                    crypt,
                    _std_hook_native_crypto_aes_256_cbc_encrypt,
                    _std_hook_native_crypto_aes_256_cbc_decrypt,
                    _test_rng_source,
                    _std_hook_native_hmac_sha512,
                    _std_hook_native_hmac_sha256,
                    _error_hook_native_sha256,
                    rng_source /* ctx */),
                 crypt);

      MAKE_PATH ("encrypted-field-map.json");
      ASSERT_OK (mongocrypt_setopt_encrypted_field_config_map (
                    crypt, TEST_FILE (pathbuf)),
                 crypt);
      mongocrypt_binary_destroy (localkey);
      ASSERT_OK (mongocrypt_init (crypt), crypt);
   }

   /* Create encryption context. */
   mongocrypt_ctx_t *ctx;
   {
      ctx = mongocrypt_ctx_new (crypt);
      MAKE_PATH ("cmd.json");
      ASSERT_OK (
         mongocrypt_ctx_encrypt_init (ctx, "db", -1, TEST_FILE (pathbuf)), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   {
      /* Use a FLE2EncryptionPlaceholder obtained from
       * https://gist.github.com/kevinAlbs/cba611fe0d120b3f67c6bee3195d4ce6. */
      MAKE_PATH ("mongocryptd-reply.json");
      ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, TEST_FILE (pathbuf)), ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

#define TEST_KEY_FILE(name)            \
   TEST_FILE ("./test/data/keys/" name \
              "123498761234123456789012-local-document.json")

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, TEST_KEY_FILE ("12345678")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, TEST_KEY_FILE ("ABCDEFAB")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }
#undef TEST_KEY_FILE

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      mongocrypt_binary_t *out;
      bson_t out_bson, expect_bson;

      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      MAKE_PATH ("encrypted-payload.json");
      ASSERT (_mongocrypt_binary_to_bson (TEST_FILE (pathbuf), &expect_bson));
      _assert_match_bson (&out_bson, &expect_bson);
      mongocrypt_binary_destroy (out);
   }
#undef MAKE_PATH

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}
#endif


/* First 16 bytes are IV for 'p' field in FLE2InsertUpdatePayload
 * Second 16 bytes are IV for 'v' field in FLE2InsertUpdatePayload
 */
#define RNG_DATA                                                      \
   "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9" \
   "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"
static void
_test_encrypt_fle2_insert_payload (_mongocrypt_tester_t *tester)
{
   _test_rng_data_source source = {
      .buf = {.data = (uint8_t*)RNG_DATA, .len = sizeof (RNG_DATA)}};
   _test_encrypt_fle2_encryption_placeholder (tester, "fle2-insert", &source);
}
#undef RNG_DATA

// FLE2FindEqualityPayload only uses deterministic token generation.
static void
_test_encrypt_fle2_find_payload (_mongocrypt_tester_t *tester)
{
   _test_rng_data_source source = {{0}};
   _test_encrypt_fle2_encryption_placeholder (tester, "fle2-find", &source);
}

void
_mongocrypt_tester_install_ctx_encrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_explicit_encrypt_init);
   INSTALL_TEST (_test_encrypt_init);
   INSTALL_TEST (_test_encrypt_need_collinfo);
   INSTALL_TEST (_test_encrypt_need_markings);
   INSTALL_TEST (_test_encrypt_csfle_no_needs_markings);
   INSTALL_TEST (_test_encrypt_need_keys);
   INSTALL_TEST (_test_encrypt_ready);
   INSTALL_TEST (_test_key_missing_region);
   INSTALL_TEST (_test_view);
   INSTALL_TEST (_test_local_schema);
   INSTALL_TEST (_test_encrypt_caches_collinfo);
   INSTALL_TEST (_test_encrypt_caches_keys);
   INSTALL_TEST (_test_encrypt_caches_keys_by_alt_name);
   INSTALL_TEST (_test_encrypt_random);
   INSTALL_TEST (_test_encrypt_is_remote_schema);
   INSTALL_TEST (_test_encrypt_init_each_cmd);
   INSTALL_TEST (_test_encrypt_invalid_siblings);
   INSTALL_TEST (_test_encrypt_dupe_jsonschema);
   INSTALL_TEST (_test_encrypting_with_explicit_encryption);
   INSTALL_TEST (_test_explicit_encryption);
   INSTALL_TEST (_test_encrypt_empty_aws);
   INSTALL_TEST (_test_encrypt_custom_endpoint);
   INSTALL_TEST (_test_encrypt_with_aws_session_token);
   INSTALL_TEST (_test_encrypt_caches_empty_collinfo);
   INSTALL_TEST (_test_encrypt_caches_collinfo_without_jsonschema);
   INSTALL_TEST (_test_encrypt_per_ctx_credentials);
   INSTALL_TEST (_test_encrypt_per_ctx_credentials_local);
   INSTALL_TEST (_test_encrypt_with_encrypted_field_config_map);
   INSTALL_TEST (_test_encrypt_with_encrypted_field_config_map_bypassed);
   INSTALL_TEST (_test_encrypt_no_schema);
   INSTALL_TEST (_test_encrypt_remote_encryptedfields);
   INSTALL_TEST (_test_encrypt_with_bypassqueryanalysis);
   INSTALL_TEST (_test_FLE2EncryptionPlaceholder_parse);
   INSTALL_TEST (_test_encrypt_fle2_insert_payload);
   INSTALL_TEST (_test_encrypt_fle2_find_payload);
}
