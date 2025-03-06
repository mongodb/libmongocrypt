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

#include "kms_message/kms_b64.h"
#include "mongocrypt-crypto-private.h" // MONGOCRYPT_KEY_LEN
#include "mongocrypt.h"
#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt-crypto-std-hooks.h"
#include "test-mongocrypt.h"

static void _test_explicit_encrypt_init(_mongocrypt_tester_t *tester) {
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

    char *random = MONGOCRYPT_ALGORITHM_RANDOM_STR;
    char *deterministic = MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR;

    bson_msg = BCON_NEW("v", "hello");
    msg = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(bson_msg), bson_msg->len);

    bson_msg_no_v = BCON_NEW("a", "hello");
    no_v_msg = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(bson_msg_no_v), bson_msg_no_v->len);

    bson_name = BCON_NEW("keyAltName", "Rebekah");
    name = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(bson_name), bson_name->len);

    bson_bad_name = BCON_NEW("noAltName", "Barry");
    bad_name = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(bson_bad_name), bson_bad_name->len);

    string_msg = mongocrypt_binary_new_from_data(MONGOCRYPT_DATA_AND_LEN("hello"));
    key_id = mongocrypt_binary_new_from_data(MONGOCRYPT_DATA_AND_LEN("2395340598345034"));

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    /* Initting with no options will fail (need key_id). */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, msg), ctx, "either key id or key alt name required");
    mongocrypt_ctx_destroy(ctx);

    /* Initting with only key_id will not succeed, we also
       need an algorithm. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, msg), ctx, "algorithm or index type required");
    mongocrypt_ctx_destroy(ctx);

    /* Test null msg input. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, NULL), ctx, "msg required for explicit encryption");
    mongocrypt_ctx_destroy(ctx);

    /* Test with string msg input (no bson) */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, string_msg), ctx, "msg must be bson");
    mongocrypt_ctx_destroy(ctx);

    /* Test with input bson that has no "v" field */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, no_v_msg), ctx, "invalid msg, must contain 'v'");
    mongocrypt_ctx_destroy(ctx);

    /* Initting with RANDOM passes */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, msg), ctx);
    BSON_ASSERT(ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
    mongocrypt_ctx_destroy(ctx);

    /* Test that bad algorithm input fails */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_setopt_algorithm(ctx, "nonexistent algorithm", -1), ctx, "unsupported algorithm");
    mongocrypt_ctx_destroy(ctx);

    /* Test with badly formatted key alt name */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_setopt_key_alt_name(ctx, bad_name), ctx, "must have field");
    mongocrypt_ctx_destroy(ctx);

    /* Test with key alt name */
    ctx = mongocrypt_ctx_new(crypt);
    BSON_ASSERT(mongocrypt_ctx_setopt_key_alt_name(ctx, name));
    BSON_ASSERT(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1));
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, msg), ctx);

    /* After initing, we should be at NEED_KEYS */
    BSON_ASSERT(ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
    BSON_ASSERT(ctx->state == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    mongocrypt_ctx_destroy(ctx);

    /* double succeeds for random. */
    tmp = TEST_BSON("{'v': { '$double': '1.23'} }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* double fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for deterministic encryption");
    mongocrypt_ctx_destroy(ctx);

    /* decimal128 succeeds for random. */
    tmp = TEST_BSON("{'v': {'$numberDecimal': '1.23'} }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* decimal128 fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for deterministic encryption");
    mongocrypt_ctx_destroy(ctx);

    /* document succeeds for random. */
    tmp = TEST_BSON("{'v': { 'x': 1 } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* document fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for deterministic encryption");
    mongocrypt_ctx_destroy(ctx);

    /* array succeeds for random. */
    tmp = TEST_BSON("{'v': [1,2,3] }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* document fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for deterministic encryption");
    mongocrypt_ctx_destroy(ctx);

    /* codewscope succeeds for random. */
    tmp = TEST_BSON("{'v': {'$code': 'var x = 1;', '$scope': {} } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* codewscope fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for deterministic encryption");
    mongocrypt_ctx_destroy(ctx);

    /* bool succeeds for random. */
    tmp = TEST_BSON("{'v': true }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* bool fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for deterministic encryption");
    mongocrypt_ctx_destroy(ctx);

    /* null fails for deterministic. */
    tmp = TEST_BSON("{'v': null }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* null fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* minkey fails for deterministic. */
    tmp = TEST_BSON("{'v': { '$minKey': 1 } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* minkey fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* maxkey fails for deterministic. */
    tmp = TEST_BSON("{'v': { '$maxKey': 1 } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* maxkey fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* undefined fails for deterministic. */
    tmp = TEST_BSON("{'v': { '$undefined': true } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* undefined fails for deterministic. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx, "BSON type invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* dbpointer succeeds for deterministic. */
    tmp = TEST_BSON("{'v': { '$dbPointer': {'$ref': 'ns', '$id': {'$oid': "
                    "'AAAAAAAAAAAAAAAAAAAAAAAA'} } } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* dbpointer succeeds for random. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp), ctx);
    mongocrypt_ctx_destroy(ctx);

    /* binary subtype 6 fails for deterministic. */
    tmp = TEST_BSON("{'v': { '$binary': { 'base64': 'AAAA', 'subType': '06' } } }");
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp),
                 ctx,
                 "BSON binary subtype 6 is invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    /* binary subtype 6 fails for random. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, random, -1), ctx);
    ASSERT_FAILS(mongocrypt_ctx_explicit_encrypt_init(ctx, tmp),
                 ctx,
                 "BSON binary subtype 6 is invalid for encryption");
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);

    mongocrypt_binary_destroy(msg);
    mongocrypt_binary_destroy(bad_name);
    mongocrypt_binary_destroy(name);
    mongocrypt_binary_destroy(string_msg);
    mongocrypt_binary_destroy(no_v_msg);
    mongocrypt_binary_destroy(key_id);
    bson_destroy(bson_bad_name);
    bson_destroy(bson_name);
    bson_destroy(bson_msg);
    bson_destroy(bson_msg_no_v);
}

/* Test individual ctx states. */
static void _test_encrypt_init(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    /* Success. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    mongocrypt_ctx_destroy(ctx);

    /* NULL namespace. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, NULL, 0, TEST_FILE("./test/example/cmd.json")), ctx, "invalid db");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);

    /* Wrong state. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")),
                 ctx,
                 "cannot double initialize");
    mongocrypt_ctx_destroy(ctx);

    /* Empty db name is an error. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "", -1, TEST_FILE("./test/example/cmd.json")), ctx, "invalid db");
    mongocrypt_ctx_destroy(ctx);

    /* Empty coll name is an error. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "", -1, TEST_BSON("{'find': ''}")), ctx, "invalid db");
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);
}

static void _test_encrypt_need_collinfo(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    /* Success. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/collection-info.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* Coll info with no schema. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */
    /* Coll info with NULL schema. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, NULL), ctx, "invalid NULL");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* No coll info. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    /* No call to ctx_mongo_feed. */
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* Wrong state. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/collection-info.json")), ctx, "wrong state");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_need_markings(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *bin;

    bin = mongocrypt_binary_new();

    /* Success. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    mongocrypt_ctx_mongo_op(ctx, bin);
    ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/mongocryptd-cmd.json"), bin);

    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/mongocryptd-reply.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* Key alt name. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-key-alt-name.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* No placeholders. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-no-markings.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_READY);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* No encryption in schema. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-no-encryption-needed.json")),
              ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_READY);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* Invalid marking. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-invalid.json")),
                 ctx,
                 "no 'v'");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* NULL markings. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, NULL), ctx, "invalid NULL");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* Wrong state. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/mongocryptd-reply.json")),
                 ctx,
                 "wrong state");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_csfle_no_needs_markings(_mongocrypt_tester_t *tester) {
    if (!TEST_MONGOCRYPT_HAVE_REAL_CRYPT_SHARED_LIB) {
        TEST_STDERR_PRINTF("No 'real' csfle library is available. The %s test is a no-op.\n", BSON_FUNC);
        return;
    }

    /* Success. */
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_WITH_CRYPT_SHARED_LIB);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_need_keys(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    /* Success. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/key-document.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_KMS);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */

    /* Did not provide all keys. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_done(ctx), ctx, "not all keys requested were satisfied");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* recreate crypt because of caching. */
}

static void _test_encrypt_ready(_mongocrypt_tester_t *tester) {
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
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    encrypted_cmd = mongocrypt_binary_new();

    ASSERT_OR_PRINT(crypt, status);

    /* Success. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, encrypted_cmd), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_DONE);

    /* check that the encrypted command has a valid ciphertext. */
    BSON_ASSERT(_mongocrypt_binary_to_bson(encrypted_cmd, &as_bson));
    CRYPT_TRACEF(&crypt->log, "encrypted doc: %s", tmp_json(&as_bson));
    bson_iter_init(&iter, &as_bson);
    bson_iter_find_descendant(&iter, "filter.ssn", &iter);
    BSON_ASSERT(BSON_ITER_HOLDS_BINARY(&iter));
    BSON_ASSERT(_mongocrypt_buffer_from_binary_iter(&ciphertext_buf, &iter));
    ret = _mongocrypt_ciphertext_parse_unowned(&ciphertext_buf, &ciphertext, status);
    ASSERT_OR_PRINT(ret, status);

    /* check that encrypted command matches. */
    ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/encrypted-cmd.json"), encrypted_cmd);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_binary_destroy(encrypted_cmd);
    mongocrypt_status_destroy(status);
    mongocrypt_destroy(crypt);
}

static void _test_key_missing_region(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-no-region.json")),
                 ctx,
                 "expected UTF-8 region");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Test that attempting to auto encrypt on a view is disallowed. */
static void _test_view(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_BSON(BSON_STR({"find" : "v", "filter" : {}}))), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/collection-info-view.json")),
                 ctx,
                 "cannot auto encrypt a view");
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_ERROR);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Check that the schema identified in the schema_map by 'ns' matches the
 * 'jsonSchema' of the mongocryptd command. */
static void
_assert_schema_compares(mongocrypt_binary_t *schema_map, const char *ns, mongocrypt_binary_t *mongocryptd_cmd) {
    bson_t schema_map_bson, mongocryptd_cmd_bson, expected_schema, actual_schema;
    uint32_t len;
    const uint8_t *data;
    bson_iter_t iter;

    /* Get the schema from the map. */
    BSON_ASSERT(_mongocrypt_binary_to_bson(schema_map, &schema_map_bson));
    BSON_ASSERT(bson_iter_init_find(&iter, &schema_map_bson, ns));
    bson_iter_document(&iter, &len, &data);
    bson_init_static(&expected_schema, data, len);

    /* Get the schema from the mongocryptd command. */
    BSON_ASSERT(_mongocrypt_binary_to_bson(mongocryptd_cmd, &mongocryptd_cmd_bson));
    BSON_ASSERT(bson_iter_init_find(&iter, &mongocryptd_cmd_bson, "jsonSchema"));
    bson_iter_document(&iter, &len, &data);
    BSON_ASSERT(bson_init_static(&actual_schema, data, len));

    BSON_ASSERT(bson_equal(&expected_schema, &actual_schema));
}

static void _test_local_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *schema_map, *mongocryptd_cmd;

    crypt = mongocrypt_new();
    schema_map = TEST_FILE("./test/data/schema-map.json");
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, schema_map), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    /* Schema map has test.test, we should jump right to NEED_MONGO_MARKINGS */
    ctx = mongocrypt_ctx_new(crypt);
    mongocryptd_cmd = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, mongocryptd_cmd), ctx);

    /* We should get back the schema we gave. */
    _assert_schema_compares(schema_map, "test.test", mongocryptd_cmd);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_binary_destroy(mongocryptd_cmd);

    /* Schema map has test.test2, we should jump right to NEED_MONGO_MARKINGS */
    ctx = mongocrypt_ctx_new(crypt);
    mongocryptd_cmd = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_BSON("{'find': 'test2'}")), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, mongocryptd_cmd), ctx);

    /* We should get back the schema we gave. */
    _assert_schema_compares(schema_map, "test.test2", mongocryptd_cmd);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_binary_destroy(mongocryptd_cmd);

    /* Database that does not match should not get from the map. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "mismatch", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    mongocrypt_ctx_destroy(ctx);

    /* Collection that does not match should not get from the map. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_BSON("{'find': 'mismatch'}")), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);
}

static void _test_encrypt_caches_collinfo(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    bson_t *cached_collinfo;
    mongocrypt_status_t *status;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    status = mongocrypt_status_new();
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/collection-info.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    /* The next ctx has the schema cached. */
    BSON_ASSERT(_mongocrypt_cache_get(&crypt->cache_collinfo, "test.test", (void **)&cached_collinfo));
    BSON_ASSERT(cached_collinfo != NULL);
    bson_destroy(cached_collinfo);
    mongocrypt_ctx_destroy(ctx);

    /* The next context enters the NEED_MONGO_MARKINGS state immediately. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
}

static void _test_encrypt_caches_keys(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);
    /* The next context skips needing keys after being supplied mark documents.
     */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/mongocryptd-reply.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_READY);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_cache_expiration(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_WITH_SHORT_CACHE);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);

    // Sleep to trigger cache expiration.
    // Cache entries expire after 1ms, but use 20ms to avoid timing errors observed on Windows distros: CDRIVER-4526
    _usleep(20 * 1000);
    /* The next context requests keys again
     */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/mongocryptd-reply.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/key-document.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_caches_keys_by_alt_name(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-key-alt-name.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-with-alt-name.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    mongocrypt_ctx_destroy(ctx);

    /* The next context skips needing keys after being supplied mark documents.
     */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-key-alt-name.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_READY);
    mongocrypt_ctx_destroy(ctx);

    /* But a context requesting a different key alt name does not get it from the
     * cache. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-key-alt-name2.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-with-alt-name2.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);
}

static void _test_encrypt_random(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-random.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_is_remote_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *bin;
    bson_t as_bson;
    bson_iter_t iter;

    bin = mongocrypt_binary_new();

    /* isRemoteSchema = true for a remote schema. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, bin), ctx);
    BSON_ASSERT(_mongocrypt_binary_to_bson(bin, &as_bson));
    BSON_ASSERT(bson_iter_init_find(&iter, &as_bson, "isRemoteSchema"));
    BSON_ASSERT(bson_iter_bool(&iter) == true);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);

    /* isRemoteSchema = false for a local schema. */
    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_FILE("./test/data/schema-map.json")), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, bin), ctx);
    BSON_ASSERT(_mongocrypt_binary_to_bson(bin, &as_bson));
    BSON_ASSERT(bson_iter_init_find(&iter, &as_bson, "isRemoteSchema"));
    BSON_ASSERT(bson_iter_bool(&iter) == false);

    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _init_fails(_mongocrypt_tester_t *tester, const char *json, const char *msg) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_BSON_STR(json)), ctx, msg);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _init_ok(_mongocrypt_tester_t *tester, const char *json) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_BSON_STR(json)), ctx);

    if (MONGOCRYPT_CTX_NEED_MONGO_COLLINFO == mongocrypt_ctx_state(ctx)) {
        mongocrypt_binary_t *filter;
        /* verify the collection in the filter is 'coll' */
        filter = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, filter), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'name': 'coll'}"), filter);

        mongocrypt_binary_destroy(filter);
    } else {
        // The "create" command transitions directly to
        // MONGOCRYPT_CTX_NEED_MONGO_MARKINGS.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _init_bypass(_mongocrypt_tester_t *tester, const char *json) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *bin;

    bin = mongocrypt_binary_new();
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_BSON_STR(json)), ctx);
    BSON_ASSERT(MONGOCRYPT_CTX_READY == mongocrypt_ctx_state(ctx));
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
    ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON_STR(json), (bin));

    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_init_each_cmd(_mongocrypt_tester_t *tester) {
    /* collection aggregate is ok */
    _init_ok(tester, "{'aggregate': 'coll'}");
    /* db agg is not ok */
    _init_fails(tester, "{'aggregate': 1}", "non-collection command not supported for auto encryption: aggregate");
    _init_ok(tester, "{'count': 'coll'}");
    _init_ok(tester, "{'distinct': 'coll'}");
    _init_ok(tester, "{'delete': 'coll'}");
    _init_ok(tester, "{'find': 'coll'}");
    _init_ok(tester, "{'findAndModify': 'coll'}");
    _init_bypass(tester, "{'getMore': 'coll'}");
    _init_ok(tester, "{'insert': 'coll'}");
    _init_ok(tester, "{'update': 'coll'}");
    _init_bypass(tester, "{'authenticate': 1}");
    _init_bypass(tester, "{'getnonce': 1}");
    _init_bypass(tester, "{'logout': 1}");
    _init_bypass(tester, "{'isMaster': 1}");
    _init_bypass(tester, "{'abortTransaction': 1}");
    _init_bypass(tester, "{'commitTransaction': 1}");
    _init_bypass(tester, "{'endSessions': 1}");
    _init_bypass(tester, "{'startSession': 1}");
    _init_ok(tester, "{'create': 'coll'}");
    _init_ok(tester, "{'createIndexes': 'coll'}");
    _init_bypass(tester, "{'drop': 1}");
    _init_bypass(tester, "{'dropDatabase': 1}");
    _init_bypass(tester, "{'killCursors': 1}");
    _init_bypass(tester, "{'listCollections': 1}");
    _init_bypass(tester, "{'listDatabases': 1}");
    _init_bypass(tester, "{'listIndexes': 1}");
    _init_bypass(tester, "{'renameCollection': 'coll'}");
    _init_ok(tester, "{'explain': { 'find': 'coll' }}");
    _init_fails(tester, "{'explain': { } }", "invalid empty BSON");
    _init_fails(tester, "{'explain': { 'aggregate': 1 }}", "non-collection command not supported for auto encryption");
    _init_bypass(tester, "{'ping': 1}");
    _init_bypass(tester, "{'saslStart': 1}");
    _init_bypass(tester, "{'saslContinue': 1}");
    _init_fails(tester, "{'fakecmd': 'coll'}", "command not supported for auto encryption: fakecmd");
    /* fails for eligible command with no collection name. */
    _init_fails(tester, "{'insert': 1}", "non-collection command not supported for auto encryption: insert");
    _init_fails(tester, "{}", "unexpected empty BSON for command");
    _init_bypass(tester, "{'isMaster': 1}");
    _init_bypass(tester, "{'ismaster': 1}");
    _init_bypass(tester, "{'killAllSessions': 1}");
    _init_bypass(tester, "{'killSessions': 1}");
    _init_bypass(tester, "{'killAllSessionsByPattern': 1}");
    _init_bypass(tester, "{'refreshSessions': 1}");
    _init_ok(tester, "{'cleanupStructuredEncryptionData': 'coll'}");
    _init_ok(tester, "{'compactStructuredEncryptionData': 'coll'}");
    _init_bypass(tester, "{'hello': 1}");
    _init_bypass(tester, "{'buildInfo': 1}");
    _init_bypass(tester, "{'getCmdLineOpts': 1}");
    _init_bypass(tester, "{'getLog': 1}");
    _init_ok(tester, "{'collMod': 'coll'}");
    _init_bypass(tester, "{'listSearchIndexes': 'coll' }");
    _init_bypass(tester, "{'createSearchIndexes': 'coll' }");
    _init_bypass(tester, "{'dropSearchIndex': 'coll' }");
    _init_bypass(tester, "{'updateSearchIndex': 'coll' }");
}

static void _test_encrypt_invalid_siblings(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);

    BSON_ASSERT(MONGOCRYPT_CTX_NEED_MONGO_COLLINFO == mongocrypt_ctx_state(ctx));
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/collinfo-siblings.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    BSON_ASSERT(MONGOCRYPT_CTX_NEED_MONGO_MARKINGS == mongocrypt_ctx_state(ctx));
    // MONGOCRYPT-771 removes checks for sibling validators.
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/mongocryptd-reply.json")), ctx);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypting_with_explicit_encryption(_mongocrypt_tester_t *tester) {
    /* Test that we do not strip existing ciphertexts when automatically
     * encrypting a document. */
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *bin;
    bson_iter_t iter;
    bson_t tmp;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);

    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-reply-existing-ciphertext.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    bin = mongocrypt_binary_new();
    mongocrypt_ctx_finalize(ctx, bin);
    BSON_ASSERT(_mongocrypt_binary_to_bson(bin, &tmp));
    BSON_ASSERT(bson_iter_init(&iter, &tmp));
    BSON_ASSERT(bson_iter_find_descendant(&iter, "filter.existing_ciphertext", &iter));
    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_explicit_encryption(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    _mongocrypt_buffer_t from_key_id, from_key_altname;
    mongocrypt_binary_t *bin, *key_id;
    char *deterministic = MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    ctx = mongocrypt_ctx_new(crypt);
    key_id = mongocrypt_binary_new_from_data(MONGOCRYPT_DATA_AND_LEN("aaaaaaaaaaaaaaaa"));

    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, key_id), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON("{'v': 123}")), ctx);

    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
    _mongocrypt_buffer_copy_from_binary(&from_key_id, bin);
    mongocrypt_binary_destroy(bin);

    mongocrypt_binary_destroy(key_id);
    mongocrypt_ctx_destroy(ctx);

    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, deterministic, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON("{'keyAltName': 'keyDocumentName'}")), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON("{'v': 123}")), ctx);

    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
    _mongocrypt_buffer_copy_from_binary(&from_key_altname, bin);
    mongocrypt_binary_destroy(bin);

    mongocrypt_ctx_destroy(ctx);

    BSON_ASSERT(0 == _mongocrypt_buffer_cmp(&from_key_id, &from_key_altname));

    _mongocrypt_buffer_cleanup(&from_key_id);
    _mongocrypt_buffer_cleanup(&from_key_altname);

    mongocrypt_destroy(crypt);
}

/* Test with empty AWS credentials. */
static void _test_encrypt_empty_aws(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "", -1, "", -1), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/key-document.json")),
                 ctx,
                 "failed to create KMS message");

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_custom_endpoint(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms_ctx;
    mongocrypt_binary_t *bin;
    const char *endpoint;

    /* Success. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/key-document-custom-endpoint.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_KMS);
    kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
    BSON_ASSERT(kms_ctx);
    ASSERT_OK(mongocrypt_kms_ctx_endpoint(kms_ctx, &endpoint), ctx);
    BSON_ASSERT(0 == strcmp("example.com:443", endpoint));
    bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_kms_ctx_message(kms_ctx, bin), ctx);
    BSON_ASSERT(NULL != strstr((char *)bin->data, "Host:example.com"));

    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_per_ctx_credentials(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms_ctx;
    mongocrypt_binary_t *bin;
    const char *endpoint;

    /* Success. */
    crypt = mongocrypt_new();
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {}}"));
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
    ASSERT_OK(mongocrypt_ctx_provide_kms_providers(ctx,
                                                   TEST_BSON("{'aws':{'accessKeyId': 'example',"
                                                             "'secretAccessKey': 'example'}}")),
              ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/example/key-document-custom-endpoint.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_NEED_KMS);
    kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
    BSON_ASSERT(kms_ctx);
    ASSERT_OK(mongocrypt_kms_ctx_endpoint(kms_ctx, &endpoint), ctx);
    BSON_ASSERT(0 == strcmp("example.com:443", endpoint));
    bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_kms_ctx_message(kms_ctx, bin), ctx);
    BSON_ASSERT(NULL != strstr((char *)bin->data, "Host:example.com"));

    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

// Regression test for MONGOCRYPT-488.
static void _test_encrypt_per_ctx_credentials_given_empty(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = mongocrypt_new();
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {}}"));
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
    ASSERT_FAILS(mongocrypt_ctx_provide_kms_providers(ctx, TEST_BSON("{}")), ctx, "no kms provider set");

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_ERROR);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_per_ctx_credentials_local(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    /* local_kek is the KEK used to encrypt the keyMaterial in
     * ./test/data/key-document-local.json */
    uint8_t local_kek_raw[MONGOCRYPT_KEY_LEN] = {0};
    char *local_kek = kms_message_raw_to_b64(local_kek_raw, sizeof(local_kek_raw));

    crypt = mongocrypt_new();
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'local': {}}"));
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
    ASSERT_OK(mongocrypt_ctx_provide_kms_providers(ctx,
                                                   TEST_BSON("{'local':{'key': { '$binary': {'base64': '%s', "
                                                             "'subType': '00'}}}}",
                                                             local_kek)),
              ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-local.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
    bson_free(local_kek);
}

static void _test_encrypt_with_aws_session_token(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_binary_t *bin;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms_ctx;
    char *http_req;

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt,
                                              TEST_BSON("{'aws': {'sessionToken': 'mySessionToken', "
                                                        "'accessKeyId': 'myAccessKeyId', "
                                                        "'secretAccessKey': 'mySecretAccessKey'}}")),
              crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);

    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
    kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
    BSON_ASSERT(NULL != kms_ctx);

    bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_kms_ctx_message(kms_ctx, bin), kms_ctx);
    http_req = (char *)mongocrypt_binary_data(bin);
    ASSERT_STRCONTAINS(http_req, "X-Amz-Security-Token:mySessionToken");

    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_caches_empty_collinfo(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    /* Do not feed anything for collinfo. */
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);

    /* Create another encryption context on the same namespace test.test. It
     * should not transition to the MONGOCRYPT_CTX_NEED_MONGO_COLLINFO state. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);
}

static void _test_encrypt_caches_collinfo_without_jsonschema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/collection-info-no-validator.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);

    /* Create another encryption context on the same namespace test.test. It
     * should not transition to the MONGOCRYPT_CTX_NEED_MONGO_COLLINFO state. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
    mongocrypt_ctx_destroy(ctx);

    mongocrypt_destroy(crypt);
}

static void _test_encrypt_with_encrypted_field_config_map(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = mongocrypt_new();
    ASSERT_OK(
        mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
        crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BSON("{'db.coll': {'fields': []}}")), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    /* Test encrypting a command on a collection present in the encrypted field
     * config map. */
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd;

        cmd_to_mongocryptd = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        ASSERT_OK(
            mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-find-explicit/reply-from-mongocryptd.json")),
            ctx);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *cmd_to_mongod;

        cmd_to_mongod = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, cmd_to_mongod), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongod.json"),
                                            cmd_to_mongod);
        mongocrypt_binary_destroy(cmd_to_mongod);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Test encrypting a bypassed command on a collection present in the encrypted
 * field config map. Expect no encryptionInformation. */
static void _test_encrypt_with_encrypted_field_config_map_bypassed(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = mongocrypt_new();
    ASSERT_OK(
        mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
        crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BSON("{'db.coll': {'fields': []}}")), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    ctx = mongocrypt_ctx_new(crypt);
    /* 'drop' is bypassed. Expect that no 'encryptionInformation' is appended. */
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'drop': 'coll'}")), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *cmd_to_mongod;

        cmd_to_mongod = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, cmd_to_mongod), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'drop': 'coll'}"), cmd_to_mongod);
        mongocrypt_binary_destroy(cmd_to_mongod);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Test that an empty jsonSchema document is appended to the command sent to
 * mongocryptd when no encryptedFieldConfig or jsonSchema is found for the
 * collection.
 *
 * This is a regression test for PYTHON-3188. */
static void _test_encrypt_no_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(
        mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'find': 'collection_without_schema', 'filter': {}}")),
        ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    /* Give no collection info. */
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd;

        cmd_to_mongocryptd = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'find': 'collection_without_schema', 'filter': {}, "
                                                      "'jsonSchema': {}, 'isRemoteSchema': true}"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_remote_encryptedfields(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = mongocrypt_new();
    ASSERT_OK(
        mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
        crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    /* Test success. */
    {
        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")),
                  ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_BSON("{'name': 'coll', 'options': "
                                                          "{'encryptedFields': {'fields': []}}}")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        /* Check that command to mongocryptd includes "encryptionInformation". */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            /* "encryptionInformation.schema" must be the document from
             * "encryptedFields" fed from MONGOCRYPT_CTX_NEED_MONGO_COLLINFO. */
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        mongocrypt_ctx_destroy(ctx);
    }

    /* Test that the previous 'encryptedFields' is cached. */
    {
        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")),
                  ctx);

        /* Check that command to mongocryptd includes "encryptionInformation". */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            /* "encryptionInformation.schema" must be the document from
             * "encryptedFields" fed from MONGOCRYPT_CTX_NEED_MONGO_COLLINFO. */
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        mongocrypt_ctx_destroy(ctx);
    }

    /* Test that "encryptedFields" is preferred over "$jsonSchema". */
    {
        /* Recreate crypt to clear cache. */
        mongocrypt_destroy(crypt);
        crypt = mongocrypt_new();
        ASSERT_OK(
            mongocrypt_setopt_kms_providers(crypt,
                                            TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
            crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")),
                  ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_BSON("{'name': 'coll', 'options': { 'validator': { '$jsonSchema': "
                                                          "{'baz': 'qux' }}, 'encryptedFields': {'fields': []}}}")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        /* Check that command to mongocryptd includes "encryptionInformation". */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd;

            cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            /* "encryptionInformation.schema" must be the document from
             * "encryptedFields" fed from MONGOCRYPT_CTX_NEED_MONGO_COLLINFO. */
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        mongocrypt_ctx_destroy(ctx);
    }

    mongocrypt_destroy(crypt);
}

static void _test_encrypt_with_bypassqueryanalysis(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    /* Test with EncryptedFieldConfig from map. */
    {
        crypt = mongocrypt_new();
        ASSERT_OK(
            mongocrypt_setopt_kms_providers(crypt,
                                            TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
            crypt);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BSON("{'db.coll': {'fields': []}}")), crypt);
        mongocrypt_setopt_bypass_query_analysis(crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")),
                  ctx);

        /* Should transition directly to ready. */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *cmd_to_mongod = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, cmd_to_mongod), ctx);
            /* "encryptionInformation" must be present. */
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongod.json"),
                                                cmd_to_mongod);
            mongocrypt_binary_destroy(cmd_to_mongod);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    /* Test with EncryptedFieldConfig from listCollections. */
    {
        crypt = mongocrypt_new();
        ASSERT_OK(
            mongocrypt_setopt_kms_providers(crypt,
                                            TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
            crypt);
        mongocrypt_setopt_bypass_query_analysis(crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(
                          ctx,
                          TEST_BSON("{'name': 'coll', 'options': {'encryptedFields': {'fields': []}}}")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *cmd_to_mongod = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, cmd_to_mongod), ctx);
            /* "encryptionInformation" must be present. */
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongod.json"),
                                                cmd_to_mongod);
            mongocrypt_binary_destroy(cmd_to_mongod);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

// Shared implementation for insert and find tests
typedef struct {
    _mongocrypt_buffer_t buf;
    int pos;
} _test_rng_data_source;

static bool _test_rng_source(void *ctx, mongocrypt_binary_t *out, uint32_t count, mongocrypt_status_t *status) {
    _test_rng_data_source *source = (_test_rng_data_source *)ctx;

    if ((source->pos + count) > source->buf.len) {
        TEST_ERROR("Out of random data, wanted: %" PRIu32, count);
        return false;
    }

    memcpy(out->data, source->buf.data + source->pos, count);
    source->pos += count;
    return true;
}

typedef enum {
    kFLE2v2Default,
    kFLE2v2Enable,
} _test_fle2v2_option;

#define TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, data_path, rng_source, v2_failure)                            \
    if (1) {                                                                                                           \
        (rng_source)->pos = 0;                                                                                         \
        _test_encrypt_fle2_encryption_placeholder(tester, data_path, rng_source, NULL);                                \
    } else                                                                                                             \
        ((void)0)

static void _test_encrypt_fle2_encryption_placeholder(_mongocrypt_tester_t *tester,
                                                      const char *data_path,
                                                      _test_rng_data_source *rng_source,
                                                      const char *finalize_failure) {
    mongocrypt_t *crypt;
    char pathbuf[2048];

#define MAKE_PATH(mypath)                                                                                              \
    if (1) {                                                                                                           \
        int pathbuf_ret = snprintf(pathbuf, sizeof(pathbuf), "./test/data/%s/%s", data_path, mypath);                  \
        ASSERT(pathbuf_ret >= 0 && (size_t)pathbuf_ret < sizeof(pathbuf));                                             \
    } else                                                                                                             \
        ((void)0)

    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    /* Create crypt with custom hooks. */
    {
        /* localkey_data is the KEK used to encrypt the keyMaterial
         * in ./test/data/keys/ */
        char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
        mongocrypt_binary_t *localkey;

        crypt = mongocrypt_new();
        mongocrypt_setopt_log_handler(crypt, _mongocrypt_stdout_log_fn, NULL);
        localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_hooks(crypt,
                                                 _std_hook_native_crypto_aes_256_cbc_encrypt,
                                                 _std_hook_native_crypto_aes_256_cbc_decrypt,
                                                 _test_rng_source,
                                                 _std_hook_native_hmac_sha512,
                                                 _std_hook_native_hmac_sha256,
                                                 _error_hook_native_sha256,
                                                 rng_source /* ctx */),
                  crypt);

        MAKE_PATH("encrypted-field-map.json");
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_FILE(pathbuf)), crypt);
        mongocrypt_binary_destroy(localkey);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    }

    /* Create encryption context. */
    mongocrypt_ctx_t *ctx;
    {
        ctx = mongocrypt_ctx_new(crypt);
        MAKE_PATH("cmd.json");
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE(pathbuf)), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        /* Use a FLE2EncryptionPlaceholder obtained from
         * https://gist.github.com/kevinAlbs/cba611fe0d120b3f67c6bee3195d4ce6. */
        MAKE_PATH("mongocryptd-reply.json");
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE(pathbuf)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

#define TEST_KEY_FILE(name) TEST_FILE("./test/data/keys/" name "123498761234123456789012-local-document.json")

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_KEY_FILE("12345678")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_KEY_FILE("ABCDEFAB")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }
#undef TEST_KEY_FILE

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        bool ok = mongocrypt_ctx_finalize(ctx, out);
        if (finalize_failure) {
            ASSERT_FAILS_STATUS(ok, ctx->status, finalize_failure);
        } else {
            ASSERT_OK(ok, ctx);
            MAKE_PATH("encrypted-payload.json");
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE(pathbuf), out);
        }
        mongocrypt_binary_destroy(out);
    }
#undef MAKE_PATH

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* First 16 bytes are IV for 'p' field in FLE2InsertUpdatePayload
 * Second 16 bytes are IV for 'v' field in FLE2InsertUpdatePayload
 */
#define RNG_DATA                                                                                                       \
    "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9"                                                 \
    "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"

static void _test_encrypt_fle2_insert_payload(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;

    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-v2", &source, NULL);
}

static void _test_encrypt_fle2_insert_payload_with_str_encode_version(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;

    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-v2-with-str-encode-version", &source, NULL);
}

static void _test_encrypt_fle2_insert_text_search_payload(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;

    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-text-search", &source, NULL);
}

static void _test_encrypt_fle2_insert_text_search_payload_with_str_encode_version(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;

    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-text-search-with-str-encode-version", &source, NULL);
}

#undef RNG_DATA

// FLE2FindEqualityPayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_payload(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-equality-v2", &source, NULL);
}

/* 16 bytes of random data are used for IV. This IV produces the expected test
 * ciphertext. */
#define RNG_DATA "\x4d\x06\x95\x64\xf5\xa0\x5e\x9e\x35\x23\xb9\x8f\x57\x5a\xcb\x15"

static void _test_encrypt_fle2_unindexed_encrypted_payload(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-unindexed-v2", &source, NULL);
}

#undef RNG_DATA

#include "./data/fle2-insert-range/int32/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_int32(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/int32-v2", &source, NULL);
}

#undef RNG_DATA

#include "./data/fle2-insert-range/int64/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_int64(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/int64-v2", &source, NULL);
}

#undef RNG_DATA

#include "./data/fle2-insert-range/date/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_date(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/date-v2", &source, NULL);
}

#undef RNG_DATA

#include "./data/fle2-insert-range/double/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_double(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/double-v2", &source, NULL);
}

#undef RNG_DATA

#include "./data/fle2-insert-range/double-precision/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_double_precision(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/double-precision-v2", &source, NULL);
}

#undef RNG_DATA

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT()
#include "./data/fle2-insert-range/decimal128/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_decimal128(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/decimal128-v2", &source, NULL);
}

#undef RNG_DATA

#include "./data/fle2-insert-range/decimal128-precision/RNG_DATA.h"

static void _test_encrypt_fle2_insert_range_payload_decimal128_precision(_mongocrypt_tester_t *tester) {
    uint8_t rng_data[] = RNG_DATA;
    _test_rng_data_source source = {.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-insert-range/decimal128-precision-v2", &source, NULL);
}

#undef RNG_DATA
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_int32(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/int32-v2", &source, NULL);
}

// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_int64(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/int64-v2", &source, NULL);
}

// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_date(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/date-v2", &source, NULL);
}

// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_double(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/double-v2", &source, NULL);
}

// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_double_precision(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/double-precision-v2", &source, NULL);
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT()
// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_decimal128(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/decimal128-v2", &source, NULL);
}

// FLE2FindRangePayload only uses deterministic token generation.
static void _test_encrypt_fle2_find_range_payload_decimal128_precision(_mongocrypt_tester_t *tester) {
    _test_rng_data_source source = {{0}};
    TEST_ENCRYPT_FLE2_ENCRYPTION_PLACEHOLDER(tester, "fle2-find-range/decimal128-precision-v2", &source, NULL);
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

static mongocrypt_t *_crypt_with_rng(_test_rng_data_source *rng_source) {
    mongocrypt_t *crypt;
    mongocrypt_binary_t *localkey;
    /* localkey_data is the KEK used to encrypt the keyMaterial
     * in ./test/data/keys/ */
    char localkey_data[MONGOCRYPT_KEY_LEN] = {0};

    crypt = mongocrypt_new();
    mongocrypt_setopt_log_handler(crypt, _mongocrypt_stdout_log_fn, NULL);
    localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
    ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
    ASSERT_OK(mongocrypt_setopt_crypto_hooks(crypt,
                                             _std_hook_native_crypto_aes_256_cbc_encrypt,
                                             _std_hook_native_crypto_aes_256_cbc_decrypt,
                                             _test_rng_source,
                                             _std_hook_native_hmac_sha512,
                                             _std_hook_native_hmac_sha256,
                                             _error_hook_native_sha256,
                                             rng_source /* ctx */),
              crypt);

    mongocrypt_binary_destroy(localkey);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    return crypt;
}

typedef struct {
    const char *desc;
    _test_rng_data_source rng_data;
    const char *algorithm;
    _mongocrypt_buffer_t *user_key_id;
    _mongocrypt_buffer_t *index_key_id;
    mc_optional_int64_t contention_factor;
    mongocrypt_binary_t *range_opts;
    const char *query_type;
    mongocrypt_binary_t *msg;
    mongocrypt_binary_t *keys_to_feed[3]; // NULL terminated list.
    mongocrypt_binary_t *expect;
    const char *expect_finalize_error;
    const char *expect_init_error;
    bool is_expression;
} ee_testcase;

static void ee_testcase_run(ee_testcase *tc) {
    TEST_PRINTF("  explicit_encryption_finalize test case: %s ... begin\n", tc->desc);
    extern void mc_reset_payloadId_for_testing(void);
    mc_reset_payloadId_for_testing();
    mongocrypt_t *crypt;
    if (tc->rng_data.buf.len > 0) {
        // Use fixed data for random number generation to produce deterministic
        // results.
        crypt = _crypt_with_rng(&tc->rng_data);
    } else {
        tester_mongocrypt_flags flags = TESTER_MONGOCRYPT_DEFAULT;
        crypt = _mongocrypt_tester_mongocrypt(flags);
    }
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    if (tc->algorithm) {
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, tc->algorithm, -1), ctx);
    }
    if (tc->user_key_id) {
        ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, _mongocrypt_buffer_as_binary(tc->user_key_id)), ctx);
    }
    if (tc->index_key_id) {
        ASSERT_OK(mongocrypt_ctx_setopt_index_key_id(ctx, _mongocrypt_buffer_as_binary(tc->index_key_id)), ctx);
    }
    if (tc->contention_factor.set) {
        ASSERT_OK(mongocrypt_ctx_setopt_contention_factor(ctx, tc->contention_factor.value), ctx);
    }
    if (tc->range_opts) {
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm_range(ctx, tc->range_opts), ctx);
    }
    if (tc->query_type) {
        ASSERT_OK(mongocrypt_ctx_setopt_query_type(ctx, tc->query_type, -1), ctx);
    }
    BSON_ASSERT(tc->msg);
    {
        bool ret;
        if (tc->is_expression) {
            ret = mongocrypt_ctx_explicit_encrypt_expression_init(ctx, tc->msg);
        } else {
            ret = mongocrypt_ctx_explicit_encrypt_init(ctx, tc->msg);
        }
        if (tc->expect_init_error) {
            ASSERT_FAILS(ret, ctx, tc->expect_init_error);
            goto cleanup;
        } else {
            ASSERT_OK(ret, ctx);
        }
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        for (size_t i = 0; i < sizeof(tc->keys_to_feed) / sizeof(tc->keys_to_feed[0]); i++) {
            mongocrypt_binary_t *key_to_feed = tc->keys_to_feed[i];
            if (!key_to_feed) {
                break;
            }
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, key_to_feed), ctx);
        }
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *got = mongocrypt_binary_new();

        bool ret = mongocrypt_ctx_finalize(ctx, got);
        if (tc->expect_finalize_error) {
            ASSERT_FAILS(ret, ctx, tc->expect_finalize_error);
        } else {
            ASSERT_OK(ret, ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(tc->expect, got);
        }
        mongocrypt_binary_destroy(got);
    }

cleanup:
    TEST_PRINTF("  explicit_encryption_finalize test case: %s ... end\n", tc->desc);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

// Test the finalized output of explicit encryption.
static void _test_encrypt_fle2_explicit(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t keyABC_id;
    _mongocrypt_buffer_t key123_id;

    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    _mongocrypt_buffer_copy_from_hex(&keyABC_id, "ABCDEFAB123498761234123456789012");
    _mongocrypt_buffer_copy_from_hex(&key123_id, "12345678123498761234123456789012");

    mongocrypt_binary_t *keyABC = TEST_FILE("./test/data/keys/"
                                            "ABCDEFAB123498761234123456789012-local-"
                                            "document.json");
    mongocrypt_binary_t *key123 = TEST_FILE("./test/data/keys/"
                                            "12345678123498761234123456789012-local-"
                                            "document.json");

    {
        ee_testcase tc = {0};
        tc.desc = "Unindexed (v2)";
#define RNG_DATA "\x4d\x06\x95\x64\xf5\xa0\x5e\x9e\x35\x23\xb9\x8f\x57\x5a\xcb\x15"
        uint8_t rng_data[] = RNG_DATA;
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_UNINDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.msg = TEST_BSON("{'v': 'value123'}");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_BSON("{'v' : {'$binary' : {'base64': "
                              "'EKvN76sSNJh2EjQSNFZ4kBICTQaVZPWgXp41I7mPV1rLFVl3jjP90PgD4T+Mtubn/"
                              "mm4CKsKGaV1yxlic9Dty1Adef4Y+bsLGKhBbCa5eojM/A==','subType' : '06'}}}");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "Indexed (v2)";
#define RNG_DATA                                                                                                       \
    "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9"                                                 \
    "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"
        uint8_t rng_data[] = RNG_DATA;
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.msg = TEST_BSON("{'v': 'value123'}");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-explicit/insert-indexed-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "Indexed with non-zero ContentionFactor. Random number chosen is 0 (v2)";
/* First 8 bytes are for random ContentionFactor.
 * Second 16 bytes are IV for 'p' field in FLE2InsertUpdatePayload
 * Third 16 bytes are IV for 'v' field in FLE2InsertUpdatePayload
 */
#define RNG_DATA                                                                                                       \
    "\x00\x00\x00\x00\x00\x00\x00\x00"                                                                                 \
    "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9"                                                 \
    "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"
        uint8_t rng_data[] = RNG_DATA;
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.msg = TEST_BSON("{'v': 'value123'}");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-explicit/insert-indexed-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "Indexed with non-zero ContentionFactor. Random number chosen is 1 (v2)";
/* First 8 bytes are for random ContentionFactor.
 * Second 16 bytes are IV for 'p' field in FLE2InsertUpdatePayload
 * Third 16 bytes are IV for 'v' field in FLE2InsertUpdatePayload
 */
#define RNG_DATA                                                                                                       \
    "\x01\x00\x00\x00\x00\x00\x00\x00"                                                                                 \
    "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9"                                                 \
    "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"
        uint8_t rng_data[] = RNG_DATA;
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.msg = TEST_BSON("{'v': 'value123'}");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-explicit/"
                              "insert-indexed-contentionFactor1-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "omitted index_key_id defaults to using user_key_id (v2)";
#define RNG_DATA                                                                                                       \
    "\xc7\x43\xd6\x75\x76\x9e\xa7\x88\xd5\xe5\xc4\x40\xdb\x24\x0d\xf9"                                                 \
    "\x4c\xd9\x64\x10\x43\x81\xe6\x61\xfa\x1f\xa0\x5c\x49\x8e\xad\x21"
        uint8_t rng_data[] = RNG_DATA;
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data, .len = sizeof(rng_data) - 1u}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.msg = TEST_BSON("{'v': 'value123'}");
        tc.keys_to_feed[0] = keyABC;
        tc.expect = TEST_FILE("./test/data/fle2-explicit/"
                              "insert-indexed-same-user-and-index-key-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Indexed' with query type (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_EQUALITY_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.msg = TEST_BSON("{'v': 123456}");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-explicit/find-indexed-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Indexed' with query type and non-zero contention factor (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_EQUALITY_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.msg = TEST_BSON("{'v': 123456}");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-explicit/find-indexed-contentionFactor1-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "Negative contention factor is an error on insert (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(-1);
        tc.msg = TEST_BSON("{'v': 123456}");
        tc.expect_init_error = "contention must be non-negative";
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "INT64_MAX contention factor is an error on insert (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_INDEXED_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(INT64_MAX);
        tc.msg = TEST_BSON("{'v': 123456}");
        tc.expect_init_error = "contention must be < INT64_MAX";
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with int32 (v2)";
#include "./data/fle2-insert-range-explicit/int32/RNG_DATA.h"
        tc.rng_data = (_test_rng_data_source){.buf = {.data = (uint8_t *)RNG_DATA, .len = sizeof(RNG_DATA) - 1}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_FILE("./test/data/fle2-insert-range-explicit/"
                                  "int32/rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-insert-range-explicit/int32/"
                           "value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-insert-range-explicit/int32/"
                              "encrypted-payload-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with sparsity=2 with int32 (v2)";
#include "./data/fle2-insert-range-explicit/sparsity-2/RNG_DATA.h"
        tc.rng_data = (_test_rng_data_source){.buf = {.data = (uint8_t *)RNG_DATA, .len = sizeof(RNG_DATA) - 1}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_FILE("./test/data/fle2-insert-range-explicit/"
                                  "sparsity-2/rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-insert-range-explicit/sparsity-2/"
                           "value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-insert-range-explicit/sparsity-2/"
                              "encrypted-payload-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with query_type='range' with int32 (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(4);
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.range_opts = TEST_FILE("./test/data/fle2-find-range-explicit/"
                                  "int32/rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-find-range-explicit/int32/"
                           "value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.expect = TEST_FILE("./test/data/fle2-find-range-explicit/int32/"
                              "encrypted-payload-v2.json");
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "An unsupported range BSON type is an error (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON("{'min': 0, 'max': 1, 'sparsity': {'$numberLong': '1'}}");
        tc.msg = TEST_BSON("{'v': 'abc'}");
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "expected matching 'min' and value type";
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with query_type='range' with double with "
                  "precision (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.range_opts = TEST_FILE("./test/data/fle2-find-range-explicit/double-precision/"
                                  "rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-find-range-explicit/"
                           "double-precision/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-find-range-explicit/"
                              "double-precision/encrypted-payload-v2.json");
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with double precision with precision (v2)";
#include "./data/fle2-insert-range-explicit/double-precision/RNG_DATA.h"
        tc.rng_data = (_test_rng_data_source){.buf = {.data = (uint8_t *)RNG_DATA, .len = sizeof(RNG_DATA) - 1}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_FILE("./test/data/fle2-insert-range-explicit/double-precision/"
                                  "rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-insert-range-explicit/"
                           "double-precision/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-insert-range-explicit/double-precision/"
                              "encrypted-payload-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with query_type='range' with double without "
                  "precision (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.range_opts = TEST_FILE("./test/data/fle2-find-range-explicit/double/"
                                  "rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-find-range-explicit/double/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-find-range-explicit/double/encrypted-payload-v2.json");
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "algorithm='Range' with double without precision (v2)";
#include "./data/fle2-insert-range-explicit/double/RNG_DATA.h"
        tc.rng_data = (_test_rng_data_source){.buf = {.data = (uint8_t *)RNG_DATA, .len = sizeof(RNG_DATA) - 1}};
#undef RNG_DATA
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.index_key_id = &key123_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_FILE("./test/data/fle2-insert-range-explicit/double/"
                                  "rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-insert-range-explicit/double/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.keys_to_feed[1] = key123;
        tc.expect = TEST_FILE("./test/data/fle2-insert-range-explicit/double/"
                              "encrypted-payload-v2.json");
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "min > max for insert (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON("{'min': 1, 'max': 0, 'sparsity': {'$numberLong': '1'}}");
        tc.msg = TEST_FILE("./test/data/fle2-insert-range-explicit/int32/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "minimum value must be less than the maximum value";
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "min > max for find (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON("{'min': 25, 'max': 24, 'sparsity': {'$numberLong': '1'}}");
        tc.msg = TEST_FILE("./test/data/fle2-find-range-explicit/int32/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "minimum value must be less than the maximum value";
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "open interval (v2)";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_FILE("./test/data/fle2-find-range-explicit/"
                                  "int32-openinterval/rangeopts.json");
        tc.msg = TEST_FILE("./test/data/fle2-find-range-explicit/"
                           "int32-openinterval/value-to-encrypt.json");
        tc.keys_to_feed[0] = keyABC;
        tc.expect = TEST_FILE("./test/data/fle2-find-range-explicit/"
                              "int32-openinterval/encrypted-payload-v2.json");
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

#define RAW_STRING(...) #__VA_ARGS__

    {
        ee_testcase tc = {0};
        tc.desc = "min is required to insert int for range";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON(RAW_STRING({"max" : {"$numberInt" : "200"}, "sparsity" : {"$numberLong" : "1"}}));
        tc.msg = TEST_BSON(RAW_STRING({"v" : {"$numberInt" : "1"}}));
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "Range option 'min' is required";
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "max is required to insert int for range";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON(RAW_STRING({"min" : {"$numberInt" : "0"}, "sparsity" : {"$numberLong" : "1"}}));
        tc.msg = TEST_BSON(RAW_STRING({"v" : {"$numberInt" : "1"}}));
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "Range option 'max' is required";
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "min is required to find int for range";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON(RAW_STRING({"max" : {"$numberInt" : "200"}, "sparsity" : {"$numberLong" : "1"}}));
        tc.msg = TEST_BSON(RAW_STRING({
            "v" : {"$and" :
                       [ {"age" : {"$gte" : {"$numberInt" : "23"}}}, {"age" : {"$lte" : {"$numberInt" : "35"}}} ]}
        }));
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "Range option 'min' is required";
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

    {
        ee_testcase tc = {0};
        tc.desc = "max is required to find int for range";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.user_key_id = &keyABC_id;
        tc.contention_factor = OPT_I64(0);
        tc.range_opts = TEST_BSON(RAW_STRING({"min" : {"$numberInt" : "0"}, "sparsity" : {"$numberLong" : "1"}}));
        tc.msg = TEST_BSON(RAW_STRING({
            "v" : {"$and" :
                       [ {"age" : {"$gte" : {"$numberInt" : "23"}}}, {"age" : {"$lte" : {"$numberInt" : "35"}}} ]}
        }));
        tc.keys_to_feed[0] = keyABC;
        tc.expect_finalize_error = "Range option 'max' is required";
        tc.is_expression = true;
        ee_testcase_run(&tc);
    }

    _mongocrypt_buffer_cleanup(&keyABC_id);
    _mongocrypt_buffer_cleanup(&key123_id);
}

static void _test_encrypt_applies_default_state_collections(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    /* Defaults are applied */
    {
        crypt = mongocrypt_new();
        ASSERT_OK(
            mongocrypt_setopt_kms_providers(crypt,
                                            TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
            crypt);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BSON("{'db.coll': {'fields': []}}")), crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'find': 'coll'}")), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            const char *expect_schema = "{ 'fields': [], 'escCollection': "
                                        "'enxcol_.coll.esc', 'ecocCollection': "
                                        "'enxcol_.coll.ecoc' }";
            mongocrypt_binary_t *cmd_to_mongocryptd;

            cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                                                          "'schema': { 'db.coll':  %s }}}",
                                                          expect_schema),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
    /* Defaults do not override. */
    {
        crypt = mongocrypt_new();
        ASSERT_OK(
            mongocrypt_setopt_kms_providers(crypt,
                                            TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
            crypt);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                      crypt,
                      TEST_BSON("{'db.coll': { 'fields': [], 'escCollection': 'esc', 'ecocCollection': 'ecoc'}}")),
                  crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'find': 'coll'}")), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            const char *expect_schema = "{'fields': [], 'escCollection': 'esc', 'ecocCollection': 'ecoc' }";
            mongocrypt_binary_t *cmd_to_mongocryptd;

            cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                                                          "'schema': { 'db.coll':  %s }}}",
                                                          expect_schema),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
    /* Test with some defaults. */
    {
        crypt = mongocrypt_new();
        ASSERT_OK(
            mongocrypt_setopt_kms_providers(crypt,
                                            TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
            crypt);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt,
                                                               TEST_BSON("{'fields': [], 'db.coll': {'escCollection': "
                                                                         "'esc', 'fields': []}}")),
                  crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'find': 'coll'}")), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            const char *expect_schema =
                "{'escCollection': 'esc', 'fields': [], 'ecocCollection': 'enxcol_.coll.ecoc' }";
            mongocrypt_binary_t *cmd_to_mongocryptd;

            cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'find': 'coll', 'encryptionInformation': { 'type': 1, "
                                                          "'schema': { 'db.coll': %s }}}",
                                                          expect_schema),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

/* Test encrypting an empty 'delete' command without values to be encrypted.
 * Expect deleteTokens to not be applied. */
static void _test_encrypt_fle2_delete_v2(_mongocrypt_tester_t *tester) {
    tester_mongocrypt_flags flags = TESTER_MONGOCRYPT_DEFAULT;

    /* Test success. */
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(flags);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-delete/success/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-delete/success/collinfo.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            ASSERT_OK(
                mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-delete/success/mongocryptd-reply.json")),
                ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "ABCDEFAB123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "12345678123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-delete/success/encrypted-payload-v2.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
    /* Test with no encrypted values. */
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(flags);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-delete/empty/cmd.json")), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-delete/empty/collinfo.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-delete/empty/mongocryptd-reply.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        /* We do not need delete tokens in v2 so we skip need keys state. */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-delete/empty/encrypted-payload-v2.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    /* Test that deleteTokens are not appended when bypassQueryAnalysis is true in v2. */
    {
        mongocrypt_t *crypt = mongocrypt_new();
        /* Configure crypt. */
        {
            char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
            mongocrypt_binary_t *localkey;
            localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
            ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
            mongocrypt_binary_destroy(localkey);
            mongocrypt_setopt_bypass_query_analysis(crypt);
            ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        }

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-delete/empty/cmd.json")), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-delete/empty/collinfo.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        /* We do not need delete tokens in v2 so we skip need keys state. */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-delete/empty/encrypted-payload-v2.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    /* Test that deleteTokens are not appended when using an
     * encrypted_field_config_map in v2. */
    {
        mongocrypt_t *crypt = mongocrypt_new();
        /* Configure crypt. */
        {
            char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
            mongocrypt_binary_t *localkey;
            localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
            ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
            mongocrypt_binary_destroy(localkey);
            ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt,
                                                                   TEST_FILE("./test/data/fle2-delete/success/"
                                                                             "encrypted-field-config-map.json")),
                      crypt);
            ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        }

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-delete/success/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            ASSERT_OK(
                mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-delete/success/mongocryptd-reply.json")),
                ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "ABCDEFAB123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "12345678123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-delete/success/encrypted-payload-v2.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    /* Test that deleteTokens are not appended when using an
     * encrypted_field_config_map and bypass_query_analysis in v2. */
    {
        mongocrypt_t *crypt = mongocrypt_new();
        /* Configure crypt. */
        {
            char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
            mongocrypt_binary_t *localkey;
            localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
            ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
            mongocrypt_binary_destroy(localkey);
            ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt,
                                                                   TEST_FILE("./test/data/fle2-delete/empty/"
                                                                             "encrypted-field-config-map.json")),
                      crypt);
            mongocrypt_setopt_bypass_query_analysis(crypt);
            ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
        }

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-delete/empty/cmd.json")), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-delete/empty/encrypted-payload-v2.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void _test_encrypt_fle2_delete(_mongocrypt_tester_t *tester) {
    _test_encrypt_fle2_delete_v2(tester);
}

/* Test behavior introduced in MONGOCRYPT-423: "encryptionInformation" is
 * omitted when no values are encrypted for eligible commands.*/
static void _test_encrypt_fle2_omits_encryptionInformation(_mongocrypt_tester_t *tester) {
    /* 'find' does not include 'encryptionInformation' if no fields are
     * encrypted. */
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx;

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'find': 'coll'}")), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_BSON("{'name': 'coll', 'options': "
                                                          "{'encryptedFields': {'fields': []}}}")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        /* Check that command to mongocryptd includes "encryptionInformation". */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/find-with-encryptionInformation.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *cmd_to_mongod;

            cmd_to_mongod = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, cmd_to_mongod), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'find': 'coll'}"), cmd_to_mongod);
            mongocrypt_binary_destroy(cmd_to_mongod);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    /* 'find' includes encryptionInformation if the initial command includes an
     * explicitly encrypted payload. */
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx;

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-find-explicit/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_BSON("{'name': 'coll', 'options': "
                                                          "{'encryptedFields': {'fields': []}}}")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        /* Check that command to mongocryptd includes "encryptionInformation". */
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *cmd_to_mongod;

            cmd_to_mongod = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, cmd_to_mongod), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-find-explicit/cmd-to-mongod.json"),
                                                cmd_to_mongod);
            mongocrypt_binary_destroy(cmd_to_mongod);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void _test_encrypt_fle2_explain_with_mongocryptd(_mongocrypt_tester_t *tester) {
    /* Test with an encrypted value. Otherwise 'encryptionInformation' is not
     * appended. */
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(
            mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-explain/with-mongocryptd/cmd.json")),
            ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(
                mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-explain/with-mongocryptd/collinfo.json")),
                ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-explain/with-mongocryptd/"
                                                          "cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);

            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/fle2-explain/with-mongocryptd/"
                                                          "mongocryptd-reply.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "ABCDEFAB123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "12345678123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-explain/with-mongocryptd/"
                                                          "encrypted-payload.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void _test_encrypt_fle2_explain_with_csfle(_mongocrypt_tester_t *tester) {
    if (!TEST_MONGOCRYPT_HAVE_REAL_CRYPT_SHARED_LIB) {
        TEST_STDERR_PRINTF("No 'real' csfle library is available. The %s test is a no-op.\n", BSON_FUNC);
        return;
    }

    /* Test with an encrypted value. Otherwise 'encryptionInformation' is not
     * appended. */
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_WITH_CRYPT_SHARED_LIB);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-explain/with-csfle/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-explain/with-csfle/collinfo.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/keys/"
                                                          "12345678123498761234123456789012-local-document.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-explain/with-csfle/"
                                                          "encrypted-payload.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void _test_encrypt_fle1_explain_with_mongocryptd(_mongocrypt_tester_t *tester) {
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(
            mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-explain/with-mongocryptd/cmd.json")),
            ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(
                mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle1-explain/with-mongocryptd/collinfo.json")),
                ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-explain/with-mongocryptd/"
                                                          "cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);

            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                                TEST_FILE("./test/data/fle1-explain/with-mongocryptd/"
                                                          "mongocryptd-reply.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-explain/with-mongocryptd/"
                                                          "encrypted-payload.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void _test_encrypt_fle1_explain_with_csfle(_mongocrypt_tester_t *tester) {
    if (!TEST_MONGOCRYPT_HAVE_REAL_CRYPT_SHARED_LIB) {
        TEST_STDERR_PRINTF("No 'real' csfle library is available. The %s test is a no-op.\n", BSON_FUNC);
        return;
    }

    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_WITH_CRYPT_SHARED_LIB);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-explain/with-csfle/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle1-explain/with-csfle/collinfo.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-explain/with-csfle/"
                                                          "encrypted-payload.json"),
                                                out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

// Test that an input command with $db preserves $db in the output.
static void _test_dollardb_preserved(_mongocrypt_tester_t *tester) {
    /* Test with an encrypted value. */
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/dollardb/preserved/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/dollardb/preserved/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/preserved/"
                                                      "cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);

        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/dollardb/preserved/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/preserved/"
                                                      "encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

// Test that an input command with $db preserves $db in the output, when no
// values are encrypted.
static void _test_dollardb_preserved_empty(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/dollardb/preserved_empty/cmd.json")),
              ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/dollardb/preserved_empty/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/preserved_empty/"
                                                      "cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);

        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/dollardb/preserved_empty/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/preserved_empty/"
                                                      "encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

// Test that an input command with no $db does not include $db in the output.
static void _test_dollardb_omitted(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/dollardb/omitted/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/dollardb/omitted/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/omitted/"
                                                      "cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);

        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/dollardb/omitted/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/omitted/"
                                                      "encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

// Test that an input command with $db does includes $db in the output for FLE1.
static void _test_dollardb_preserved_fle1(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/dollardb/preserved_fle1/cmd.json")),
              ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/dollardb/preserved_fle1/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/preserved_fle1/"
                                                      "cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);

        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/dollardb/preserved_fle1/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/dollardb/preserved_fle1/"
                                                      "encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

#define expect_mongo_op(ctx, expect)                                                                                   \
    if (1) {                                                                                                           \
        mongocrypt_binary_t *got = mongocrypt_binary_new();                                                            \
        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, got), ctx);                                                             \
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON((expect), got);                                                            \
        mongocrypt_binary_destroy(got);                                                                                \
    } else                                                                                                             \
        ((void)0)

#define expect_and_reply_to_ismaster(ctx)                                                                              \
    if (1) {                                                                                                           \
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);                             \
        expect_mongo_op(ctx, TEST_BSON("{'isMaster': 1}"));                                                            \
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-ismaster-26.json")), ctx);         \
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);                                                                \
    } else                                                                                                             \
        ((void)0)

static void _test_fle1_create_without_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-create/without-schema/cmd.json")),
              ctx);

    expect_and_reply_to_ismaster(ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/without-schema/cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/fle1-create/without-schema/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/without-schema/encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Test encrypting a "create" command with a schema from the schema map. */
static void _test_fle1_create_with_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();

    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_FILE("./test/data/fle1-create/with-schema/schema-map.json")),
              crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-create/with-schema/cmd.json")),
              ctx);

    expect_and_reply_to_ismaster(ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/with-schema/cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/fle1-create/with-schema/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/with-schema/encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Test encrypting a "create" command with a schema included in the "create"
 * command. This is a regression test for MONGOCRYPT-436. */
static void _test_fle1_create_with_cmd_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-create/with-cmd-schema/cmd.json")),
              ctx);

    expect_and_reply_to_ismaster(ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(
            TEST_FILE("./test/data/fle1-create/with-cmd-schema/cmd-to-mongocryptd.json"),
            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/fle1-create/with-cmd-schema/"
                                                      "mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/with-cmd-schema/encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* Test encrypting the "create" command with mongocryptd version < 6.0.0.
 * Expect the "create" command not to be sent to mongocryptd. */
static void _test_fle1_create_old_mongocryptd(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-create/old-mongocryptd/cmd.json")),
              ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/old-mongocryptd/"
                                                      "ismaster-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/fle1-create/old-mongocryptd/"
                                                      "mongocryptd-ismaster.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/old-mongocryptd/encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_fle1_create_with_csfle(_mongocrypt_tester_t *tester) {
    if (!TEST_MONGOCRYPT_HAVE_REAL_CRYPT_SHARED_LIB) {
        TEST_STDERR_PRINTF("No 'real' csfle library is available. The %s test is a no-op.\n", BSON_FUNC);
        return;
    }

    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_WITH_CRYPT_SHARED_LIB);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-create/with-schema/cmd.json")),
              ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-create/with-schema/encrypted-payload.json"),
                                            out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void test_successful_fle2_create(_mongocrypt_tester_t *tester,
                                        const char *efc_map_path,
                                        const char *cmd_path,
                                        const char *cmd_to_cryptd_path,
                                        const char *cryptd_reply_path,
                                        const char *encrypted_payload_path) {
    mongocrypt_t *crypt = mongocrypt_new();

    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_FILE(efc_map_path)), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE(cmd_path)), ctx);

    expect_and_reply_to_ismaster(ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE(cmd_to_cryptd_path), cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE(cryptd_reply_path)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE(encrypted_payload_path), out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

#define TEST_SUCCESSFUL_FLE2_CREATE(efc_path, cmd_path, cryptd_path, payload_path)                                     \
    test_successful_fle2_create(tester,                                                                                \
                                "./test/data/" efc_path "/encrypted-field-config-map.json",                            \
                                "./test/data/" cmd_path "/cmd.json",                                                   \
                                "./test/data/" cryptd_path "/cmd-to-mongocryptd.json",                                 \
                                "./test/data/" cryptd_path "/mongocryptd-reply.json",                                  \
                                "./test/data/" payload_path "/encrypted-payload.json")

#define TEST_SUCCESSFUL_FLE2_CREATE_ONEDIR(path) TEST_SUCCESSFUL_FLE2_CREATE(path, path, path, path)

static void _test_fle2_create(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE_ONEDIR("fle2-create");
}

static void _test_fle2_create_with_encrypted_fields(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE_ONEDIR("fle2-create-encrypted-collection");
}

static void _test_fle2_create_with_encrypted_fields_and_str_encode_version(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE_ONEDIR("fle2-create-encrypted-collection-with-str-encode-version");
}

static void _test_fle2_create_with_encrypted_fields_unset_str_encode_version(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE("fle2-create-encrypted-collection-with-str-encode-version",
                                "fle2-create-encrypted-collection",
                                "fle2-create-encrypted-collection-encrypted-fields-unset-str-encode-version",
                                "fle2-create-encrypted-collection-with-str-encode-version");
}

static void _test_fle2_text_search_create_with_encrypted_fields(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE_ONEDIR("fle2-text-search-create-encrypted-collection");
}

static void _test_fle2_text_search_create_with_encrypted_fields_and_str_encode_version(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE_ONEDIR("fle2-text-search-create-encrypted-collection-with-str-encode-version");
}

static void _test_fle2_text_search_create_with_encrypted_fields_unset_str_encode_version(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE("fle2-text-search-create-encrypted-collection-with-str-encode-version",
                                "fle2-text-search-create-encrypted-collection",
                                "fle2-text-search-create-encrypted-collection",
                                "fle2-text-search-create-encrypted-collection-with-str-encode-version");
}

static void
_test_fle2_text_search_create_with_encrypted_fields_unmatching_str_encode_version(_mongocrypt_tester_t *tester) {
    TEST_SUCCESSFUL_FLE2_CREATE("fle2-text-search-create-encrypted-collection",
                                "fle2-text-search-create-encrypted-collection-with-str-encode-version",
                                "fle2-text-search-create-encrypted-collection-with-str-encode-version",
                                "fle2-text-search-create-encrypted-collection-with-str-encode-version");
}

// Test that the JSON Schema found from a "create" command is not cached.
static void _test_fle2_create_does_not_cache_empty_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    // Auto encrypt a "create" to "db.coll".
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-create/cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);

        // Expect MONGOCRYPT_CTX_NEED_MONGO_COLLINFO is skipped since no server-side schema is expected for "create".
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        mongocrypt_ctx_destroy(ctx);
    }

    // Auto encrypt "find" to "db.coll". Expect server-side schema is requested.
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON(BSON_STR({"find" : "coll", "filter" : {}}))),
                  ctx);
        // The MONGOCRYPT_CTX_NEED_COLLINFO state is entered to request a server-side schema.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        mongocrypt_ctx_destroy(ctx);
    }

    mongocrypt_destroy(crypt);
}

/* Regression test for MONGOCRYPT-435 */
static void _test_fle2_create_bypass_query_analysis(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();

    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                  crypt,
                  TEST_FILE("./test/data/fle2-create/encrypted-field-config-map.json")),
              crypt);
    mongocrypt_setopt_bypass_query_analysis(crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-create/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle2-create/cmd.json"), out);
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

// Test the error message returned on macOS versions that do not support AES-CTR
// mode. This tests behavior changed in MONGOCRYPT-440.
static void _test_encrypt_macos_no_ctr(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t key_id;

    if (_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with CTR support detected. Skipping.");
        return;
    }

    _mongocrypt_buffer_copy_from_hex(&key_id, "ABCDEFAB123498761234123456789012");

    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_UNINDEXED_STR, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, _mongocrypt_buffer_as_binary(&key_id)), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON("{'v': 'value123'}")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-local-"
                                                      "document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *got = mongocrypt_binary_new();

        ASSERT_FAILS(mongocrypt_ctx_finalize(ctx, got), ctx, "CTR mode is only supported on macOS 10.15+");
        mongocrypt_binary_destroy(got);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* If collMod contains a $jsonSchema, expect the same $jsonSchema to be used in
 * the command to mongocryptd. This is a regression test for MONGOCRYPT-463. */
static void _test_fle1_collmod_with_jsonSchema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle1-collMod/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/fle1-collMod/cmd-to-mongocryptd.json"),
                                            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle1-collMod/mongocryptd-reply.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

/* If collMod does not contain a $jsonSchema, expect a schema to be requested.
 */
static void _test_fle1_collmod_without_jsonSchema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON("{'collMod': 'encryptedCollection'}")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

#define BSON_STR(...) #__VA_ARGS__

static void _test_bulkWrite(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Required by QEv2 encryption. Skipping.");
        return;
    }

    // local_kek is the KEK used to encrypt the keyMaterial in ./test/data/key-document-local.json
    uint8_t local_kek_raw[MONGOCRYPT_KEY_LEN] = {0};
    char *local_kek = kms_message_raw_to_b64(local_kek_raw, sizeof(local_kek_raw));

    // Test initializing bulkWrite commands.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_setopt_use_need_mongo_collinfo_with_db_state(crypt);
        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                      crypt,
                      TEST_FILE("./test/data/bulkWrite/simple/encrypted-field-map.json")),
                  crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        // Successful case.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            mongocrypt_binary_t *cmd = TEST_BSON(BSON_STR({"bulkWrite" : 1, "nsInfo" : [ {"ns" : "db.coll"} ]}));
            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, cmd), ctx);
            mongocrypt_ctx_destroy(ctx);
        }

        // No `nsInfo`.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            mongocrypt_binary_t *cmd = TEST_BSON(BSON_STR({"bulkWrite" : 1}));
            ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, cmd), ctx, "failed to find namespace");
            mongocrypt_ctx_destroy(ctx);
        }

        // `nsInfo` is not an array.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            mongocrypt_binary_t *cmd = TEST_BSON(BSON_STR({"bulkWrite" : 1, "nsInfo" : {"foo" : "bar"}}));
            ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, cmd), ctx, "failed to find namespace");
            mongocrypt_ctx_destroy(ctx);
        }

        // `nsInfo.ns` is not correct form.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            mongocrypt_binary_t *cmd = TEST_BSON(BSON_STR({"bulkWrite" : 1, "nsInfo" : [ {"ns" : "invalid"} ]}));
            ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, cmd), ctx, "expected namespace to contain dot");
            mongocrypt_ctx_destroy(ctx);
        }

        // `nsInfo` is empty.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            mongocrypt_binary_t *cmd = TEST_BSON(BSON_STR({"bulkWrite" : 1, "nsInfo" : []}));
            ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, cmd), ctx, "failed to find namespace");
            mongocrypt_ctx_destroy(ctx);
        }

        // `nsInfo` has more than one entry.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            mongocrypt_binary_t *cmd =
                TEST_BSON(BSON_STR({"bulkWrite" : 1, "nsInfo" : [ {"ns" : "db.coll"}, {"ns" : "db.coll2"} ]}));
            ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, cmd), ctx, "found more than one");
            mongocrypt_ctx_destroy(ctx);
        }

        mongocrypt_destroy(crypt);
    }

    // Test a bulkWrite with one namespace.
    {
        mongocrypt_t *crypt = mongocrypt_new();

        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                      crypt,
                      TEST_FILE("./test/data/bulkWrite/simple/encrypted-field-map.json")),
                  crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/simple/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/bulkWrite/simple/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/bulkWrite/simple/mongocryptd-reply.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-local.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);

            // Match results.
            bson_t out_bson;
            ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
            mongocrypt_binary_t *pattern = TEST_FILE("./test/data/bulkWrite/simple/encrypted-payload-pattern.json");
            bson_t pattern_bson;
            ASSERT(_mongocrypt_binary_to_bson(pattern, &pattern_bson));
            _assert_match_bson(&out_bson, &pattern_bson);

            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test a bulkWrite with remote encryptedFields.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_setopt_use_need_mongo_collinfo_with_db_state(crypt);

        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/simple/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB);
        {
            // Ensure the requested database is obtained from `nsInfo` (and not "admin").
            const char *db = mongocrypt_ctx_mongo_db(ctx);
            ASSERT_OK(db, ctx);
            ASSERT_STREQUAL(db, "db");

            {
                mongocrypt_binary_t *cmd = mongocrypt_binary_new();
                ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd), ctx);
                bson_t cmd_bson;
                ASSERT(_mongocrypt_binary_to_bson(cmd, &cmd_bson));
                _assert_match_bson(&cmd_bson, TMP_BSON(BSON_STR({"name" : "test"})));
                mongocrypt_binary_destroy(cmd);
            }
            // Feed back response.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/bulkWrite/simple/collinfo.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/bulkWrite/simple/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/bulkWrite/simple/mongocryptd-reply.json")),
                      ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-local.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);

            // Match results.
            bson_t out_bson;
            ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
            mongocrypt_binary_t *pattern = TEST_FILE("./test/data/bulkWrite/simple/encrypted-payload-pattern.json");
            bson_t pattern_bson;
            ASSERT(_mongocrypt_binary_to_bson(pattern, &pattern_bson));
            _assert_match_bson(&out_bson, &pattern_bson);

            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test a bulkWrite with remote schema when MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB is not supported.
    {
        mongocrypt_t *crypt = mongocrypt_new();

        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_FAILS(
            mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/simple/cmd.json")),
            ctx,
            "Fetching remote collection information on separate databases is not supported. Try upgrading driver, or "
            "specify a local schemaMap or encryptedFieldsMap.");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test a bulkWrite to an unencrypted collection.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        // Opt-in to handling required state for fetching remote encryptedFields with `bulkWrite`.
        mongocrypt_setopt_use_need_mongo_collinfo_with_db_state(crypt);

        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(
            mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/unencrypted/cmd.json")),
            ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB);
        {
            // Do not feed any response.
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/bulkWrite/unencrypted/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(
                mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/bulkWrite/unencrypted/mongocryptd-reply.json")),
                ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);

            // `expect` excludes `encryptionInformation`.
            mongocrypt_binary_t *expect = TEST_FILE("./test/data/bulkWrite/unencrypted/payload.json");
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, out);

            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);

        // Test again to ensure the cached collinfo produces same result.
        ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(
            mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/unencrypted/cmd.json")),
            ctx);

        // MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB state is not entered. collinfo is loaded from cache.

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/bulkWrite/unencrypted/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);
            ASSERT_OK(
                mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/bulkWrite/unencrypted/mongocryptd-reply.json")),
                ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);

            // `expect` excludes `encryptionInformation`.
            mongocrypt_binary_t *expect = TEST_FILE("./test/data/bulkWrite/unencrypted/payload.json");
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, out);

            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test a bulkWrite with bypassQueryAnalysis. Expect `encryptionInformation` is added, but query analysis is not
    // consulted.
    {
        mongocrypt_t *crypt = mongocrypt_new();

        mongocrypt_setopt_bypass_query_analysis(crypt);

        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                      crypt,
                      TEST_FILE("./test/data/bulkWrite/simple/encrypted-field-map.json")),
                  crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/simple/cmd.json")),
                  ctx);

        // Query analysis is not consulted. Immediately transitions to MONGOCRYPT_CTX_READY.

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);

            // `expect` excludes `encryptionInformation`.
            mongocrypt_binary_t *expect = TEST_FILE("./test/data/bulkWrite/bypassQueryAnalysis/payload.json");
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, out);
            mongocrypt_binary_destroy(out);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test a bulkWrite with CSFLE (not supported by server)
    {
        mongocrypt_t *crypt = mongocrypt_new();

        mongocrypt_setopt_kms_providers(
            crypt,
            TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek));

        // Associate a JSON schema to the collection to enable CSFLE.
        ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_BSON(BSON_STR({"db.test" : {}}))), crypt);
        ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "admin", -1, TEST_FILE("./test/data/bulkWrite/simple/cmd.json")),
                  ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

            ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/bulkWrite/jsonSchema/cmd-to-mongocryptd.json"),
                                                cmd_to_mongocryptd);
            mongocrypt_binary_destroy(cmd_to_mongocryptd);

            // End the test here. At present, an error query analysis returns this error for `bulkWrite` with a
            // `jsonSchema`: `The bulkWrite command only supports Queryable Encryption`.
            // libmongocrypt deliberately does not error to enable possible future server support of CSFLE
            // with bulkWrite without libmongocrypt changes.
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    bson_free(local_kek);
}

// `_test_rangePreview_fails` tests that use of "rangePreview" errors.
static void _test_rangePreview_fails(_mongocrypt_tester_t *tester) {
    // local_kek is the KEK used to encrypt the keyMaterial in ./test/data/key-document-local.json
    uint8_t local_kek_raw[MONGOCRYPT_KEY_LEN] = {0};
    char *local_kek = kms_message_raw_to_b64(local_kek_raw, sizeof(local_kek_raw));
    mongocrypt_binary_t *kms_providers =
        TEST_BSON(BSON_STR({"local" : {"key" : {"$binary" : {"base64" : "%s", "subType" : "00"}}}}), local_kek);

    // Test setting 'rangePreview' as an explicit encryption algorithm results in error.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(ctx, crypt);
        ASSERT_FAILS(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_RANGEPREVIEW_DEPRECATED_STR, -1),
                     ctx,
                     "Algorithm 'rangePreview' is deprecated");
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test setting 'rangePreview' as an explicit encryption queryType results in error.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(ctx, crypt);
        ASSERT_FAILS(mongocrypt_ctx_setopt_query_type(ctx, MONGOCRYPT_QUERY_TYPE_RANGEPREVIEW_DEPRECATED_STR, -1),
                     ctx,
                     "Query type 'rangePreview' is deprecated");
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test setting 'rangePreview' from encryptedFields results in error.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                      crypt,
                      TEST_FILE("./test/data/fle2-insert-range/int32/encrypted-field-map.json")), // Uses 'rangePreview'
                  crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(ctx, crypt);
        ASSERT_FAILS(
            mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-insert-range/int32/cmd.json")),
            ctx,
            "Cannot use field 'encrypted' with 'rangePreview' queries");
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    bson_free(local_kek);
}

// `autoencryption_test` defines a test for the automatic encryption context.
typedef struct {
    const char *desc;
    _test_rng_data_source rng_data;
    mongocrypt_binary_t *cmd;
    mongocrypt_binary_t *encrypted_field_map;
    mongocrypt_binary_t *mongocryptd_reply;
    mongocrypt_binary_t *keys_to_feed[3]; // NULL terminated list.
    mongocrypt_binary_t *expect;
} autoencryption_test;

static void autoencryption_test_run(autoencryption_test *aet) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    TEST_PRINTF("  auto_encryption test: '%s' ... begin\n", aet->desc);

    // Reset global counter for the `payloadId` to produce deterministic payloads.
    extern void mc_reset_payloadId_for_testing(void);
    mc_reset_payloadId_for_testing();

    // Initialize mongocrypt_t.
    mongocrypt_t *crypt = mongocrypt_new();
    {
        mongocrypt_setopt_log_handler(crypt, _mongocrypt_stdout_log_fn, NULL);

        // Set "local" KMS provider.
        {
            // `localkey_data` is the KEK used to encrypt the keyMaterial in ./test/data/keys/
            char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
            mongocrypt_binary_t *localkey =
                mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
            ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, localkey), crypt);
            mongocrypt_binary_destroy(localkey);
        }

        if (aet->rng_data.buf.len > 0) {
            // Set deterministic random number generator.
            ASSERT_OK(mongocrypt_setopt_crypto_hooks(crypt,
                                                     _std_hook_native_crypto_aes_256_cbc_encrypt,
                                                     _std_hook_native_crypto_aes_256_cbc_decrypt,
                                                     _test_rng_source,
                                                     _std_hook_native_hmac_sha512,
                                                     _std_hook_native_hmac_sha256,
                                                     _error_hook_native_sha256,
                                                     &aet->rng_data /* ctx */),
                      crypt);
        }

        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, aet->encrypted_field_map), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
    }

    // Create the auto encryption context and run.
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, aet->cmd), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, aet->mongocryptd_reply), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        for (mongocrypt_binary_t **iter = aet->keys_to_feed; *iter != NULL; iter++) {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, *iter), ctx);
        }
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *got = mongocrypt_binary_new();

        bool ret = mongocrypt_ctx_finalize(ctx, got);
        ASSERT_OK(ret, ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(aet->expect, got);
        mongocrypt_binary_destroy(got);
    }

    TEST_PRINTF("  auto_encryption test: '%s' ... end\n", aet->desc);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_no_trimFactor(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    mongocrypt_binary_t *key123 = TEST_FILE("./test/data/keys/12345678123498761234123456789012-local-document.json");

    // Test insert.
    {
        autoencryption_test aet = {
            .desc = "missing trimFactor in mongocryptd reply for `insert` is OK",
            .cmd = TEST_FILE("test/data/no-trimFactor/insert/cmd.json"),
            .encrypted_field_map = TEST_FILE("test/data/no-trimFactor/insert/encrypted-field-map.json"),
            .mongocryptd_reply = TEST_FILE("test/data/no-trimFactor/insert/mongocryptd-reply.json"),
            .keys_to_feed = {key123},
            .expect = TEST_FILE("test/data/no-trimFactor/insert/encrypted-payload.json"),
        };

        // Set fixed random data for deterministic results.
        mongocrypt_binary_t *rng_data = TEST_BIN(1024);
        aet.rng_data = (_test_rng_data_source){.buf = {.data = rng_data->data, .len = rng_data->len}};

        autoencryption_test_run(&aet);
    }

    // Test find.
    {
        autoencryption_test aet = {
            .desc = "missing trimFactor in mongocryptd reply for `find` is OK",
            .cmd = TEST_FILE("test/data/no-trimFactor/find/cmd.json"),
            .encrypted_field_map = TEST_FILE("test/data/no-trimFactor/find/encrypted-field-map.json"),
            .mongocryptd_reply = TEST_FILE("test/data/no-trimFactor/find/mongocryptd-reply.json"),
            .keys_to_feed = {key123},
            .expect = TEST_FILE("test/data/no-trimFactor/find/encrypted-payload.json"),
        };

        // Set fixed random data for deterministic results.
        mongocrypt_binary_t *rng_data = TEST_BIN(1024);
        aet.rng_data = (_test_rng_data_source){.buf = {.data = rng_data->data, .len = rng_data->len}};

        autoencryption_test_run(&aet);
    }
}

// `lookup_payload_bson` looks up a payload from the BSON document `result` at path `path`.
// The BSON portion of the payload is parsed into `payload_bson`.
static void lookup_payload_bson(mongocrypt_binary_t *result, char *path, bson_t *payload_bson) {
    bson_t result_bson;
    ASSERT(_mongocrypt_binary_to_bson(result, &result_bson));

    // Iterate to the path.
    bson_iter_t iter;
    ASSERT(bson_iter_init(&iter, &result_bson));
    if (!bson_iter_find_descendant(&iter, path, &iter)) {
        TEST_ERROR("Unable to find path '%s'. Got: %s", path, tmp_json(&result_bson));
    }

    _mongocrypt_buffer_t buf;
    ASSERT(_mongocrypt_buffer_from_binary_iter(&buf, &iter));
    ASSERT_CMPINT((int)buf.subtype, ==, (int)BSON_SUBTYPE_ENCRYPTED);

    // Expect a payload to start with an identifier byte. Expect the remainder to be BSON.
    ASSERT_CMPUINT32(buf.len, >, 0);
    ASSERT(bson_init_static(payload_bson, buf.data + 1, buf.len - 1));
}

// Test that the crypto params added in SERVER-91889 are sent for "range" payloads.
static void _test_range_sends_cryptoParams(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    // Set up key data used for test.
    _mongocrypt_buffer_t key123_id;
    _mongocrypt_buffer_copy_from_hex(&key123_id, "12345678123498761234123456789012");
    mongocrypt_binary_t *key123 = TEST_FILE("./test/data/keys/12345678123498761234123456789012-local-document.json");
    // Use fixed random data for deterministic results.
    mongocrypt_binary_t *rng_data = TEST_BIN(1024);

    // Test explicit insert.
    {
        ee_testcase tc = {0};
        tc.desc = "'range' sends crypto params for insert";
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data->data, .len = rng_data->len}};
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.range_opts = TEST_BSON("{'min': 0, 'max': 1234567, 'sparsity': { '$numberLong': '3' }, 'trimFactor': 4}");
        tc.msg = TEST_BSON("{'v': 123456}");
        tc.keys_to_feed[0] = key123;
        tc.expect = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-insert-int32/expected.json");
        ee_testcase_run(&tc);
        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(tc.expect, "v", &payload_bson);
            _assert_match_bson(
                &payload_bson,
                TMP_BSON(BSON_STR({"sp" : 3, "tf" : 4, "mn" : 0, "mx" : 1234567, "pn" : {"$exists" : false}})));
        }
    }

    // Test explicit insert with defaults.
    {
        ee_testcase tc = {0};
        tc.desc = "'range' sends crypto params for insert with correct defaults";
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data->data, .len = rng_data->len}};
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        // Use defaults for `sparsity` (2), and `trimFactor` (6).
        tc.range_opts = TEST_BSON("{'min': 0, 'max': 1234567}");
        tc.msg = TEST_BSON("{'v': 123456}");
        tc.keys_to_feed[0] = key123;
        tc.expect = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-insert-int32-defaults/expected.json");
        ee_testcase_run(&tc);
        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(tc.expect, "v", &payload_bson);
            _assert_match_bson(
                &payload_bson,
                TMP_BSON(BSON_STR({"sp" : 2, "tf" : 6, "mn" : 0, "mx" : 1234567, "pn" : {"$exists" : false}})));
        }
    }

    // Test explicit insert of double.
    {
        ee_testcase tc = {0};
        tc.desc = "'range' sends crypto params for insert for double";
        mongocrypt_binary_t *rng_data = TEST_BIN(1024);
        tc.rng_data = (_test_rng_data_source){.buf = {.data = rng_data->data, .len = rng_data->len}};
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.user_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.range_opts = TEST_BSON(
            "{'min': 0.0, 'max': 1234567.0, 'precision': 2, 'sparsity': { '$numberLong': '3' }, 'trimFactor': 4}");
        tc.msg = TEST_BSON("{'v': 123456.0}");
        tc.keys_to_feed[0] = key123;
        tc.expect = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-insert-double/expected.json");
        ee_testcase_run(&tc);
        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(tc.expect, "v", &payload_bson);
            _assert_match_bson(&payload_bson,
                               TMP_BSON(BSON_STR({"sp" : 3, "tf" : 4, "mn" : 0.0, "mx" : 1234567.0, "pn" : 2})));
        }
    }

    // Test explicit find.
    {
        ee_testcase tc = {0};
        tc.desc = "'range' sends crypto params for find with correct defaults";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.is_expression = true;
        tc.user_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.range_opts =
            TEST_BSON("{'min': 0, 'max': 1234567}"); // Use defaults for `sparsity` (2), and `trimFactor` (6).
        tc.msg = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-find-int32-defaults/to-encrypt.json");
        tc.keys_to_feed[0] = key123;
        tc.expect = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-find-int32-defaults/expected.json");
        ee_testcase_run(&tc);
        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(tc.expect, "v.$and.0.age.$gte", &payload_bson);
            _assert_match_bson(
                &payload_bson,
                TMP_BSON(BSON_STR({"sp" : 2, "tf" : 6, "mn" : 0, "mx" : 1234567, "pn" : {"$exists" : false}})));
        }
    }

    // Test explicit find with defaults.
    {
        ee_testcase tc = {0};
        tc.desc = "'range' sends crypto params for find";
        tc.algorithm = MONGOCRYPT_ALGORITHM_RANGE_STR;
        tc.query_type = MONGOCRYPT_QUERY_TYPE_RANGE_STR;
        tc.is_expression = true;
        tc.user_key_id = &key123_id;
        tc.contention_factor = OPT_I64(1);
        tc.range_opts = TEST_BSON("{'min': 0, 'max': 1234567, 'sparsity': { '$numberLong': '3' }, 'trimFactor': 4}");
        tc.msg = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-find-int32/to-encrypt.json");
        tc.keys_to_feed[0] = key123;
        tc.expect = TEST_FILE("./test/data/range-sends-cryptoParams/explicit-find-int32/expected.json");
        ee_testcase_run(&tc);
        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(tc.expect, "v.$and.0.age.$gte", &payload_bson);
            _assert_match_bson(
                &payload_bson,
                TMP_BSON(BSON_STR({"sp" : 3, "tf" : 4, "mn" : 0, "mx" : 1234567, "pn" : {"$exists" : false}})));
        }
    }

    // Test automatic insert of int32.
    {
        autoencryption_test aet = {
            .desc = "'range' sends crypto params for insert",
            .rng_data = {.buf = {.data = rng_data->data, .len = rng_data->len}},
            .cmd = TEST_FILE("./test/data/range-sends-cryptoParams/auto-insert-int32/cmd.json"),
            .encrypted_field_map =
                TEST_FILE("./test/data/range-sends-cryptoParams/auto-insert-int32/encrypted-field-map.json"),
            .mongocryptd_reply =
                TEST_FILE("./test/data/range-sends-cryptoParams/auto-insert-int32/mongocryptd-reply.json"),
            .keys_to_feed = {key123},
            .expect = TEST_FILE("./test/data/range-sends-cryptoParams/auto-insert-int32/encrypted-payload.json")};

        autoencryption_test_run(&aet);

        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(aet.expect, "documents.0.encrypted", &payload_bson);
            _assert_match_bson(
                &payload_bson,
                TMP_BSON(
                    BSON_STR({"sp" : 2, "tf" : 6, "mn" : -2147483648, "mx" : 2147483647, "pn" : {"$exists" : false}})));
        }
    }

    // Test automatic find of int32.
    {
        autoencryption_test aet = {
            .desc = "'range' sends crypto params for find",
            .cmd = TEST_FILE("./test/data/range-sends-cryptoParams/auto-find-int32/cmd.json"),
            .encrypted_field_map =
                TEST_FILE("./test/data/range-sends-cryptoParams/auto-find-int32/encrypted-field-map.json"),
            .mongocryptd_reply =
                TEST_FILE("./test/data/range-sends-cryptoParams/auto-find-int32/mongocryptd-reply.json"),
            .keys_to_feed = {key123},
            .expect = TEST_FILE("./test/data/range-sends-cryptoParams/auto-find-int32/encrypted-payload.json")};

        autoencryption_test_run(&aet);

        // Check the parameters are present in the final payload.
        {
            bson_t payload_bson;
            lookup_payload_bson(aet.expect, "filter.$and.0.encrypted.$gte", &payload_bson);
            _assert_match_bson(
                &payload_bson,
                TMP_BSON(
                    BSON_STR({"sp" : 2, "tf" : 6, "mn" : -2147483648, "mx" : 2147483647, "pn" : {"$exists" : false}})));
        }
    }

    _mongocrypt_buffer_cleanup(&key123_id);
}

typedef struct _responses {
    const char *key_document;
    const char *oauth_response;
    const char *decrypt_response;
} _responses;

static void _test_encrypt_retry_provider(_responses r, _mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    // Create context.
    {
        // Use explicit encryption to simplify (no schema needed).
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "keyDocumentName"}))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
        ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
    }

    // Feed key.
    {
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE(r.key_document)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    // Needs KMS for oauth token.
    {
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx);
        // Feed a retryable HTTP error.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/rmd/kms-decrypt-reply-429.txt")), kctx);
        // Expect KMS request is returned again for a retry.
        kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OK(kctx, ctx);
        ASSERT_CMPINT64(mongocrypt_kms_ctx_usleep(kctx), >, 0);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE(r.oauth_response)), kctx);
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    // Needs KMS to decrypt DEK.
    {
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx);
        // Feed a retryable HTTP error.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/rmd/kms-decrypt-reply-429.txt")), kctx);
        // Expect KMS request is returned again for a retry.
        kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OK(kctx, ctx);
        ASSERT_CMPINT64(mongocrypt_kms_ctx_usleep(kctx), >, 0);
        // Feed a successful response.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE(r.decrypt_response)), kctx);
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    mongocrypt_binary_t *bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_retry(_mongocrypt_tester_t *tester) {
    // Test that an HTTP error is retried with AWS
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
        _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OK(kms_ctx, ctx);
        // Expect no sleep is requested before any error.
        ASSERT_CMPINT64(mongocrypt_kms_ctx_usleep(kms_ctx), ==, 0);
        // Feed a retryable HTTP error.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx, TEST_FILE("./test/data/rmd/kms-decrypt-reply-429.txt")), kms_ctx);
        // Expect KMS request is returned again for a retry.
        kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OK(kms_ctx, ctx);
        // Feed a successful response.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx, TEST_FILE("./test/data/kms-aws/decrypt-response.txt")), kms_ctx);
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
    // Azure
    {
        _responses r = {
            "./test/data/key-document-azure.json",
            "./test/data/kms-azure/oauth-response.txt",
            "./test/data/kms-azure/decrypt-response.txt",
        };
        _test_encrypt_retry_provider(r, tester);
    }
    // GCP
    {
        _responses r = {
            "./test/data/key-document-gcp.json",
            "./test/data/kms-gcp/oauth-response.txt",
            "./test/data/kms-gcp/decrypt-response.txt",
        };
        _test_encrypt_retry_provider(r, tester);
    }
    // Multiple keys
    {
        // Create crypt with retry enabled.
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(
                      crypt,
                      TEST_BSON(BSON_STR({"aws" : {"accessKeyId" : "foo", "secretAccessKey" : "bar"}}))),
                  crypt);
        ASSERT_OK(mongocrypt_setopt_retry_kms(crypt, true), crypt);
        ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_FILE("./test/data/multikey/schema_map.json")), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Encrypt a command requiring two keys.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/multikey/command.json")), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/multikey/mongocryptd_reply.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/multikey/key-document-a.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/multikey/key-document-b.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Expect two keys are needed. Obtain both.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kctx1 = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx1);
        mongocrypt_kms_ctx_t *kctx2 = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx2);

        // Feed a successful response to the first.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx1, TEST_FILE("./test/data/kms-aws/decrypt-response.txt")), kctx1);

        // Feed a retryable error response to the second.
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx2, TEST_FILE("./test/data/rmd/kms-decrypt-reply-429.txt")), kctx2);

        // Expect the retried KMS context is returned again.
        mongocrypt_kms_ctx_t *kctx_retry = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx_retry);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kctx_retry, TEST_FILE("./test/data/kms-aws/decrypt-response.txt")),
                  kctx_retry);

        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_DONE);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
    // Test retry does not occur if not enabled.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(
                      crypt,
                      TEST_BSON(BSON_STR({"aws" : {"accessKeyId" : "foo", "secretAccessKey" : "bar"}}))),
                  crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
        _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OK(kms_ctx, ctx); // Give a retryable HTTP error. Expect error due to retry disabled.
        ASSERT_FAILS(mongocrypt_kms_ctx_feed(kms_ctx, TEST_FILE("./test/data/rmd/kms-decrypt-reply-429.txt")),
                     kms_ctx,
                     "Error in KMS response");
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test network retry does not occur if not enabled.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(
                      crypt,
                      TEST_BSON(BSON_STR({"aws" : {"accessKeyId" : "foo", "secretAccessKey" : "bar"}}))),
                  crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
        _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OK(kms_ctx, ctx); // Give a retryable network error. Expect error due to retry disabled.
        ASSERT_FAILS(mongocrypt_kms_ctx_fail(kms_ctx), kms_ctx, "KMS request failed due to network error");
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void capture_logs(mongocrypt_log_level_t level, const char *message, uint32_t message_len, void *ctx) {
    mc_array_t *log_msgs = ctx;
    char *message_copy = bson_strdup(message);
    _mc_array_append_val(log_msgs, message_copy);
}

// Regression test for: MONGOCRYPT-770
static void _test_does_not_warn_for_empty_local_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(
                  crypt,
                  TEST_BSON(BSON_STR({"aws" : {"accessKeyId" : "foo", "secretAccessKey" : "bar"}}))),
              crypt);

    mc_array_t log_msgs; // Array of char *;
    _mc_array_init(&log_msgs, sizeof(char *));
    ASSERT_OK(mongocrypt_setopt_log_handler(crypt, capture_logs, &log_msgs), crypt);

    // Configure a local schema for "db.coll":
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_BSON(BSON_STR({"db.coll" : {}}))), crypt);

    ASSERT_OK(mongocrypt_init(crypt), crypt);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_BSON(BSON_STR({"find" : "coll", "filter" : {}}))), ctx);
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);

    // Feed mongocryptd reply indicating `schemaRequiresEncryption: false`.
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_BSON(BSON_STR({
                                            "hasEncryptionPlaceholders" : false,
                                            "schemaRequiresEncryption" : false,
                                            "result" : {"find" : "test", "filter" : {}},
                                            "ok" : {"$numberDouble" : "1.0"}
                                        }))),
              ctx);

    // Expect no warning (passing an empty local schema is a valid use-case).
    if (log_msgs.len > 0) {
        TEST_STDERR_PRINTF("Got unexpected log messages:\n");
        for (size_t i = 0; i < log_msgs.len; i++) {
            TEST_STDERR_PRINTF("> %s\n", _mc_array_index(&log_msgs, char *, i));
        }
        abort();
    }

    for (size_t i = 0; i < log_msgs.len; i++) {
        bson_free(_mc_array_index(&log_msgs, char *, i));
    }
    _mc_array_destroy(&log_msgs);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_fle2_encrypted_field_config_with_bad_str_encode_version(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();

    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                  crypt,
                  TEST_FILE("./test/data/fle2-bad-str-encode-version/bad-encrypted-field-config-map.json")),
              crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-insert-v2/cmd.json")),
                 ctx,
                 "'strEncodeVersion' of 99 is not supported");

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_fle2_encrypted_fields_with_unmatching_str_encode_version(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();

    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt,
                                                           TEST_FILE("./test/data/fle2-create-encrypted-collection/"
                                                                     "encrypted-field-config-map.json")),
              crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(
                  ctx,
                  "db",
                  -1,
                  TEST_FILE("./test/data/fle2-create-encrypted-collection-with-str-encode-version/cmd.json")),
              ctx);

    expect_and_reply_to_ismaster(ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
    {
        mongocrypt_binary_t *cmd_to_mongocryptd = mongocrypt_binary_new();

        ASSERT_OK(mongocrypt_ctx_mongo_op(ctx, cmd_to_mongocryptd), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(
            TEST_FILE("./test/data/fle2-bad-str-encode-version/bad-create-cmd-to-mongocryptd.json"),
            cmd_to_mongocryptd);
        mongocrypt_binary_destroy(cmd_to_mongocryptd);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(
                      ctx,
                      TEST_FILE("./test/data/fle2-bad-str-encode-version/bad-create-cmd-mongocryptd-reply.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_FAILS(mongocrypt_ctx_finalize(ctx, out),
                     ctx,
                     "'strEncodeVersion' of 1 does not match efc->str_encode_version of 0");
        mongocrypt_binary_destroy(out);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_fle2_collinfo_with_bad_str_encode_version(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/fle2-insert-v2/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/fle2-bad-str-encode-version/bad-collinfo.json")),
                 ctx,
                 "'strEncodeVersion' of 99 is not supported");

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_lookup(_mongocrypt_tester_t *tester) {
    // Test $lookup works.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        expect_and_reply_to_ismaster(ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup errors if multiple-collection support is not opted-in.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        crypt->multiple_collinfo_enabled = false;
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_FAILS(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")),
                     ctx,
                     "not configured to support encrypting a command with multiple collections");
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup errors if mongocryptd is too old.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TEST_BSON("{'isMaster': 1}"));
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/mongocryptd-ismaster-17.json")), ctx);
            ASSERT_FAILS(mongocrypt_ctx_mongo_done(ctx), ctx, "Upgrade mongocryptd");
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test nested $lookup.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-nested/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        expect_and_reply_to_ismaster(ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2", "c3" ]}})));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup within $unionWith.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-unionWith/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        expect_and_reply_to_ismaster(ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2", "c3" ]}})));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup within $facet.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-facet/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        expect_and_reply_to_ismaster(ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup when one schema is in the schemaMap.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-schemaMap/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_SKIP_INIT);
        ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TF("schemaMap.json")), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        expect_and_reply_to_ismaster(ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c1"})));
            // Feed remote schema for "c1". "c2" is found in the schemaMap.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup with a self-lookup.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-self/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c1"})));
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup when one schema is already cached.
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

        // Do a self-lookup to add only "c1" to the cache.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-self/" suffix)
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
            {
                expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c1"})));
                ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
                ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
            }
            mongocrypt_ctx_destroy(ctx);
        }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
        // Expect "c1" schema is not requested again.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
            expect_and_reply_to_ismaster(ctx);
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
            {
                expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c2"})));
                // Feed remaining needed schema.
                ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
                ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));

            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

#undef TF

    // Test $lookup caches no collinfo results as empty schemas.
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

        // Do a self-lookup to add only "c1" to the cache.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
            expect_and_reply_to_ismaster(ctx);
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
            // Feed no collinfo results. Expect "c1" and "c2" to be cached as empty schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
            mongocrypt_ctx_destroy(ctx);
        }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
        // Expect "c1" schema is not requested again.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
            expect_and_reply_to_ismaster(ctx);
            // Expect no more schemas are needed (both empty).
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }
#undef TF
// Test $lookup from a view.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-view/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "v1" ]}})));

            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-v1.json")), ctx, "cannot auto encrypt a view");
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF
// Test $lookup with feeding the same schema twice.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            // Feed schema for "c2" twice.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx, "unexpected duplicate");
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with with feeding a non-matching schema.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-mismatch/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c3.json")), ctx, "got unexpected collinfo");
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with only local schemas.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-only-schemaMap/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_SKIP_INIT);
        ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TF("schemaMap.json")), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup from a collection that has no $jsonSchema configured.
#define TF(suffix) TEST_FILE("./test/data/lookup/csfle-sibling/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("reply-from-mongocryptd.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with QE.
#define TF(suffix) TEST_FILE("./test/data/lookup/qe/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            // Expect no `encryptionInformation` since no encryption payloads.
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with QE with an encrypted payload.
#define TF(suffix) TEST_FILE("./test/data/lookup/qe-with-payload/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            // Expect `encryptionInformation` since command has encryption payloads.
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with QE from encryptedFieldsMap.
#define TF(suffix) TEST_FILE("./test/data/lookup/qe-encryptedFieldsMap/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_SKIP_INIT);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TF("encryptedFieldsMap.json")), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c1"})));
            // Only feed collinfo for c1. c2 is included in encryptedFieldsMap.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with QE with self-lookup.
#define TF(suffix) TEST_FILE("./test/data/lookup/qe-self/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c1"})));
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

    // Test $lookup with QE from from cache.
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

        // Do a self-lookup to add only "c1" to the cache.
#define TF(suffix) TEST_FILE("./test/data/lookup/qe-self/" suffix)
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
            {
                expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c1"})));
                ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
                ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
            }
            mongocrypt_ctx_destroy(ctx);
        }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/qe-with-payload/" suffix)
        // Expect "c1" schema is not requested again.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

            ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
            expect_and_reply_to_ismaster(ctx);
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
            {
                expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : "c2"})));
                // Feed remaining needed schema.
                ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
                ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));

            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

#undef TF

// Test $lookup with mixed: QE + CSFLE
#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/qe/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));

            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_FAILS(mongocrypt_ctx_mongo_op(ctx, got), ctx, "currently not supported");
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with mixed: QE + no-schema
#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/qe/no-schema/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with mixed: QE + QE
#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/qe/qe/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

// Test $lookup with mixed: CSFLE + CSFLE.
#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/csfle/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/csfle/qe/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_FAILS(mongocrypt_ctx_mongo_op(ctx, got), ctx, "This is currently not supported");
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/csfle/no-schema/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/no-schema/csfle/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/no-schema/no-schema/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF

#define TF(suffix) TEST_FILE("./test/data/lookup/mixed/no-schema/qe/" suffix)
    {
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

        ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TF("cmd.json")), ctx);
        expect_and_reply_to_ismaster(ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
        {
            expect_mongo_op(ctx, TEST_BSON(BSON_STR({"name" : {"$in" : [ "c1", "c2" ]}})));
            // Feed both needed schemas.
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c1.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TF("collInfo-c2.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
        {
            expect_mongo_op(ctx, TF("cmd-to-mongocryptd.json"));
            mongocrypt_binary_t *to_feed = TF("reply-from-mongocryptd.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            mongocrypt_binary_t *to_feed = TF("key-doc.json");
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, to_feed), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *expect = TF("cmd-to-mongod.json");
            mongocrypt_binary_t *got = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, got), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expect, got);
            mongocrypt_binary_destroy(got);
        }
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
#undef TF
}

void _mongocrypt_tester_install_ctx_encrypt(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_explicit_encrypt_init);
    INSTALL_TEST(_test_encrypt_init);
    INSTALL_TEST(_test_encrypt_need_collinfo);
    INSTALL_TEST(_test_encrypt_need_markings);
    INSTALL_TEST(_test_encrypt_csfle_no_needs_markings);
    INSTALL_TEST(_test_encrypt_need_keys);
    INSTALL_TEST(_test_encrypt_ready);
    INSTALL_TEST(_test_key_missing_region);
    INSTALL_TEST(_test_view);
    INSTALL_TEST(_test_local_schema);
    INSTALL_TEST(_test_encrypt_caches_collinfo);
    INSTALL_TEST(_test_encrypt_caches_keys);
    INSTALL_TEST(_test_encrypt_cache_expiration);
    INSTALL_TEST(_test_encrypt_caches_keys_by_alt_name);
    INSTALL_TEST(_test_encrypt_random);
    INSTALL_TEST(_test_encrypt_is_remote_schema);
    INSTALL_TEST(_test_encrypt_init_each_cmd);
    INSTALL_TEST(_test_encrypt_invalid_siblings);
    INSTALL_TEST(_test_encrypting_with_explicit_encryption);
    INSTALL_TEST(_test_explicit_encryption);
    INSTALL_TEST(_test_encrypt_empty_aws);
    INSTALL_TEST(_test_encrypt_custom_endpoint);
    INSTALL_TEST(_test_encrypt_with_aws_session_token);
    INSTALL_TEST(_test_encrypt_caches_empty_collinfo);
    INSTALL_TEST(_test_encrypt_caches_collinfo_without_jsonschema);
    INSTALL_TEST(_test_encrypt_per_ctx_credentials);
    INSTALL_TEST(_test_encrypt_per_ctx_credentials_given_empty);
    INSTALL_TEST(_test_encrypt_per_ctx_credentials_local);
    INSTALL_TEST(_test_encrypt_with_encrypted_field_config_map);
    INSTALL_TEST(_test_encrypt_with_encrypted_field_config_map_bypassed);
    INSTALL_TEST(_test_encrypt_no_schema);
    INSTALL_TEST(_test_encrypt_remote_encryptedfields);
    INSTALL_TEST(_test_encrypt_with_bypassqueryanalysis);
    INSTALL_TEST(_test_encrypt_fle2_insert_payload);
    INSTALL_TEST(_test_encrypt_fle2_insert_payload_with_str_encode_version);
    INSTALL_TEST(_test_encrypt_fle2_find_payload);
    INSTALL_TEST(_test_encrypt_fle2_unindexed_encrypted_payload);
    INSTALL_TEST(_test_encrypt_fle2_explicit);
    INSTALL_TEST(_test_encrypt_applies_default_state_collections);
    INSTALL_TEST(_test_encrypt_fle2_delete);
    INSTALL_TEST(_test_encrypt_fle2_omits_encryptionInformation);
    INSTALL_TEST(_test_encrypt_fle2_explain_with_mongocryptd);
    INSTALL_TEST(_test_encrypt_fle2_explain_with_csfle);
    INSTALL_TEST(_test_encrypt_fle1_explain_with_mongocryptd);
    INSTALL_TEST(_test_encrypt_fle1_explain_with_csfle);
    INSTALL_TEST(_test_dollardb_preserved);
    INSTALL_TEST(_test_dollardb_preserved_empty);
    INSTALL_TEST(_test_dollardb_omitted);
    INSTALL_TEST(_test_dollardb_preserved_fle1);
    INSTALL_TEST(_test_fle1_create_without_schema);
    INSTALL_TEST(_test_fle1_create_with_schema);
    INSTALL_TEST(_test_fle1_create_with_cmd_schema);
    INSTALL_TEST(_test_fle1_create_old_mongocryptd);
    INSTALL_TEST(_test_fle1_create_with_csfle);
    INSTALL_TEST(_test_fle2_create);
    INSTALL_TEST(_test_fle2_create_with_encrypted_fields);
    INSTALL_TEST(_test_fle2_create_with_encrypted_fields_and_str_encode_version);
    INSTALL_TEST(_test_fle2_create_with_encrypted_fields_unset_str_encode_version);
    INSTALL_TEST(_test_fle2_text_search_create_with_encrypted_fields);
    INSTALL_TEST(_test_fle2_text_search_create_with_encrypted_fields_and_str_encode_version);
    INSTALL_TEST(_test_fle2_text_search_create_with_encrypted_fields_unset_str_encode_version);
    INSTALL_TEST(_test_fle2_text_search_create_with_encrypted_fields_unmatching_str_encode_version);
    INSTALL_TEST(_test_fle2_create_does_not_cache_empty_schema);
    INSTALL_TEST(_test_fle2_create_bypass_query_analysis);
    INSTALL_TEST(_test_encrypt_macos_no_ctr);
    INSTALL_TEST(_test_fle1_collmod_with_jsonSchema);
    INSTALL_TEST(_test_fle1_collmod_without_jsonSchema);
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_int32);
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_int64);
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_date);
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_double);
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_double_precision);
#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT()
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_decimal128);
    INSTALL_TEST(_test_encrypt_fle2_insert_range_payload_decimal128_precision);
#endif
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_int32);
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_int64);
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_date);
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_double);
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_double_precision);
#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT()
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_decimal128);
    INSTALL_TEST(_test_encrypt_fle2_find_range_payload_decimal128_precision);
#endif
    INSTALL_TEST(_test_encrypt_fle2_insert_text_search_payload);
    INSTALL_TEST(_test_encrypt_fle2_insert_text_search_payload_with_str_encode_version);
    INSTALL_TEST(_test_bulkWrite);
    INSTALL_TEST(_test_rangePreview_fails);
    INSTALL_TEST(_test_no_trimFactor);
    INSTALL_TEST(_test_range_sends_cryptoParams);
    INSTALL_TEST(_test_encrypt_retry);
    INSTALL_TEST(_test_does_not_warn_for_empty_local_schema);
    INSTALL_TEST(_test_fle2_encrypted_field_config_with_bad_str_encode_version);
    INSTALL_TEST(_test_fle2_encrypted_fields_with_unmatching_str_encode_version);
    INSTALL_TEST(_test_fle2_collinfo_with_bad_str_encode_version);
    INSTALL_TEST(_test_lookup);
}
