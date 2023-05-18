/*
 * Copyright 2023-present MongoDB, Inc.
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

static void _test_cleanup_success(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/cleanup/success/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789013-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/cleanup/success/encrypted-payload.json"), out);
        mongocrypt_binary_destroy(out);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_DONE);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_cleanup_nonlocal_kms(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/cleanup/success/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-aws-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-aws-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789013-aws-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
    {
        mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kms_ctx);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx,
                                          TEST_FILE("./test/data/keys/"
                                                    "12345678123498761234123456789013-"
                                                    "aws-decrypt-reply.txt")),
                  kms_ctx);
        kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kms_ctx);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx,
                                          TEST_FILE("./test/data/keys/"
                                                    "ABCDEFAB123498761234123456789012-"
                                                    "aws-decrypt-reply.txt")),
                  kms_ctx);
        kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kms_ctx);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx,
                                          TEST_FILE("./test/data/keys/"
                                                    "12345678123498761234123456789012-"
                                                    "aws-decrypt-reply.txt")),
                  kms_ctx);
        ASSERT(!mongocrypt_ctx_next_kms_ctx(ctx));
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/cleanup/success/encrypted-payload.json"), out);
        mongocrypt_binary_destroy(out);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_DONE);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_cleanup_missing_key_id(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_FAILS(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/cleanup/missing-key-id/collinfo.json")),
                     ctx,
                     "unable to find 'keyId' in 'field' document");
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_cleanup_key_not_provided(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/cleanup/success/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_FAILS(mongocrypt_ctx_mongo_done(ctx), ctx, "not all keys requested were satisfied");
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_cleanup_need_kms_credentials(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = mongocrypt_new();
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {}}")), crypt);
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/cleanup/success/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
    {
        ASSERT_OK(mongocrypt_ctx_provide_kms_providers(ctx,
                                                       TEST_BSON("{'aws': {"
                                                                 "   'accessKeyId': 'example',"
                                                                 "   'secretAccessKey': 'example'}}")),
                  ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-aws-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-aws-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789013-aws-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
    {
        mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kms_ctx);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx,
                                          TEST_FILE("./test/data/keys/"
                                                    "12345678123498761234123456789013-"
                                                    "aws-decrypt-reply.txt")),
                  kms_ctx);
        kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kms_ctx);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx,
                                          TEST_FILE("./test/data/keys/"
                                                    "ABCDEFAB123498761234123456789012-"
                                                    "aws-decrypt-reply.txt")),
                  kms_ctx);
        kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kms_ctx);
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms_ctx,
                                          TEST_FILE("./test/data/keys/"
                                                    "12345678123498761234123456789012-"
                                                    "aws-decrypt-reply.txt")),
                  kms_ctx);
        ASSERT(!mongocrypt_ctx_next_kms_ctx(ctx));
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/cleanup/success/encrypted-payload.json"), out);
        mongocrypt_binary_destroy(out);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_DONE);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_cleanup_no_fields(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/cleanup/no-fields/collinfo.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/cleanup/no-fields/encrypted-payload.json"), out);
        mongocrypt_binary_destroy(out);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_DONE);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_cleanup_from_encrypted_field_config_map(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;

    /* Initialize crypt with encrypted_field_config_map */
    {
        char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
        mongocrypt_binary_t *localkey;

        crypt = mongocrypt_new();
        mongocrypt_setopt_log_handler(crypt, _mongocrypt_stdout_log_fn, NULL);
        localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
        mongocrypt_setopt_kms_provider_local(crypt, localkey);
        mongocrypt_binary_destroy(localkey);
        ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(
                      crypt,
                      TEST_FILE("./test/data/cleanup/success/encrypted-field-config-map.json")),
                  crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
    }
    ctx = mongocrypt_ctx_new(crypt);

    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "db", -1, TEST_FILE("./test/data/cleanup/success/cmd.json")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "ABCDEFAB123498761234123456789012-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx,
                                            TEST_FILE("./test/data/keys/"
                                                      "12345678123498761234123456789013-local-document.json")),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_FILE("./test/data/cleanup/success/encrypted-payload.json"), out);
        mongocrypt_binary_destroy(out);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_DONE);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_cleanup(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_cleanup_success);
    INSTALL_TEST(_test_cleanup_nonlocal_kms);
    INSTALL_TEST(_test_cleanup_missing_key_id);
    INSTALL_TEST(_test_cleanup_key_not_provided);
    INSTALL_TEST(_test_cleanup_need_kms_credentials);
    INSTALL_TEST(_test_cleanup_no_fields);
    INSTALL_TEST(_test_cleanup_from_encrypted_field_config_map);
}
