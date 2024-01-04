/*
 * Copyright 2022-present MongoDB, Inc.
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

/* Test authentication with the "gcp" KMS provider. */

static void _test_createdatakey_with_credentials(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms;
    const char *kek = "{"
                      "'provider': 'gcp',"
                      "'projectId': 'test-projectId',"
                      "'location': 'test-location',"
                      "'keyRing': 'test-keyRing',"
                      "'keyName': 'test-keyName'"
                      "}";

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(kek)), ctx);
    ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
    /* Assert first CTX_NEED_KMS state requests access token. */
    {
        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(kms, "expected KMS context, got NULL");

        const char *endpoint;
        mongocrypt_kms_ctx_endpoint(kms, &endpoint);
        ASSERT_STREQUAL("oauth2.googleapis.com:443", endpoint);

        /* Satisfy request. */
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kms);
        ASSERT_CMPINT((int)mongocrypt_kms_ctx_bytes_needed(kms), ==, 0);

        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(NULL == kms, "expected NULL KMS context, got non-NULL");
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    /* Assert second CTX_NEED_KMS state requests encryption. */
    {
        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(kms, "expected KMS context, got NULL");

        const char *endpoint;
        mongocrypt_kms_ctx_endpoint(kms, &endpoint);
        ASSERT_STREQUAL("cloudkms.googleapis.com:443", endpoint);

        /* Satisfy request. */
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-gcp/encrypt-response.txt")), kms);
        ASSERT_CMPINT((int)mongocrypt_kms_ctx_bytes_needed(kms), ==, 0);

        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(NULL == kms, "expected NULL KMS context, got non-NULL");
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_with_credentials(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms;
    mongocrypt_binary_t *uuid;
    const char *uuid_data = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61";

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    uuid = mongocrypt_binary_new_from_data((uint8_t *)uuid_data, UUID_LEN);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, uuid), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON("{'v': 1}")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-gcp.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
    /* Assert first CTX_NEED_KMS state requests access token. */
    {
        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(kms, "expected KMS context, got NULL");

        const char *endpoint;
        mongocrypt_kms_ctx_endpoint(kms, &endpoint);
        ASSERT_STREQUAL("oauth2.googleapis.com:443", endpoint);

        /* Satisfy request. */
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kms);
        ASSERT_CMPINT((int)mongocrypt_kms_ctx_bytes_needed(kms), ==, 0);

        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(NULL == kms, "expected NULL KMS context, got non-NULL");
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    /* Assert second CTX_NEED_KMS state requests decryption. */
    {
        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(kms, "expected KMS context, got NULL");

        const char *endpoint;
        mongocrypt_kms_ctx_endpoint(kms, &endpoint);
        ASSERT_STREQUAL("cloudkms.googleapis.com:443", endpoint);

        /* Satisfy request. */
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kms);
        ASSERT_CMPINT((int)mongocrypt_kms_ctx_bytes_needed(kms), ==, 0);

        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(NULL == kms, "expected NULL KMS context, got non-NULL");
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);

    mongocrypt_binary_destroy(uuid);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_createdatakey_with_accesstoken(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms;
    const char *kek = "{"
                      "'provider': 'gcp',"
                      "'projectId': 'test-projectId',"
                      "'location': 'test-location',"
                      "'keyRing': 'test-keyRing',"
                      "'keyName': 'test-keyName'"
                      "}";

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'gcp': {}}")), crypt);
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(kek)), ctx);
    ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
    { ASSERT_OK(mongocrypt_ctx_provide_kms_providers(ctx, TEST_BSON("{'gcp': { 'accessToken': 'foobar' } }")), ctx); }

    /* Assert first CTX_NEED_KMS state requests encryption. */
    {
        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(kms, "expected KMS context, got NULL");

        const char *endpoint;
        mongocrypt_kms_ctx_endpoint(kms, &endpoint);
        ASSERT_STREQUAL("cloudkms.googleapis.com:443", endpoint);

        /* Satisfy request. */
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-gcp/encrypt-response.txt")), kms);
        ASSERT_CMPINT((int)mongocrypt_kms_ctx_bytes_needed(kms), ==, 0);

        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(NULL == kms, "expected NULL KMS context, got non-NULL");
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void _test_encrypt_with_accesstoken(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_kms_ctx_t *kms;
    mongocrypt_binary_t *uuid;
    const char *uuid_data = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61";

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'gcp': {}}")), crypt);
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    ctx = mongocrypt_ctx_new(crypt);
    uuid = mongocrypt_binary_new_from_data((uint8_t *)uuid_data, UUID_LEN);
    ASSERT_OK(mongocrypt_ctx_setopt_key_id(ctx, uuid), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
    ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON("{'v': 1}")), ctx);

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
    { ASSERT_OK(mongocrypt_ctx_provide_kms_providers(ctx, TEST_BSON("{'gcp': { 'accessToken': 'foobar' } }")), ctx); }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    {
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-gcp.json")), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);

    /* Assert first CTX_NEED_KMS state requests decryption. */
    {
        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(kms, "expected KMS context, got NULL");

        const char *endpoint;
        mongocrypt_kms_ctx_endpoint(kms, &endpoint);
        ASSERT_STREQUAL("cloudkms.googleapis.com:443", endpoint);

        /* Satisfy request. */
        ASSERT_OK(mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kms);
        ASSERT_CMPINT((int)mongocrypt_kms_ctx_bytes_needed(kms), ==, 0);

        kms = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT_OR_PRINT_MSG(NULL == kms, "expected NULL KMS context, got non-NULL");
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);

    mongocrypt_binary_destroy(uuid);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_gcp_auth(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_createdatakey_with_credentials);
    INSTALL_TEST(_test_encrypt_with_credentials);
    INSTALL_TEST(_test_createdatakey_with_accesstoken);
    INSTALL_TEST(_test_encrypt_with_accesstoken);
}
