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

#include "mongocrypt-cache-oauth-private.h"
#include "test-mongocrypt.h"

static void _test_cache_oauth_expiration(_mongocrypt_tester_t *tester) {
    mc_mapof_kmsid_to_token_t *cache;
    char *token;
    bool ret;
    mongocrypt_status_t *status;

    cache = mc_mapof_kmsid_to_token_new();
    token = mc_mapof_kmsid_to_token_get_token(cache, "aws");
    BSON_ASSERT(!token);

    status = mongocrypt_status_new();
    ret = mc_mapof_kmsid_to_token_add_response(cache,
                                               "aws",
                                               TMP_BSON("{'expires_in': 0, 'access_token': 'foo'}"),
                                               status);
    ASSERT_OR_PRINT(ret, status);
    /* Does not return expired token. */
    token = mc_mapof_kmsid_to_token_get_token(cache, "aws");
    BSON_ASSERT(!token);

    /* Attempt to get again, to ensure MONGOCRYPT-321 is fixed. */
    token = mc_mapof_kmsid_to_token_get_token(cache, "aws");
    BSON_ASSERT(!token);

    /* Add an unexpired token. */
    ret = mc_mapof_kmsid_to_token_add_response(cache,
                                               "aws",
                                               TMP_BSON("{'expires_in': 1000, 'access_token': 'bar'}"),
                                               status);
    ASSERT_OR_PRINT(ret, status);

    token = mc_mapof_kmsid_to_token_get_token(cache, "aws");
    ASSERT_STREQUAL(token, "bar");
    bson_free(token);

    mc_mapof_kmsid_to_token_destroy(cache);
    mongocrypt_status_destroy(status);
}

#define BSON_STR(...) #__VA_ARGS__

static void test_mc_mapof_kmsid_to_token(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    bson_t *response1 = TMP_BSON(BSON_STR({"access_token" : "foo", "expires_in" : 1234}));
    bson_t *response2 = TMP_BSON(BSON_STR({"access_token" : "bar", "expires_in" : 4567}));

    // Test inserting one entry.
    {
        mc_mapof_kmsid_to_token_t *k2t = mc_mapof_kmsid_to_token_new();
        ASSERT(NULL == mc_mapof_kmsid_to_token_get_token(k2t, "local:1"));
        ASSERT_OK_STATUS(mc_mapof_kmsid_to_token_add_response(k2t, "local:1", response1, status), status);
        char *got = mc_mapof_kmsid_to_token_get_token(k2t, "local:1");
        ASSERT_STREQUAL(got, "foo");
        bson_free(got);
        mc_mapof_kmsid_to_token_destroy(k2t);
    }

    // Test inserting two entries.
    {
        mc_mapof_kmsid_to_token_t *k2t = mc_mapof_kmsid_to_token_new();

        // Insert first.
        {
            ASSERT(NULL == mc_mapof_kmsid_to_token_get_token(k2t, "local:1"));
            ASSERT_OK_STATUS(mc_mapof_kmsid_to_token_add_response(k2t, "local:1", response1, status), status);
            char *got = mc_mapof_kmsid_to_token_get_token(k2t, "local:1");
            ASSERT_STREQUAL(got, "foo");
            bson_free(got);
        }

        // Insert second.
        {
            ASSERT(NULL == mc_mapof_kmsid_to_token_get_token(k2t, "local:2"));
            ASSERT_OK_STATUS(mc_mapof_kmsid_to_token_add_response(k2t, "local:2", response2, status), status);
            char *got = mc_mapof_kmsid_to_token_get_token(k2t, "local:2");
            ASSERT_STREQUAL(got, "bar");
            bson_free(got);
        }

        mc_mapof_kmsid_to_token_destroy(k2t);
    }

    // Test overwriting an entry.
    {
        mc_mapof_kmsid_to_token_t *k2t = mc_mapof_kmsid_to_token_new();

        // Insert first.
        {
            ASSERT(NULL == mc_mapof_kmsid_to_token_get_token(k2t, "local:1"));
            ASSERT_OK_STATUS(mc_mapof_kmsid_to_token_add_response(k2t, "local:1", response1, status), status);
            char *got = mc_mapof_kmsid_to_token_get_token(k2t, "local:1");
            ASSERT_STREQUAL(got, "foo");
            bson_free(got);
        }

        // Overwrite 'local:1' with a different token.
        {
            ASSERT_OK_STATUS(mc_mapof_kmsid_to_token_add_response(k2t, "local:1", response2, status), status);
            char *got = mc_mapof_kmsid_to_token_get_token(k2t, "local:1");
            ASSERT_STREQUAL(got, "bar");
            bson_free(got);
        }

        mc_mapof_kmsid_to_token_destroy(k2t);
    }
    // Test getting a missing entry.
    {
        mc_mapof_kmsid_to_token_t *k2t = mc_mapof_kmsid_to_token_new();
        ASSERT(NULL == mc_mapof_kmsid_to_token_get_token(k2t, "local:1"));
        mc_mapof_kmsid_to_token_destroy(k2t);
    }

    mongocrypt_status_destroy(status);
}

void _mongocrypt_tester_install_cache_oauth(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_cache_oauth_expiration);
    INSTALL_TEST(test_mc_mapof_kmsid_to_token);
}
