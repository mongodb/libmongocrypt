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

#include <mongocrypt-opts-private.h>

#include <test-mongocrypt-assert-match-bson.h>
#include <test-mongocrypt.h>

#define LOCAL_KEK1_BASE64                                                                                              \
    "+ol0TFyLuVvKFSqGzOFGuaOGQnnyfAqalhOv3II/VSxQTCORCGhOmw/IxhthGx0r"                                                 \
    "2R/NpMWc91qQ8Ieho4QuE9ucToTnpJ4OquFpdZv2IcO4gey3ecZGCl9jPDig8F+a"

#define LOCAL_KEK2_BASE64                                                                                              \
    "yPSpsO8FoVkmt+qdTDnw/pJaKriwfI6NLD1yse3BZLd3ZcXb3rAVJEA+/yu/vPzE"                                                 \
    "8ju7OYTV63AwfLor8Hg9qzo8lyYC6H3RSfdJ9g9aXdCRfGZJgpbpchJUjR06JMLR"

#define BSON_STR(...) #__VA_ARGS__

static void test_configuring_named_kms_providers(_mongocrypt_tester_t *tester) {
    // Test that a named KMS provider can be set.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:name1" : {"key" : "%s"}}),
                      LOCAL_KEK1_BASE64,
                      LOCAL_KEK2_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that an unrecognized named KMS provider errors.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"foo:bar" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "unrecognized type");
        mongocrypt_destroy(crypt);
    }

    // Test character validation. Only valid characters are: [a-zA-Z0-9_]
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local:name_with_invalid_character_?" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "unsupported character `?`");
        mongocrypt_destroy(crypt);
    }

    // Test configuring a named KMS provider with an empty document is prohibited.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {}}));
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "expected UTF-8 or binary key");
        mongocrypt_destroy(crypt);

        // An empty document is allowed for a non-named KMS provider to configure on-demand credentials.
        crypt = mongocrypt_new();
        kms_providers = TEST_BSON(BSON_STR({"local" : {}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that duplicate named KMS providers is an error.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}, "local:name1" : {"key" : "%s"}}),
                      LOCAL_KEK1_BASE64,
                      LOCAL_KEK2_BASE64);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt, "duplicate entry");
        mongocrypt_destroy(crypt);
    }

    // Test that a named KMS provider can be set with Azure.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({
                          "local" : {"key" : "%s"},
                          "azure:name1" : {
                              "tenantId" : "placeholder1-tenantId",
                              "clientId" : "placeholder1-clientId",
                              "clientSecret" : "placeholder1-clientSecret",
                              "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
                          }
                      }),
                      LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that only configuring named KMS provider is OK.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }
}

static void test_create_datakey_with_named_kms_provider(_mongocrypt_tester_t *tester) {
    // Test creating with an unconfigured KMS provider.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested kms provider not configured: `local:not_configured`");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating with an unconfigured KMS provider, when provider of same type is configured.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:name1" : {"key" : "%s"}}),
                      LOCAL_KEK1_BASE64,
                      LOCAL_KEK2_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested kms provider not configured: `local:not_configured`");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating with an unconfigured KMS provider, when provider of same type is configured with an
    // empty document.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local" : {}, "local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64, LOCAL_KEK2_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        mongocrypt_setopt_use_need_kms_credentials_state(crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested kms provider required by datakey is not configured: `local:not_configured`");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating a local DEK with a named KMS provider.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:name1"}))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "local:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an Azure DEK with a named KMS provider
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
            "azure:name1" : {
                "tenantId" : "placeholder1-tenantId",
                "clientId" : "placeholder1-clientId",
                "clientSecret" : "placeholder1-clientSecret",
                "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
            }
        }));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:name1",
                                                               "keyName" : "placeholder1-keyName",
                                                               "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an Azure DEK when `accessToken` is passed.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"azure:name1" : {"accessToken" : "foo"}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:name1",
                                                               "keyName" : "placeholder1-keyName",
                                                               "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating two Azure keys with different named providers.
    // This is intended to test that they do not share cache entries.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
            "azure:name1" : {
                "tenantId" : "placeholder1-tenantId",
                "clientId" : "placeholder1-clientId",
                "clientSecret" : "placeholder1-clientSecret",
                "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
            },
            "azure:name2" : {
                "tenantId" : "placeholder2-tenantId",
                "clientId" : "placeholder2-clientId",
                "clientSecret" : "placeholder2-clientSecret",
                "identityPlatformEndpoint" : "placeholder2-identityPlatformEndpoint.com"
            }
        }));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with `azure:name1`.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(
                mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                             "provider" : "azure:name1",
                                                             "keyName" : "placeholder1-keyName",
                                                             "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                                         }))),
                ctx);
            ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to encrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")),
                          kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            // Check that `out` contains name.
            bson_t out_bson;
            ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
            char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name1"}});
            _assert_match_bson(&out_bson, TMP_BSON(pattern));
            bson_destroy(&out_bson);
            mongocrypt_binary_destroy(out);
            mongocrypt_ctx_destroy(ctx);
        }

        // Create with `azure:name2`. Expect a separate oauth token is needed.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(
                mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                             "provider" : "azure:name2",
                                                             "keyName" : "placeholder2-keyName",
                                                             "keyVaultEndpoint" : "placeholder2-keyVaultEndpoint.com"
                                                         }))),
                ctx);
            ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to encrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")),
                          kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            // Check that `out` contains name.
            bson_t out_bson;
            ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
            char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name2"}});
            _assert_match_bson(&out_bson, TMP_BSON(pattern));
            bson_destroy(&out_bson);
            mongocrypt_binary_destroy(out);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }
}

void _mongocrypt_tester_install_named_kms_providers(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_configuring_named_kms_providers);
    INSTALL_TEST(test_create_datakey_with_named_kms_provider);
}
