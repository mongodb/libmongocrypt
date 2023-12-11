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
        ASSERT_FAILS(ok, crypt, "invalid KMS provider");
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

void _mongocrypt_tester_install_named_kms_providers(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_configuring_named_kms_providers);
}
