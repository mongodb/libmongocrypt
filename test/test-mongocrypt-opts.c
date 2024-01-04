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

#define BSON_STR(...) #__VA_ARGS__

static void test_mongocrypt_opts_kms_providers_lookup(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *bson = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}));

    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, bson), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    mc_kms_creds_t got;
    ASSERT(_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "azure", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_AZURE);

    ASSERT(!_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "local", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_NONE);

    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_opts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mongocrypt_opts_kms_providers_lookup);
}
