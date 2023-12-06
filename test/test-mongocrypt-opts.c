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

static void test_mongocrypt_opts_kms_providers_lookup (_mongocrypt_tester_t *tester) {
    TEST_ERROR ("Not yet implemented");
}

void _mongocrypt_tester_install_opts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mongocrypt_opts_kms_providers_lookup);
}
