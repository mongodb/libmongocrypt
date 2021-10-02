/*
 * Copyright 2020-present MongoDB, Inc.
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

#include <bson/bson.h>
#include "test-mongocrypt.h"
#include "test-conveniences.h"
#include "mongocrypt-kek-private.h"

static void _run_one_test (_mongocrypt_tester_t *tester, bson_t *test) {
    bson_iter_t iter;
    bson_t input;
    char *input_str;
    mongocrypt_status_t *status;
    _mongocrypt_kek_t kek;
    const char* expect;
    bool ret;
    bson_t out;

    status = mongocrypt_status_new ();
    memset (&kek, 0, sizeof (_mongocrypt_kek_t));
    BSON_ASSERT (bson_iter_init_find (&iter, test, "input"));
    bson_iter_bson (&iter, &input);
    BSON_ASSERT (bson_iter_init_find (&iter, test, "expect"));
    expect = bson_iter_utf8 (&iter, NULL);

    input_str = bson_as_json (&input, NULL);
    printf ("- testcase: %s\n", input_str);
    bson_free (input_str);

    ret = _mongocrypt_kek_parse_owned (&input, &kek, status);
    if (0 == strcmp (expect, "ok")) {
        _mongocrypt_kek_t kek_copy;

        ASSERT_OK_STATUS (ret, status);
        bson_init (&out);
        ret = _mongocrypt_kek_append (&kek, &out, status);
        ASSERT_OK_STATUS (ret, status);
        /* This should round trip. */
        _assert_match_bson (&out, &input);

        /* Check that copy works as well. */
        bson_reinit (&out);
        _mongocrypt_kek_copy_to (&kek, &kek_copy);
        ret = _mongocrypt_kek_append (&kek_copy, &out, status);
        ASSERT_OK_STATUS (ret, status);
        _assert_match_bson (&out, &input);
        _mongocrypt_kek_cleanup (&kek_copy);
        bson_destroy (&out);
    } else {
        ASSERT_FAILS_STATUS (ret, status, expect);
    }

    _mongocrypt_kek_cleanup (&kek);
    mongocrypt_status_destroy (status);
}

void
test_mongocrypt_kek_parsing (_mongocrypt_tester_t *tester) {
   bson_t test_file;
   bson_iter_t iter;

   _load_json_as_bson ("./test/data/kek-tests.json", &test_file);
   for (bson_iter_init (&iter, &test_file); bson_iter_next (&iter);) {
      bson_t test;

      bson_iter_bson (&iter, &test);
      _run_one_test (tester, &test);
      bson_destroy (&test);
   }
   bson_destroy (&test_file);
}

void
_mongocrypt_tester_install_kek (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_mongocrypt_kek_parsing);
}