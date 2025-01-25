/*
 * Copyright 2025-present MongoDB, Inc.
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

#include "mongocrypt-status-private.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"
#include "unicode/fold.h"

#define TEST_UNICODE_FOLD(expected, expected_len, input, input_len, options)                                           \
    do {                                                                                                               \
        char *_buf;                                                                                                    \
        size_t _len;                                                                                                   \
        ASSERT_OR_PRINT(unicode_fold(input, input_len, options, &_buf, &_len, status), status);                        \
        TEST_PRINTF("Testing: input=%.*s, expected=%.*s, output=%.*s\n",                                               \
                    (int)input_len,                                                                                    \
                    input,                                                                                             \
                    (int)expected_len,                                                                                 \
                    expected,                                                                                          \
                    (int)_len,                                                                                         \
                    _buf);                                                                                             \
        ASSERT_CMPSIZE_T(_len, ==, expected_len);                                                                      \
        ASSERT_CMPBYTES((uint8_t *)_buf, _len, (uint8_t *)expected, expected_len);                                     \
        free(_buf);                                                                                                    \
    } while (0)

#define TEST_UNICODE_FOLD_ALL_CASES(input, case_folded, dia_folded, both_folded)                                       \
    do {                                                                                                               \
        size_t _input_len = strlen(input);                                                                             \
        size_t _cf_len = strlen(case_folded);                                                                          \
        size_t _df_len = strlen(dia_folded);                                                                           \
        size_t _both_len = strlen(both_folded);                                                                        \
        TEST_UNICODE_FOLD(case_folded, _cf_len, input, _input_len, kUnicodeFoldToLower);                               \
        TEST_UNICODE_FOLD(dia_folded, _df_len, input, _input_len, kUnicodeFoldRemoveDiacritics);                       \
        TEST_UNICODE_FOLD(both_folded,                                                                                 \
                          _both_len,                                                                                   \
                          input,                                                                                       \
                          _input_len,                                                                                  \
                          kUnicodeFoldToLower | kUnicodeFoldRemoveDiacritics);                                         \
    } while (0)

static void test_unicode_fold(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    // Test all ascii chars.
    char *buf1 = bson_malloc0(2);
    char *buf2 = bson_malloc0(2);
    for (unsigned char ch = 0; ch <= 0x7f; ch++) {
        buf1[0] = ch;
        // Diacritics
        if (ch >= 'A' && ch <= 'Z') {
            buf2[0] = ch + 0x20;
            TEST_UNICODE_FOLD_ALL_CASES(buf1, buf2, buf1, buf2);
        } else if (ch == '^' || ch == '`') {
            TEST_UNICODE_FOLD_ALL_CASES(buf1, buf1, "", "");
        }
    }
    free(buf1);
    free(buf2);
    TEST_UNICODE_FOLD_ALL_CASES("abc", "abc", "abc", "abc");
    // Tests of composed unicode
    TEST_UNICODE_FOLD_ALL_CASES("¿CUÁNTOS AÑOS tienes Tú?",
                                "¿cuántos años tienes tú?",
                                "¿CUANTOS ANOS tienes Tu?",
                                "¿cuantos anos tienes tu?");
    TEST_UNICODE_FOLD_ALL_CASES("СКОЛЬКО ТЕБЕ ЛЕТ?", "сколько тебе лет?", "СКОЛЬКО ТЕБЕ ЛЕТ?", "сколько тебе лет?");
    TEST_UNICODE_FOLD_ALL_CASES("Πόσο χρονών είσαι?", "πόσο χρονών είσαι?", "Ποσο χρονων εισαι?", "ποσο χρονων εισαι?");
    // Tests of decomposed unicode
    const char nfd1[] = {'C', 'a', 'f', 'e', 0xcc, 0x81, 0};
    const char nfd1_lower[] = {'c', 'a', 'f', 'e', 0xcc, 0x81, 0};
    TEST_UNICODE_FOLD_ALL_CASES(nfd1, nfd1_lower, "Cafe", "cafe");
    const char nfd2[] = {'C', 'a', 'f', 'E', 0xcc, 0x81, 0};
    const char nfd2_lower[] = {'c', 'a', 'f', 'e', 0xcc, 0x81, 0};
    TEST_UNICODE_FOLD_ALL_CASES(nfd2, nfd2_lower, "CafE", "cafe");

    mongocrypt_status_destroy(status);
}

void _mongocrypt_tester_install_unicode_fold(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_unicode_fold);
}
