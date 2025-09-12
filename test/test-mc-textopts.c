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

#include "mc-textopts-private.h"
#include "test-mongocrypt.h"

#define RAW_STRING(...) #__VA_ARGS__

static void test_mc_TextOpts_parse(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *expectError;
        bool expectCaseSensitive;
        bool expectDiacriticSensitive;
        bool expectSubstringSet;
        int32_t expectSubstringStrMaxLength;
        int32_t expectSubstringStrMinQueryLength;
        int32_t expectSubstringStrMaxQueryLength;
        bool expectPrefixSet;
        int32_t expectPrefixStrMaxLength;
        int32_t expectPrefixStrMinQueryLength;
        int32_t expectPrefixStrMaxQueryLength;
        bool expectSuffixSet;
        int32_t expectSuffixStrMaxLength;
        int32_t expectSuffixStrMinQueryLength;
        int32_t expectSuffixStrMaxQueryLength;
    } testcase;

    testcase tests[] = {
        {.desc = "Works with minimal options",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 1, "strMaxQueryLength" : 2}
         }),
         .expectCaseSensitive = true,
         .expectDiacriticSensitive = false,
         .expectPrefixSet = true,
         .expectPrefixStrMinQueryLength = 1,
         .expectPrefixStrMaxQueryLength = 2},
        {.desc = "Works with substring options",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "substring" : {"strMaxLength" : 10, "strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .expectCaseSensitive = true,
         .expectDiacriticSensitive = false,
         .expectSubstringSet = true,
         .expectSubstringStrMaxLength = 10,
         .expectSubstringStrMinQueryLength = 3,
         .expectSubstringStrMaxQueryLength = 8},
        {.desc = "Errors if none of prefix, suffix, or substring is provided",
         .in = RAW_STRING({"caseSensitive" : true, "diacriticSensitive" : false}),
         .expectError = "One of 'prefix', 'suffix', or 'substring' is required"},
        {.desc = "Errors if substring, prefix, and suffix are all provided",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "substring" : {"strMaxLength" : 10, "strMinQueryLength" : 3, "strMaxQueryLength" : 8},
             "prefix" : {"strMinQueryLength" : 2, "strMaxQueryLength" : 10},
             "suffix" : {"strMinQueryLength" : 4, "strMaxQueryLength" : 12}
         }),
         .expectError = "Cannot specify 'substring' with 'prefix' or 'suffix'"},
        {.desc = "Errors if strMaxLength is present in prefix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMaxLength" : 12, "strMinQueryLength" : 2, "strMaxQueryLength" : 10}
         }),
         .expectError = "'strMaxLength' is not allowed in 'prefix'"},
        {.desc = "Errors if strMaxLength is present in suffix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "suffix" : {"strMaxLength" : 15, "strMinQueryLength" : 4, "strMaxQueryLength" : 12}
         }),
         .expectError = "'strMaxLength' is not allowed in 'suffix'"},
        {.desc = "Errors on invalid caseSensitive type",
         .in = RAW_STRING({"caseSensitive" : 123, "diacriticSensitive" : false}),
         .expectError = "Expected bool for caseSensitive"},
        {.desc = "Errors on invalid diacriticSensitive type",
         .in = RAW_STRING({"caseSensitive" : true, "diacriticSensitive" : "false"}),
         .expectError = "Expected bool for diacriticSensitive"},
        {.desc = "Errors on invalid substring type",
         .in = RAW_STRING({"caseSensitive" : true, "diacriticSensitive" : false, "substring" : "invalid"}),
         .expectError = "Expected document for substring"},
        {.desc = "Errors on invalid strMaxLength type",
         .in =
             RAW_STRING({"caseSensitive" : true, "diacriticSensitive" : false, "substring" : {"strMaxLength" : "10"}}),
         .expectError = "must be an int32"},
        {.desc = "Errors on negative strMaxLength",
         .in = RAW_STRING({"caseSensitive" : true, "diacriticSensitive" : false, "substring" : {"strMaxLength" : -1}}),
         .expectError = "must be greater than zero"},
        {.desc = "Errors on unrecognized field",
         .in = RAW_STRING({"caseSensitive" : true, "diacriticSensitive" : false, "unknown" : true}),
         .expectError = "Unrecognized field"}};

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_TextOpts_t txo;
        TEST_PRINTF("running test_mc_TextOpts_parse subtest: %s\n", test->desc);
        bool ret = mc_TextOpts_parse(&txo, TMP_BSON_STR(test->in), status);
        if (!test->expectError) {
            ASSERT_OK_STATUS(ret, status);
            ASSERT_CMPINT(test->expectCaseSensitive, ==, txo.caseSensitive);
            ASSERT_CMPINT(test->expectDiacriticSensitive, ==, txo.diacriticSensitive);
            ASSERT_CMPINT(test->expectSubstringSet, ==, txo.substring.set);
            if (test->expectSubstringSet) {
                ASSERT_CMPINT32(test->expectSubstringStrMaxLength, ==, txo.substring.strMaxLength.value);
                ASSERT_CMPINT32(test->expectSubstringStrMinQueryLength, ==, txo.substring.strMinQueryLength);
                ASSERT_CMPINT32(test->expectSubstringStrMaxQueryLength, ==, txo.substring.strMaxQueryLength);
            }
            ASSERT_CMPINT(test->expectPrefixSet, ==, txo.prefix.set);
            if (test->expectPrefixSet) {
                ASSERT_CMPINT32(test->expectPrefixStrMaxLength, ==, txo.prefix.strMaxLength.value);
                ASSERT_CMPINT32(test->expectPrefixStrMinQueryLength, ==, txo.prefix.strMinQueryLength);
                ASSERT_CMPINT32(test->expectPrefixStrMaxQueryLength, ==, txo.prefix.strMaxQueryLength);
            }
            ASSERT_CMPINT(test->expectSuffixSet, ==, txo.suffix.set);
            if (test->expectSuffixSet) {
                ASSERT_CMPINT32(test->expectSuffixStrMaxLength, ==, txo.suffix.strMaxLength.value);
                ASSERT_CMPINT32(test->expectSuffixStrMinQueryLength, ==, txo.suffix.strMinQueryLength);
                ASSERT_CMPINT32(test->expectSuffixStrMaxQueryLength, ==, txo.suffix.strMaxQueryLength);
            }
        } else {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
        }
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_TextOpts_to_FLE2TextSearchInsertSpec(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *v;
        const char *expectError;
        const char *expect;
    } testcase;

    testcase tests[] = {
        {.desc = "Works with substring",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "substring" : {"strMaxLength" : 10, "strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .expect = RAW_STRING(
             {"v" : {"v" : "test", "casef" : true, "diacf" : false, "substr" : {"mlen" : 10, "ub" : 8, "lb" : 3}}})},
        {.desc = "Works with prefix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .expect =
             RAW_STRING({"v" : {"v" : "test", "casef" : true, "diacf" : false, "prefix" : {"ub" : 8, "lb" : 3}}})},
        {.desc = "Works with suffix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "suffix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .expect =
             RAW_STRING({"v" : {"v" : "test", "casef" : true, "diacf" : false, "suffix" : {"ub" : 8, "lb" : 3}}})},
        {.desc = "Works with prefix + suffix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 4, "strMaxQueryLength" : 9},
             "suffix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .expect = RAW_STRING({
             "v" : {
                 "v" : "test",
                 "casef" : true,
                 "diacf" : false,
                 "prefix" : {"ub" : 9, "lb" : 4},
                 "suffix" : {"ub" : 8, "lb" : 3}
             }
         })},
        {.desc = "Errors with missing v",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"foo" : "bar"}),
         .expectError = "Unable to find 'v' in input"}};

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_TextOpts_t txo;
        TEST_PRINTF("running test_mc_TextOpts_to_FLE2TextSearchInsertSpec subtest: %s\n", test->desc);
        ASSERT_OK_STATUS(mc_TextOpts_parse(&txo, TMP_BSON_STR(test->in), status), status);
        bson_t out = BSON_INITIALIZER;
        bool ret = mc_TextOpts_to_FLE2TextSearchInsertSpec(&txo, TMP_BSON_STR(test->v), &out, status);
        if (!test->expectError) {
            ASSERT_OK_STATUS(ret, status);
            ASSERT_EQUAL_BSON(TMP_BSON_STR(test->expect), &out);
        } else {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
        }
        bson_destroy(&out);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_TextOpts_to_FLE2TextSearchInsertSpec_for_query(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *v;
        mongocrypt_query_type_t qt;
        const char *expectError;
        const char *expect;
    } testcase;

    testcase tests[] = {
        {.desc = "Works with substring",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "substring" : {"strMaxLength" : 10, "strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .qt = MONGOCRYPT_QUERY_TYPE_SUBSTRINGPREVIEW,
         .expect = RAW_STRING(
             {"v" : {"v" : "test", "casef" : true, "diacf" : false, "substr" : {"mlen" : 10, "ub" : 8, "lb" : 3}}})},
        {.desc = "Works with prefix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .qt = MONGOCRYPT_QUERY_TYPE_PREFIXPREVIEW,
         .expect =
             RAW_STRING({"v" : {"v" : "test", "casef" : true, "diacf" : false, "prefix" : {"ub" : 8, "lb" : 3}}})},
        {.desc = "Works with suffix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "suffix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .qt = MONGOCRYPT_QUERY_TYPE_SUFFIXPREVIEW,
         .expect =
             RAW_STRING({"v" : {"v" : "test", "casef" : true, "diacf" : false, "suffix" : {"ub" : 8, "lb" : 3}}})},
        {.desc = "Works with prefix + suffix when querying prefix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 4, "strMaxQueryLength" : 9},
             "suffix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .qt = MONGOCRYPT_QUERY_TYPE_PREFIXPREVIEW,
         .expect =
             RAW_STRING({"v" : {"v" : "test", "casef" : true, "diacf" : false, "prefix" : {"ub" : 9, "lb" : 4}}})},
        {.desc = "Works with prefix + suffix when querying suffix",
         .in = RAW_STRING({
             "caseSensitive" : true,
             "diacriticSensitive" : false,
             "prefix" : {"strMinQueryLength" : 4, "strMaxQueryLength" : 9},
             "suffix" : {"strMinQueryLength" : 3, "strMaxQueryLength" : 8}
         }),
         .v = RAW_STRING({"v" : "test"}),
         .qt = MONGOCRYPT_QUERY_TYPE_SUFFIXPREVIEW,
         .expect =
             RAW_STRING({"v" : {"v" : "test", "casef" : true, "diacf" : false, "suffix" : {"ub" : 8, "lb" : 3}}})},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_TextOpts_t txo;
        TEST_PRINTF("running test_mc_TextOpts_to_FLE2TextSearchInsertSpec subtest: %s\n", test->desc);
        ASSERT_OK_STATUS(mc_TextOpts_parse(&txo, TMP_BSON_STR(test->in), status), status);
        bson_t out = BSON_INITIALIZER;
        bool ret =
            mc_TextOpts_to_FLE2TextSearchInsertSpec_for_query(&txo, TMP_BSON_STR(test->v), test->qt, &out, status);
        if (!test->expectError) {
            ASSERT_OK_STATUS(ret, status);
            ASSERT_EQUAL_BSON(TMP_BSON_STR(test->expect), &out);
        } else {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
        }
        bson_destroy(&out);
        mongocrypt_status_destroy(status);
    }
}

void _mongocrypt_tester_install_mc_TextOpts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_TextOpts_parse);
    INSTALL_TEST(test_mc_TextOpts_to_FLE2TextSearchInsertSpec);
    INSTALL_TEST(test_mc_TextOpts_to_FLE2TextSearchInsertSpec_for_query);
}
