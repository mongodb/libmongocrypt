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

#include "mc-rangeopts-private.h"
#include "test-mongocrypt.h"

#define RAW_STRING(...) #__VA_ARGS__

static void test_mc_RangeOpts_parse(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *expectError;
        mc_optional_int32_t expectMin;
        mc_optional_int32_t expectMax;
        int64_t expectSparsity;
        mc_optional_uint32_t expectPrecision;
    } testcase;

    testcase tests[] = {
        {.desc = "Works",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}}),
         .expectSparsity = 1,
         .expectMin = OPT_I32_C(123),
         .expectMax = OPT_I32_C(456)},
        {.desc = "Errors if precision is set with int min/max",
         .in = RAW_STRING({"min" : 123, "max" : 456, "precision" : 2, "sparsity" : {"$numberLong" : "1"}}),
         .expectError = "expected 'precision' to be set with double or decimal128 index"},
        {.desc = "Errors on missing fields",
         .in = RAW_STRING({"min" : 123, "max" : 456}),
         .expectError = "Missing field 'sparsity'"},
        {.desc = "Errors on extra fields",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}, "foo" : 1}),
         .expectError = "Unrecognized field: 'foo'"},
        {.desc = "Errors if min/max types mismatch",
         .in = RAW_STRING({"min" : 123, "max" : 456.0, "sparsity" : {"$numberLong" : "1"}}),
         .expectError = "expected 'min' and 'max' to be same type"},
        {
            .desc = "Does not require min/max",
            .in = RAW_STRING({"sparsity" : {"$numberLong" : "1"}}),
            .expectSparsity = 1,
        },
        {.desc = "Requires precision for double when min/max is set",
         .in = RAW_STRING({"min" : 0.0, "max" : 1.0, "sparsity" : {"$numberLong" : "1"}}),
         .expectError = "expected 'precision'"},
        {.desc = "Requires min/max for double when precision is set",
         .in = RAW_STRING({"precision" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .expectError = "setting precision requires min"},
        {.desc = "Requires precision for double when only min is set",
         .in = RAW_STRING({"min" : 0.0, "sparsity" : {"$numberLong" : "1"}}),
         .expectError = "expected 'precision'"},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_RangeOpts_t ro;
        printf("running test_mc_RangeOpts_parse subtest: %s\n", test->desc);
        bool ret = mc_RangeOpts_parse(&ro, TMP_BSON(test->in), status);
        if (!test->expectError) {
            ASSERT_OK_STATUS(ret, status);
            ASSERT_CMPINT(test->expectMin.set, ==, ro.min.set);
            if (test->expectMin.set) {
                ASSERT_CMPINT32(test->expectMin.value, ==, bson_iter_int32(&ro.min.value));
            }
            ASSERT_CMPINT(test->expectMax.set, ==, ro.max.set);
            if (test->expectMax.set) {
                ASSERT_CMPINT32(test->expectMax.value, ==, bson_iter_int32(&ro.max.value));
            }
            ASSERT_CMPINT64(test->expectSparsity, ==, ro.sparsity);
            ASSERT_CMPINT(test->expectPrecision.set, ==, ro.precision.set);
            ASSERT_CMPINT(test->expectPrecision.value, ==, ro.precision.value);
        } else {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
        }
        mc_RangeOpts_cleanup(&ro);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_RangeOpts_to_FLE2RangeInsertSpec(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *v;
        const char *expectError;
        const char *expect;
    } testcase;

    testcase tests[] = {
        {.desc = "Works",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 789}),
         .expect = RAW_STRING({"v" : {"v" : 789, "min" : 123, "max" : 456}})},
        {.desc = "Works with precision",
         .in = RAW_STRING({"min" : 123.0, "max" : 456.0, "precision" : 2, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 789.0}),
         .expect = RAW_STRING({"v" : {"v" : 789.0, "min" : 123.0, "max" : 456.0, "precision" : 2}})},
        {.desc = "Errors with missing 'v'",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"foo" : "bar"}),
         .expectError = "Unable to find 'v'"}};

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_RangeOpts_t ro;
        printf("running test_mc_RangeOpts_to_FLE2RangeInsertSpec subtest: %s\n", test->desc);
        ASSERT_OK_STATUS(mc_RangeOpts_parse(&ro, TMP_BSON(test->in), status), status);
        bson_t out = BSON_INITIALIZER;
        bool ret = mc_RangeOpts_to_FLE2RangeInsertSpec(&ro, TMP_BSON(test->v), &out, status);
        if (!test->expectError) {
            ASSERT_OK_STATUS(ret, status);
            ASSERT_EQUAL_BSON(TMP_BSON(test->expect), &out);
        } else {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
        }
        bson_destroy(&out);
        mc_RangeOpts_cleanup(&ro);
        mongocrypt_status_destroy(status);
    }
}

void _mongocrypt_tester_install_mc_RangeOpts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_RangeOpts_parse);
    INSTALL_TEST(test_mc_RangeOpts_to_FLE2RangeInsertSpec);
}
