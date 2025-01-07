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

#include "mc-range-encoding-private.h"
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
        mc_optional_int32_t expectTrimFactor;
        bool useRangeV2;
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
        // Once `use_range_v2` is default true, this test may be removed.
        {.desc = "Fails when trim factor is set but Range V2 is disabled",
         .in = RAW_STRING({"trimFactor" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .expectError = "'trimFactor' is not supported for QE range v1"},
        {.desc = "Works when trim factor is set and Range V2 is enabled",
         .in = RAW_STRING({"trimFactor" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .useRangeV2 = true,
         .expectSparsity = 1,
         .expectTrimFactor = OPT_I32(1)},
        {.desc = "Does not require sparsity",
         .in = RAW_STRING({"min" : 123, "max" : 456}),
         .useRangeV2 = true,
         .expectSparsity = mc_FLERangeSparsityDefault,
         .expectMin = OPT_I32_C(123),
         .expectMax = OPT_I32_C(456)},
        {.desc = "Errors on negative trim factor",
         .in = RAW_STRING({"trimFactor" : -1, "sparsity" : {"$numberLong" : "1"}}),
         .useRangeV2 = true,
         .expectError = "'trimFactor' must be non-negative"},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_RangeOpts_t ro;
        TEST_PRINTF("running test_mc_RangeOpts_parse subtest: %s\n", test->desc);
        bool ret = mc_RangeOpts_parse(&ro, TMP_BSON(test->in), test->useRangeV2, status);
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
            ASSERT_CMPINT(test->expectTrimFactor.set, ==, ro.trimFactor.set);
            ASSERT_CMPINT(test->expectTrimFactor.value, ==, ro.trimFactor.value);
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
        // Most of the tests are for trim factor, so range V2 is default enabled.
        bool disableRangeV2;
    } testcase;

    testcase tests[] = {
        {.desc = "Works",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 789}),
         .expect = RAW_STRING({"v" : {"v" : 789, "min" : 123, "max" : 456}})},
        {.desc = "Trim factor not appended if range V2 disabled",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 789}),
         .disableRangeV2 = true,
         .expect = RAW_STRING({"v" : {"v" : 789, "min" : 123, "max" : 456}})},
        {.desc = "Works with precision",
         .in = RAW_STRING({"min" : 123.0, "max" : 456.0, "precision" : 2, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 789.0}),
         .expect = RAW_STRING({"v" : {"v" : 789.0, "min" : 123.0, "max" : 456.0, "precision" : 2}})},
        {.desc = "Errors with missing 'v'",
         .in = RAW_STRING({"min" : 123, "max" : 456, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"foo" : "bar"}),
         .expectError = "Unable to find 'v'"},
        // Tests of trim factor
        {.desc = "tf = 0 works",
         .in = RAW_STRING({"trimFactor" : 0, "min" : 0, "max" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0}),
         .expect = RAW_STRING({"v" : {"v" : 0, "min" : 0, "max" : 1, "trimFactor" : 0}})},
        {.desc = "tf = 1 fails when domain size is 2 = 2^1",
         .in = RAW_STRING({"trimFactor" : 1, "min" : 0, "max" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0}),
         .expectError = "Trim factor (1) must be less than the total number of bits (1) used to represent any element "
                        "in the domain."},
        {.desc = "tf = 1 works when domain size is 3 > 2^1",
         .in = RAW_STRING({"trimFactor" : 1, "min" : 0, "max" : 2, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0}),
         .expect = RAW_STRING({"v" : {"v" : 0, "min" : 0, "max" : 2, "trimFactor" : 1}})},
        {.desc = "tf = 2 fails when domain size is 3 <= 2^2",
         .in = RAW_STRING({"trimFactor" : 2, "min" : 0, "max" : 2, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0}),
         .expectError = "Trim factor (2) must be less than the total number of bits (2) used to represent any element "
                        "in the domain."},

        // min = INT32_MIN, max = INT32_MAX
        {.desc = "tf = 31 works for unbounded int32 (domain size = 2^32)",
         .in = RAW_STRING(
             {"trimFactor" : 31, "min" : -2147483648, "max" : 2147483647, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0}),
         .expect = RAW_STRING({"v" : {"v" : 0, "min" : -2147483648, "max" : 2147483647, "trimFactor" : 31}})},
        {.desc = "tf = 32 fails for unbounded int32 (domain size = 2^32)",
         .in = RAW_STRING(
             {"trimFactor" : 32, "min" : -2147483648, "max" : 2147483647, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0}),
         .expectError = "Trim factor (32) must be less than the total number of bits (32) used to represent any "
                        "element in the domain."},

        // min = INT64_MIN, max = INT64_MAX
        {.desc = "tf = 63 works for int64 with no min/max (domain size = 2^64)",
         .in = RAW_STRING({
             "trimFactor" : 63,
             "min" : -9223372036854775808,
             "max" : 9223372036854775807,
             "sparsity" : {"$numberLong" : "1"}
         }),
         .v = RAW_STRING({"v" : {"$numberLong" : "0"}}),
         .expect = RAW_STRING({
             "v" : {
                 "v" : {"$numberLong" : "0"},
                 "min" : {"$numberLong" : "-9223372036854775808"},
                 "max" : {"$numberLong" : "9223372036854775807"},
                 "trimFactor" : 63
             }
         })},
        {.desc = "tf = 64 fails for int64 with no min/max (domain size = 2^64)",
         .in = RAW_STRING({
             "trimFactor" : 64,
             "min" : -9223372036854775808,
             "max" : 9223372036854775807,
             "sparsity" : {"$numberLong" : "1"}
         }),
         .v = RAW_STRING({"v" : {"$numberLong" : "0"}}),
         .expectError = "Trim factor (64) must be less than the total number of bits (64) used to represent any "
                        "element in the domain."},

        {.desc = "tf = 63 works for date with no min/max (domain size = 2^64)",
         .in = RAW_STRING({
             "trimFactor" : 63,
             "min" : {"$date" : {"$numberLong" : "-9223372036854775808"}},
             "max" : {"$date" : {"$numberLong" : "9223372036854775807"}},
             "sparsity" : {"$numberLong" : "1"}
         }),
         .v = RAW_STRING({"v" : {"$date" : {"$numberLong" : "0"}}}),
         .expect = RAW_STRING({
             "v" : {
                 "v" : {"$date" : {"$numberLong" : "0"}},
                 "min" : {"$date" : {"$numberLong" : "-9223372036854775808"}},
                 "max" : {"$date" : {"$numberLong" : "9223372036854775807"}},
                 "trimFactor" : 63
             }
         })},
        {.desc = "tf = 64 fails for date with no min/max (domain size = 2^64)",
         .in = RAW_STRING({
             "trimFactor" : 64,
             "min" : {"$date" : {"$numberLong" : "-9223372036854775808"}},
             "max" : {"$date" : {"$numberLong" : "9223372036854775807"}},
             "sparsity" : {"$numberLong" : "1"}
         }),
         .v = RAW_STRING({"v" : {"$date" : {"$numberLong" : "0"}}}),
         .expectError = "Trim factor (64) must be less than the total number of bits (64) used to represent any "
                        "element in the domain."},

        {.desc = "tf bound check passes correctly for double with min, max, precision set (tf = 9, 2^9 < domain size < "
                 "2^10)",
         .in = RAW_STRING(
             {"trimFactor" : 9, "min" : 0.0, "max" : 100.0, "precision" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0.0}),
         .expect = RAW_STRING({"v" : {"v" : 0.0, "min" : 0.0, "max" : 100.0, "precision" : 1, "trimFactor" : 9}})},
        {.desc = "tf bound check fails correctly for double with min, max, precision set (tf = 10, domain size < 2^10)",
         .in = RAW_STRING(
             {"trimFactor" : 10, "min" : 0.0, "max" : 100.0, "precision" : 1, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0.0}),
         .expectError = "Trim factor (10) must be less than the total number of bits (10) used to represent any "
                        "element in the domain."},

        {.desc = "tf = 63 works for unbounded double (domain size = 2^64)",
         .in = RAW_STRING({"trimFactor" : 63, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0.0}),
         // note - when min and max are unset, they are added into the insert spec.
         .expect = RAW_STRING({
             "v" : {
                 "v" : 0.0,
                 "min" : {"$numberDouble" : "-1.7976931348623157081e+308"},
                 "max" : {"$numberDouble" : "1.7976931348623157081e+308"},
                 "trimFactor" : 63
             }
         })},
        {.desc = "tf = 64 fails for unbounded double (domain size = 2^64))",
         .in = RAW_STRING({"trimFactor" : 64, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : 0.0}),
         .expectError = "Trim factor (64) must be less than the total number of bits (64) used to represent any "
                        "element in the domain."},

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
        {.desc = "tf bound check passes correctly for decimal with min, max, precision set (tf = 9, 2^9 < domain size "
                 "< 2^10)",
         .in = RAW_STRING({
             "trimFactor" : 9,
             "min" : {"$numberDecimal" : "0"},
             "max" : {"$numberDecimal" : "100"},
             "precision" : 1,
             "sparsity" : {"$numberLong" : "1"}
         }),
         .v = RAW_STRING({"v" : {"$numberDecimal" : "0"}}),
         .expect = RAW_STRING({
             "v" : {
                 "v" : {"$numberDecimal" : "0"},
                 "min" : {"$numberDecimal" : "0"},
                 "max" : {"$numberDecimal" : "100"},
                 "precision" : 1,
                 "trimFactor" : 9
             }
         })},
        {.desc =
             "tf bound check fails correctly for decimal with min, max, precision set (tf = 10, domain size < 2^10)",
         .in = RAW_STRING({
             "trimFactor" : 10,
             "min" : {"$numberDecimal" : "0"},
             "max" : {"$numberDecimal" : "100"},
             "precision" : 1,
             "sparsity" : {"$numberLong" : "1"}
         }),
         .v = RAW_STRING({"v" : {"$numberDecimal" : "0"}}),
         .expectError = "Trim factor (10) must be less than the total number of bits (10) used to represent any "
                        "element in the domain."},

        {.desc = "tf = 127 works for unbounded decimal (domain size = 2^128)",
         .in = RAW_STRING({"trimFactor" : 127, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : {"$numberDecimal" : "0"}}),
         .expect = RAW_STRING({
             "v" : {
                 "v" : {"$numberDecimal" : "0"},
                 "min" : {"$numberDecimal" : "-9.999999999999999999999999999999999E+6144"},
                 "max" : {"$numberDecimal" : "9.999999999999999999999999999999999E+6144"},
                 "trimFactor" : 127
             }
         })},
        {.desc = "tf = 128 fails for unbounded decimal (domain size = 2^128)",
         .in = RAW_STRING({"trimFactor" : 128, "sparsity" : {"$numberLong" : "1"}}),
         .v = RAW_STRING({"v" : {"$numberDecimal" : "0"}}),
         .expectError = "Trim factor (128) must be less than the total number of bits (128) used to represent any "
                        "element in the domain."},
#endif
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_RangeOpts_t ro;
        TEST_PRINTF("running test_mc_RangeOpts_to_FLE2RangeInsertSpec subtest: %s\n", test->desc);
        ASSERT_OK_STATUS(mc_RangeOpts_parse(&ro, TMP_BSON(test->in), !test->disableRangeV2, status), status);
        bson_t out = BSON_INITIALIZER;
        bool ret = mc_RangeOpts_to_FLE2RangeInsertSpec(&ro, TMP_BSON(test->v), &out, !test->disableRangeV2, status);
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
