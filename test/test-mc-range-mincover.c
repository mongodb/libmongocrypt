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

#include "test-mongocrypt.h"

#include "mc-array-private.h"
#include "mc-check-conversions-private.h"
#include "mc-optional-private.h"
#include "mc-range-mincover-private.h"

enum {
    /// Why this number? The Decimal128 tests generate thousands of test strings,
    /// but we can't set this arbitrarily high, since we'll bump up on stack
    /// overflow on MSVC. This is large enough to capture all strings in all
    /// Decimal128 tests without overflowing the stack.
    MAX_MINCOVER_STRINGS = 4500
};

typedef struct {
    int32_t lowerBound;
    bool includeLowerBound;
    int32_t upperBound;
    bool includeUpperBound;
    mc_optional_int32_t min;
    mc_optional_int32_t max;
    size_t sparsity;
    const char *expectMincoverStrings[MAX_MINCOVER_STRINGS];
    const char *expectError;
} Int32Test;

typedef struct {
    int64_t lowerBound;
    bool includeLowerBound;
    int64_t upperBound;
    bool includeUpperBound;
    mc_optional_int64_t min;
    mc_optional_int64_t max;
    size_t sparsity;
    const char *expectMincoverStrings[MAX_MINCOVER_STRINGS];
    const char *expectError;
} Int64Test;

typedef struct {
    double lowerBound;
    bool includeLowerBound;
    double upperBound;
    bool includeUpperBound;
    size_t sparsity;
    mc_optional_double_t min;
    mc_optional_double_t max;
    mc_optional_uint32_t precision;
    const char *expectMincoverStrings[MAX_MINCOVER_STRINGS];
    const char *expectError;
} DoubleTest;

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
typedef struct {
    mc_dec128 lowerBound;
    bool includeLowerBound;
    mc_dec128 upperBound;
    bool includeUpperBound;
    size_t sparsity;
    mc_optional_dec128_t min;
    mc_optional_dec128_t max;
    mc_optional_uint32_t precision;
    const char *expectMincoverStrings[MAX_MINCOVER_STRINGS];
    const char *expectError;
} Decimal128Test;
#endif

typedef struct _test_getMincover_args {
    mc_mincover_t *(*getMincover)(void *tests, size_t idx, mongocrypt_status_t *status);
    const char *(*expectError)(void *tests, size_t idx);
    const char *const *(*expectMincoverStrings)(void *tests, size_t idx);
    void (*dump)(void *tests, size_t idx, mc_mincover_t *got);
} _test_getMincover_args;

static mc_mincover_t *_test_getMincover32(void *tests, size_t idx, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(tests);

    Int32Test *test = (Int32Test *)tests + idx;

    return mc_getMincoverInt32((mc_getMincoverInt32_args_t){.lowerBound = test->lowerBound,
                                                            .includeLowerBound = test->includeLowerBound,
                                                            .upperBound = test->upperBound,
                                                            .includeUpperBound = test->includeUpperBound,
                                                            .min = test->min,
                                                            .max = test->max,
                                                            .sparsity = test->sparsity},
                               status);
}

static mc_mincover_t *_test_getMincover64(void *tests, size_t idx, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(tests);

    Int64Test *const test = (Int64Test *)tests + idx;

    return mc_getMincoverInt64((mc_getMincoverInt64_args_t){.lowerBound = test->lowerBound,
                                                            .includeLowerBound = test->includeLowerBound,
                                                            .upperBound = test->upperBound,
                                                            .includeUpperBound = test->includeUpperBound,
                                                            .min = test->min,
                                                            .max = test->max,
                                                            .sparsity = test->sparsity},
                               status);
}

static mc_mincover_t *_test_getMincoverDouble_helper(void *tests, size_t idx, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(tests);

    DoubleTest *const test = (DoubleTest *)tests + idx;

    return mc_getMincoverDouble(
        (mc_getMincoverDouble_args_t){.lowerBound = test->lowerBound,
                                      .includeLowerBound = test->includeLowerBound,
                                      .upperBound = test->upperBound,
                                      .includeUpperBound = test->includeUpperBound,
                                      .sparsity = test->sparsity,
                                      .min = test->precision.set ? test->min : (mc_optional_double_t){0},
                                      .max = test->precision.set ? test->max : (mc_optional_double_t){0},
                                      .precision = test->precision},
        status);
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
static mc_mincover_t *_test_getMincoverDecimal128_helper(void *tests, size_t idx, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(tests);

    Decimal128Test *const test = (Decimal128Test *)tests + idx;

    return mc_getMincoverDecimal128(
        (mc_getMincoverDecimal128_args_t){.lowerBound = test->lowerBound,
                                          .includeLowerBound = test->includeLowerBound,
                                          .upperBound = test->upperBound,
                                          .includeUpperBound = test->includeUpperBound,
                                          .sparsity = test->sparsity,
                                          .min = test->precision.set ? test->min : (mc_optional_dec128_t){0},
                                          .max = test->precision.set ? test->max : (mc_optional_dec128_t){0},
                                          .precision = test->precision},
        status);
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

static const char *_test_expectError32(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((Int32Test *)tests + idx)->expectError;
}

static const char *_test_expectError64(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((Int64Test *)tests + idx)->expectError;
}

static const char *_test_expectErrorDouble(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((DoubleTest *)tests + idx)->expectError;
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
static const char *_test_expectErrorDecimal128(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((Decimal128Test *)tests + idx)->expectError;
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

static const char *const *_test_expectMincover32(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((Int32Test *)tests + idx)->expectMincoverStrings;
}

static const char *const *_test_expectMincover64(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((Int64Test *)tests + idx)->expectMincoverStrings;
}

static const char *const *_test_expectMincoverDouble(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((DoubleTest *)tests + idx)->expectMincoverStrings;
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
static const char *const *_test_expectMincoverDecimal128(void *tests, size_t idx) {
    BSON_ASSERT_PARAM(tests);
    return ((Decimal128Test *)tests + idx)->expectMincoverStrings;
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

static void _test_dump_32(void *tests, size_t idx, mc_mincover_t *got) {
    BSON_ASSERT_PARAM(tests);
    Int32Test *const test = (Int32Test *)tests + idx;
    fflush(stdout); // Avoid incomplete stdout output from prior tests on error
    fprintf(stderr,
            "testcase: lowerBound=%" PRId32 " (%s) upperBound=%" PRId32 " (%s)",
            test->lowerBound,
            test->includeLowerBound ? "inclusive" : "exclusive",
            test->upperBound,
            test->includeUpperBound ? "inclusive" : "exclusive");
    if (test->min.set) {
        fprintf(stderr, " min=%" PRId32, test->min.value);
    }
    if (test->max.set) {
        fprintf(stderr, " max=%" PRId32, test->max.value);
    }
    fprintf(stderr, " sparsity=%zu\n", test->sparsity);
    fprintf(stderr, "mincover expected ... begin\n");
    for (const char **p = test->expectMincoverStrings; *p; ++p) {
        fprintf(stderr, "  %s\n", *p);
    }
    fprintf(stderr, "mincover expected ... end\n");
    fprintf(stderr, "mincover got ... begin\n");
    for (size_t i = 0; i < mc_mincover_len(got); i++) {
        fprintf(stderr, "  %s\n", mc_mincover_get(got, i));
    }
    fprintf(stderr, "mincover got ... end\n");
}

static void _test_dump_64(void *tests, size_t idx, mc_mincover_t *got) {
    BSON_ASSERT_PARAM(tests);
    Int64Test *const test = (Int64Test *)tests + idx;
    fflush(stdout); // Avoid incomplete stdout output from prior tests on error
    fprintf(stderr,
            "testcase: lowerBound=%" PRId64 " (%s) upperBound=%" PRId64 " (%s)",
            test->lowerBound,
            test->includeLowerBound ? "inclusive" : "exclusive",
            test->upperBound,
            test->includeUpperBound ? "inclusive" : "exclusive");
    if (test->min.set) {
        fprintf(stderr, " min=%" PRId64, test->min.value);
    }
    if (test->max.set) {
        fprintf(stderr, " max=%" PRId64, test->max.value);
    }
    fprintf(stderr, " sparsity=%zu\n", test->sparsity);
    fprintf(stderr, "mincover expected ... begin\n");
    for (const char **p = test->expectMincoverStrings; *p; ++p) {
        fprintf(stderr, "  %s\n", *p);
    }
    fprintf(stderr, "mincover expected ... end\n");
    fprintf(stderr, "mincover got ... begin\n");
    for (size_t i = 0; i < mc_mincover_len(got); i++) {
        fprintf(stderr, "  %s\n", mc_mincover_get(got, i));
    }
    fprintf(stderr, "mincover got ... end\n");
}

static void _test_dump_Double(void *tests, size_t idx, mc_mincover_t *got) {
    BSON_ASSERT_PARAM(tests);
    DoubleTest *const test = (DoubleTest *)tests + idx;
    fflush(stdout); // Avoid incomplete stdout output from prior tests on error
    fprintf(stderr,
            "testcase: lowerBound=%f (%s) upperBound=%f (%s)",
            test->lowerBound,
            test->includeLowerBound ? "inclusive" : "exclusive",
            test->upperBound,
            test->includeUpperBound ? "inclusive" : "exclusive");
    if (test->min.set) {
        fprintf(stderr, " min=%f", test->min.value);
    }
    if (test->max.set) {
        fprintf(stderr, " max=%f", test->max.value);
    }
    if (test->precision.set) {
        fprintf(stderr, " precision=%" PRIu32, test->precision.value);
    }
    fprintf(stderr, " sparsity=%zu\n", test->sparsity);
    fprintf(stderr, "mincover expected ... begin\n");
    for (const char **p = test->expectMincoverStrings; *p; ++p) {
        fprintf(stderr, "  %s\n", *p);
    }
    fprintf(stderr, "mincover expected ... end\n");
    fprintf(stderr, "mincover got ... begin\n");
    for (size_t i = 0; i < mc_mincover_len(got); i++) {
        fprintf(stderr, "  %s\n", mc_mincover_get(got, i));
    }
    fprintf(stderr, "mincover got ... end\n");
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
static void _test_dump_Decimal128(void *tests, size_t idx, mc_mincover_t *got) {
    BSON_ASSERT_PARAM(tests);
    Decimal128Test *const test = (Decimal128Test *)tests + idx;
    fflush(stdout); // Avoid incomplete stdout output from prior tests on error
    fprintf(stderr,
            "testcase: lowerBound=%s (%s) upperBound=%s (%s)",
            mc_dec128_to_string(test->lowerBound).str,
            test->includeLowerBound ? "inclusive" : "exclusive",
            mc_dec128_to_string(test->upperBound).str,
            test->includeUpperBound ? "inclusive" : "exclusive");
    if (test->min.set) {
        fprintf(stderr, " min=%s", mc_dec128_to_string(test->min.value).str);
    }
    if (test->max.set) {
        fprintf(stderr, " max=%s", mc_dec128_to_string(test->max.value).str);
    }
    if (test->precision.set) {
        fprintf(stderr, " precision=%" PRIu32, test->precision.value);
    }
    fprintf(stderr, " sparsity=%zu\n", test->sparsity);
    fprintf(stderr, "mincover expected ... begin\n");
    for (const char **p = test->expectMincoverStrings; *p; ++p) {
        fprintf(stderr, "  %s\n", *p);
    }
    fprintf(stderr, "mincover expected ... end\n");
    fprintf(stderr, "mincover got ... begin\n");
    for (size_t i = 0; i < mc_mincover_len(got); i++) {
        fprintf(stderr, "  %s\n", mc_mincover_get(got, i));
    }
    fprintf(stderr, "mincover got ... end\n");
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

static void _test_getMincover_impl(void *tests, size_t num_tests, _test_getMincover_args args) {
    BSON_ASSERT_PARAM(tests);

    for (size_t i = 0; i < num_tests; i++) {
        mongocrypt_status_t *const status = mongocrypt_status_new();
        mc_mincover_t *got = args.getMincover(tests, i, status);
        const char *expectError = args.expectError(tests, i);
        if (expectError) {
            ASSERT_OR_PRINT_MSG(NULL == got, "expected error, got success");
            ASSERT_STATUS_CONTAINS(status, expectError);
            mongocrypt_status_destroy(status);
            continue;
        }
        ASSERT_OK_STATUS(got != NULL, status);

        size_t numGot = mc_mincover_len(got);
        const char *const *expectStrings = args.expectMincoverStrings(tests, i);

        const char *const *exp_iter = expectStrings;
        size_t nthItem = 0;
        for (; *exp_iter; ++nthItem, ++exp_iter) {
            if (nthItem > numGot) {
                // List length mismatch. Keep scanning, though. We'll use the
                // numbers later
                continue;
            }
            const char *gotItem = mc_mincover_get(got, nthItem);
            const char *expectItem = *exp_iter;

            if (0 == strcmp(gotItem, expectItem)) {
                // This one matches, Keep going.
                continue;
            }
            args.dump(tests, nthItem, got);
            TEST_ERROR("test %zu: mincover mismatch at index %zu:\n"
                       "      Got: %s\n"
                       " Expected: %s\n",
                       i,
                       nthItem,
                       gotItem,
                       expectItem);
        }

        if (nthItem != numGot) {
            args.dump(tests, i, got);
            TEST_ERROR("test %zu: Got the wrong number of mincover items. Expected %zu "
                       "items, but got %zu\n",
                       i,
                       nthItem,
                       numGot);
        }

        mc_mincover_destroy(got);
        mongocrypt_status_destroy(status);
    }
}

static void _test_getMincoverInt32(_mongocrypt_tester_t *tester) {
    static Int32Test tests[] = {
        {.lowerBound = 1,
         .includeLowerBound = false,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"01"}},
        {.lowerBound = 1,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = false,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"001", "010"}},
        {.lowerBound = 1,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"001", "01"}},
        {.lowerBound = 3,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"011"}},
        {.lowerBound = 4,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectError = "must be less than or equal to"},
        {.lowerBound = 1,
         .includeLowerBound = true,
         .upperBound = 8,
         .includeUpperBound = true,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectError = "less than or equal to the maximum value"},

#include "./data/range-min-cover/mincover_int32.cstruct"

    };

    _test_getMincover_impl(tests,
                           sizeof(tests) / sizeof(tests[0]),
                           (_test_getMincover_args){.getMincover = _test_getMincover32,
                                                    .expectMincoverStrings = _test_expectMincover32,
                                                    .expectError = _test_expectError32,
                                                    .dump = _test_dump_32});
}

static void _test_getMincoverInt64(_mongocrypt_tester_t *tester) {
    static Int64Test tests[] = {
        {.lowerBound = 1,
         .includeLowerBound = false,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"01"}},
        {.lowerBound = 1,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = false,
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"001", "010"}},
        {.lowerBound = 1,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"001", "01"}},
        {.lowerBound = 3,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectMincoverStrings = {"011"}},
        {.lowerBound = 4,
         .includeLowerBound = true,
         .upperBound = 3,
         .includeUpperBound = true,
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectError = "must be less than or equal to"},
        {.lowerBound = 1,
         .includeLowerBound = true,
         .upperBound = 8,
         .includeUpperBound = true,
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectError = "less than or equal to the maximum value"},

#include "./data/range-min-cover/mincover_int64.cstruct"

    };

    _test_getMincover_impl(tests,
                           sizeof(tests) / sizeof(tests[0]),
                           (_test_getMincover_args){.getMincover = _test_getMincover64,
                                                    .expectMincoverStrings = _test_expectMincover64,
                                                    .expectError = _test_expectError64,
                                                    .dump = _test_dump_64});
}

static void _test_getMincoverDouble(_mongocrypt_tester_t *tester) {
    static DoubleTest tests[] = {
#include "./data/range-min-cover/mincover_double.cstruct"
#include "./data/range-min-cover/mincover_double_precision.cstruct"
    };

    _test_getMincover_impl(tests,
                           sizeof(tests) / sizeof(tests[0]),
                           (_test_getMincover_args){.getMincover = _test_getMincoverDouble_helper,
                                                    .expectMincoverStrings = _test_expectMincoverDouble,
                                                    .expectError = _test_expectErrorDouble,
                                                    .dump = _test_dump_Double});
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
static void _test_getMincoverDecimal128(_mongocrypt_tester_t *tester) {
    Decimal128Test tests[] = {
#include "./data/range-min-cover/mincover_decimal128.cstruct"
#include "./data/range-min-cover/mincover_decimal128_precision.cstruct"
    };

    _test_getMincover_impl(tests,
                           sizeof(tests) / sizeof(tests[0]),
                           (_test_getMincover_args){.getMincover = _test_getMincoverDecimal128_helper,
                                                    .expectMincoverStrings = _test_expectMincoverDecimal128,
                                                    .expectError = _test_expectErrorDecimal128,
                                                    .dump = _test_dump_Decimal128});
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

void _mongocrypt_tester_install_range_mincover(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_getMincoverInt32);
    INSTALL_TEST(_test_getMincoverInt64);
    INSTALL_TEST(_test_getMincoverDouble);
#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
    INSTALL_TEST(_test_getMincoverDecimal128);
#endif
}
