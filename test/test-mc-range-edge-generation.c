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

#include "mc-check-conversions-private.h"
#include "mc-optional-private.h"
#include "mc-range-edge-generation-private.h"

#include <float.h> // DBL_MIN

#define MAX_INT32_EDGES 33

typedef struct {
    int32_t value;
    mc_optional_int32_t min;
    mc_optional_int32_t max;
    size_t sparsity;
    // expectEdges includes a trailing NULL pointer.
    const char *expectEdges[MAX_INT32_EDGES + 1];
    const char *expectError;
} Int32Test;

#undef MAX_INT32_EDGES

static void print_edges_compared(mc_edges_t *edgesGot, const char *const *edgesExpected) {
    fflush(stdout); // Avoid incomplete stdout output from prior tests on error
    fprintf(stderr, "edges got ... begin\n");
    for (size_t i = 0; i < mc_edges_len(edgesGot); i++) {
        fprintf(stderr, "  %s\n", mc_edges_get(edgesGot, i));
    }
    fprintf(stderr, "edges got ... end\n");

    fprintf(stderr, "edges expected ... begin\n");
    const char *const *iter = edgesExpected;
    while (*iter != NULL) {
        fprintf(stderr, "  %s\n", *iter);
        iter++;
    }
    fprintf(stderr, "edges expected ... end\n");
}

static void _test_getEdgesInt32(_mongocrypt_tester_t *tester) {
    static const Int32Test tests[] = {
        {.value = 2,
         .min = OPT_I32_C(0),
         .max = OPT_I32_C(7),
         .sparsity = 1,
         .expectEdges = {"root", "010", "0", "01"}},
        {.value = 2, .min = OPT_I32_C(0), .max = OPT_I32_C(7), .sparsity = 2, .expectEdges = {"root", "010", "01"}},
        {.value = 1, .sparsity = 0, .expectError = "sparsity must be 1 or larger"},
#include "data/range-edge-generation/edges_int32.cstruct"
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        mongocrypt_status_t *const status = mongocrypt_status_new();
        const Int32Test *test = tests + i;
        mc_getEdgesInt32_args_t args = {.value = test->value,
                                        .min = test->min,
                                        .max = test->max,
                                        .sparsity = test->sparsity};
        mc_edges_t *got = mc_getEdgesInt32(args, status);
        if (test->expectError != NULL) {
            ASSERT_OR_PRINT_MSG(NULL == got, "expected error, got success");
            ASSERT_STATUS_CONTAINS(status, test->expectError);
            mongocrypt_status_destroy(status);
            continue;
        }
        ASSERT_OK_STATUS(got != NULL, status);

        size_t numGot = mc_edges_len(got);
        size_t numExpected = 0;
        while (test->expectEdges[numExpected] != NULL) {
            ++numExpected;
        }

        if (numExpected != numGot) {
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("got %zu edges, expected %zu edges\n", numGot, numExpected);
        }

        for (size_t gotI = 0; gotI < numGot; gotI++) {
            const char *edgeGot = mc_edges_get(got, gotI);
            const char *edgeExpected = test->expectEdges[gotI];
            if (0 == strcmp(edgeGot, edgeExpected)) {
                continue;
            }
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("edge mismatch at index %zu. %s != %s\n", gotI, edgeGot, edgeExpected);
        }
        mc_edges_destroy(got);
        mongocrypt_status_destroy(status);
    }
}

#define MAX_INT64_EDGES 65

typedef struct {
    int64_t value;
    mc_optional_int64_t min;
    mc_optional_int64_t max;
    size_t sparsity;
    // expectEdges includes a trailing NULL pointer.
    const char *expectEdges[MAX_INT64_EDGES + 1];
    const char *expectError;
} Int64Test;

#undef MAX_INT64_EDGES

static void _test_getEdgesInt64(_mongocrypt_tester_t *tester) {
    static const Int64Test tests[] = {
        {.value = INT64_C(2),
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 1,
         .expectEdges = {"root", "010", "0", "01"}},
        {.value = INT64_C(2),
         .min = OPT_I64_C(0),
         .max = OPT_I64_C(7),
         .sparsity = 2,
         .expectEdges = {"root", "010", "01"}},
        {.value = 1, .sparsity = 0, .expectError = "sparsity must be 1 or larger"},
#include "data/range-edge-generation/edges_int64.cstruct"
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        mongocrypt_status_t *const status = mongocrypt_status_new();
        const Int64Test *test = tests + i;
        mc_getEdgesInt64_args_t args = {.value = test->value,
                                        .min = test->min,
                                        .max = test->max,
                                        .sparsity = test->sparsity};
        mc_edges_t *got = mc_getEdgesInt64(args, status);
        if (test->expectError != NULL) {
            ASSERT_OR_PRINT_MSG(NULL == got, "expected error, got success");
            ASSERT_STATUS_CONTAINS(status, test->expectError);
            mongocrypt_status_destroy(status);
            continue;
        }
        ASSERT_OK_STATUS(got != NULL, status);

        size_t numGot = mc_edges_len(got);
        size_t numExpected = 0;
        while (test->expectEdges[numExpected] != NULL) {
            ++numExpected;
        }

        if (numExpected != numGot) {
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("got %zu edges, expected %zu edges\n", numGot, numExpected);
        }

        for (size_t gotI = 0; gotI < numGot; gotI++) {
            const char *edgeGot = mc_edges_get(got, gotI);
            const char *edgeExpected = test->expectEdges[gotI];
            if (0 == strcmp(edgeGot, edgeExpected)) {
                continue;
            }
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("edge mismatch at index %zu. %s != %s\n", gotI, edgeGot, edgeExpected);
        }
        mc_edges_destroy(got);
        mongocrypt_status_destroy(status);
    }
}

#define MAX_DOUBLE_EDGES 65

typedef struct {
    double value;
    size_t sparsity;
    // expectEdges includes a trailing NULL pointer.
    const char *expectEdges[MAX_DOUBLE_EDGES + 1];
    const char *expectError;
} DoubleTest;

#undef MAX_DOUBLE_EDGES

static void _test_getEdgesDouble(_mongocrypt_tester_t *tester) {
    static const DoubleTest tests[] = {
#include "data/range-edge-generation/edges_double.cstruct"
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        mongocrypt_status_t *const status = mongocrypt_status_new();
        const DoubleTest *test = tests + i;
        mc_getEdgesDouble_args_t args = {.value = test->value, .sparsity = test->sparsity};
        mc_edges_t *got = mc_getEdgesDouble(args, status);

        if (test->expectError != NULL) {
            if (NULL != got) {
                TEST_ERROR("test %zu expected error, got success", i);
            }
            ASSERT_STATUS_CONTAINS(status, test->expectError);
            mongocrypt_status_destroy(status);
            continue;
        }
        ASSERT_OK_STATUS(got != NULL, status);

        size_t numGot = mc_edges_len(got);
        size_t numExpected = 0;
        while (test->expectEdges[numExpected] != NULL) {
            ++numExpected;
        }

        if (numExpected != numGot) {
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("test %zu got %zu edges, expected %zu edges\n", i, numGot, numExpected);
        }

        for (size_t gotI = 0; gotI < numGot; gotI++) {
            const char *edgeGot = mc_edges_get(got, gotI);
            const char *edgeExpected = test->expectEdges[gotI];
            if (0 == strcmp(edgeGot, edgeExpected)) {
                continue;
            }
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("test %zu got edge mismatch at index %zu. %s != %s\n", i, gotI, edgeGot, edgeExpected);
        }
        mc_edges_destroy(got);
        mongocrypt_status_destroy(status);
    }
}

#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
#define MAX_DEC128_EDGES 129

typedef struct {
    mc_dec128 value;
    mc_optional_dec128_t min;
    mc_optional_dec128_t max;
    int sparsity;
    // expectEdges includes a trailing NULL pointer.
    const char *expectEdges[MAX_DEC128_EDGES + 1];
    const char *expectError;
} Decimal128Test;

#undef MAX_DEC128_EDGES

static void _test_getEdgesDecimal128(_mongocrypt_tester_t *tester) {
    Decimal128Test tests[] = {
#include "data/range-edge-generation/edges_decimal128.cstruct"
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        const Decimal128Test *test = tests + i;
        mongocrypt_status_t *const status = mongocrypt_status_new();
        mc_getEdgesDecimal128_args_t args = {
            .value = test->value,
            // Some edges specify min/max values, but we don't use them (yet)
            //  .min = test->min,
            //  .max = test->max,
            .sparsity = (size_t)test->sparsity,
        };
        mc_edges_t *got = mc_getEdgesDecimal128(args, status);

        if (test->expectError != NULL) {
            if (NULL != got) {
                TEST_ERROR("test %zu expected error, got success", i);
            }
            ASSERT_STATUS_CONTAINS(status, test->expectError);
            mongocrypt_status_destroy(status);
            continue;
        }
        ASSERT_OK_STATUS(got != NULL, status);

        size_t numGot = mc_edges_len(got);
        size_t numExpected = 0;
        while (test->expectEdges[numExpected] != NULL) {
            ++numExpected;
        }

        if (numExpected != numGot) {
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("test %zu got %zu edges, expected %zu edges\n", i, numGot, numExpected);
        }
        for (size_t gotI = 0; gotI < numGot; gotI++) {
            const char *edgeGot = mc_edges_get(got, gotI);
            const char *edgeExpected = test->expectEdges[gotI];
            if (0 == strcmp(edgeGot, edgeExpected)) {
                continue;
            }
            print_edges_compared(got, test->expectEdges);
            TEST_ERROR("test %zu got edge mismatch at index %zu. (actual) '%s' "
                       "!= '%s' (expected)\n",
                       i,
                       gotI,
                       edgeGot,
                       edgeExpected);
        }
        mc_edges_destroy(got);
        mongocrypt_status_destroy(status);
    }
}
#endif // MONGOCRYPT_HAVE_DECIMAL128_SUPPORT

static void _test_count_leading_zeros(_mongocrypt_tester_t *tester) {
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u64(UINT64_C(0)), ==, 64);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u64(UINT64_C(1)), ==, 63);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u64(UINT64_MAX), ==, 0);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u64((~UINT64_C(0)) >> 1), ==, 1);

    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u32(UINT32_C(0)), ==, 32);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u32(UINT32_C(1)), ==, 31);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u32(UINT32_MAX), ==, 0);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u32((~UINT32_C(0)) >> 1), ==, 1);

    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u128(MLIB_INT128(0)), ==, 128);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u128(MLIB_INT128(8)), ==, 124);
    ASSERT_CMPSIZE_T(mc_count_leading_zeros_u128((mlib_int128)MLIB_INT128_FROM_PARTS(0, 8)), ==, 60);
}

typedef struct {
    uint32_t in;
    const char *expect;
} bitstring_u32_test;

typedef struct {
    uint64_t in;
    const char *expect;
} bitstring_u64_test;

typedef struct {
    mlib_int128 in;
    const char *expect;
} bitstring_u128_test;

static void _test_convert_to_bitstring(_mongocrypt_tester_t *tester) {
    // Test uint32_t.
    {
        bitstring_u32_test tests[] = {{.in = 0, .expect = "00000000000000000000000000000000"},
                                      {.in = 1, .expect = "00000000000000000000000000000001"},
                                      {.in = 123, .expect = "00000000000000000000000001111011"},
                                      {.in = UINT32_MAX, .expect = "11111111111111111111111111111111"},
                                      {.in = UINT32_MAX - 1u, .expect = "11111111111111111111111111111110"}};
        for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
            bitstring_u32_test *test = tests + i;
            mc_bitstring got = mc_convert_to_bitstring_u32(test->in);
            ASSERT_STREQUAL(test->expect, got.str);
        }
    }
    // Test uint64_t.
    {
        bitstring_u64_test tests[] = {{.in = 0,
                                       .expect = "0000000000000000000000000000000000000000000000000000000000"
                                                 "000000"},
                                      {.in = 1,
                                       .expect = "0000000000000000000000000000000000000000000000000000000000"
                                                 "000001"},
                                      {.in = 123,
                                       .expect = "0000000000000000000000000000000000000000000000000000000001"
                                                 "111011"},
                                      {.in = UINT64_MAX,
                                       .expect = "1111111111111111111111111111111111111111111111111111111111"
                                                 "111111"},
                                      {.in = UINT64_MAX - 1u,
                                       .expect = "1111111111111111111111111111111111111111111111111111111111"
                                                 "111110"}};
        for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
            bitstring_u64_test *test = tests + i;
            mc_bitstring got = mc_convert_to_bitstring_u64(test->in);
            ASSERT_STREQUAL(test->expect, got.str);
        }
    }
    // Tests for u128
    {
        bitstring_u128_test tests[] = {
            {
                .in = MLIB_INT128(0),
                .expect = "00000000000000000000000000000000000000000000000000000000"
                          "00000000000000000000000000000000000000000000000000000000"
                          "0000000000000000",
            },
            {
                .in = MLIB_INT128(1),
                .expect = "00000000000000000000000000000000000000000000000000000000"
                          "00000000000000000000000000000000000000000000000000000000"
                          "0000000000000001",
            },
            {
                .in = MLIB_INT128(256),
                .expect = "00000000000000000000000000000000000000000000000000000000"
                          "00000000000000000000000000000000000000000000000000000000"
                          "0000000100000000",
            },
            {
                .in = mlib_int128_from_string("0b1011010010001011101010010100101010010101010101001010010100100"
                                              "101010101010010001010011010110110100110010101010010101001111010"
                                              "1011",
                                              NULL),
                .expect = "10110100100010111010100101001010100101010101010010100101"
                          "00100101010101010010001010011010110110100110010101010010"
                          "1010011110101011",
            },
        };
        for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
            bitstring_u128_test *test = tests + i;
            mc_bitstring got = mc_convert_to_bitstring_u128(test->in);
            ASSERT_STREQUAL(test->expect, got.str);
        }
    }
}

void _mongocrypt_tester_install_range_edge_generation(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_getEdgesInt32);
    INSTALL_TEST(_test_getEdgesInt64);
    INSTALL_TEST(_test_getEdgesDouble);
#if MONGOCRYPT_HAVE_DECIMAL128_SUPPORT
    INSTALL_TEST(_test_getEdgesDecimal128);
#endif
    INSTALL_TEST(_test_count_leading_zeros);
    INSTALL_TEST(_test_convert_to_bitstring);
}
