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

/* Enable -Wconversion as error for only this file.
 * Other libmongocrypt files warn for -Wconversion. */
MC_BEGIN_CONVERSION_ERRORS

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

static void
print_edges_compared (mc_edges_t *edgesGot, const char *edgesExpected[])
{
   fflush (stdout); // Avoid incomplete stdout output from prior tests on error
   fprintf (stderr, "edges got ... begin\n");
   for (size_t i = 0; i < mc_edges_len (edgesGot); i++) {
      fprintf (stderr, "  %s\n", mc_edges_get (edgesGot, i));
   }
   fprintf (stderr, "edges got ... end\n");

   fprintf (stderr, "edges expected ... begin\n");
   const char **iter = edgesExpected;
   while (*iter != NULL) {
      fprintf (stderr, "  %s\n", *iter);
      iter++;
   }
   fprintf (stderr, "edges expected ... end\n");
}

static void
_test_getEdgesInt32 (_mongocrypt_tester_t *tester)
{
   Int32Test tests[] = {
      {.value = 2,
       .min = OPT_I32 (0),
       .max = OPT_I32 (7),
       .sparsity = 1,
       .expectEdges = {"0", "01", "010", "root"}},
      {.value = 2,
       .min = OPT_I32 (0),
       .max = OPT_I32 (7),
       .sparsity = 2,
       .expectEdges = {"01", "010", "root"}},
      {.value = 1,
       .sparsity = 0,
       .expectError = "sparsity must be 1 or larger"},
#include "data/range-edge-generation/edges_int32.cstruct"
   };

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      mongocrypt_status_t *const status = mongocrypt_status_new ();
      Int32Test *test = tests + i;
      mc_getEdgesInt32_args_t args = {.value = test->value,
                                      .min = test->min,
                                      .max = test->max,
                                      .sparsity = test->sparsity};
      mc_edges_t *got = mc_getEdgesInt32 (args, status);
      if (test->expectError != NULL) {
         ASSERT_OR_PRINT_MSG (NULL == got, "expected error, got success");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
         mongocrypt_status_destroy (status);
         continue;
      }
      ASSERT_OK_STATUS (got != NULL, status);

      size_t numGot = mc_edges_len (got);
      size_t numExpected = 0;
      while (test->expectEdges[numExpected] != NULL) {
         numExpected += 1;
      }

      if (numExpected != numGot) {
         print_edges_compared (got, test->expectEdges);
         TEST_ERROR (
            "got %zu edges, expected %zu edges\n", numGot, numExpected);
      }

      for (size_t gotI = 0; gotI < numGot; gotI++) {
         const char *edgeGot = mc_edges_get (got, gotI);
         const char *edgeExpected = test->expectEdges[gotI];
         if (0 == strcmp (edgeGot, edgeExpected)) {
            continue;
         }
         print_edges_compared (got, test->expectEdges);
         TEST_ERROR ("edge mismatch at index %zu. %s != %s\n",
                     gotI,
                     edgeGot,
                     edgeExpected);
      }
      mc_edges_destroy (got);
      mongocrypt_status_destroy (status);
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

static void
_test_getEdgesInt64 (_mongocrypt_tester_t *tester)
{
   Int64Test tests[] = {
      {.value = INT64_C (2),
       .min = OPT_I64 (0),
       .max = OPT_I64 (7),
       .sparsity = 1,
       .expectEdges = {"0", "01", "010", "root"}},
      {.value = INT64_C (2),
       .min = OPT_I64 (0),
       .max = OPT_I64 (7),
       .sparsity = 2,
       .expectEdges = {"01", "010", "root"}},
      {.value = 1,
       .sparsity = 0,
       .expectError = "sparsity must be 1 or larger"},
#include "data/range-edge-generation/edges_int64.cstruct"
   };

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      mongocrypt_status_t *const status = mongocrypt_status_new ();
      Int64Test *test = tests + i;
      mc_getEdgesInt64_args_t args = {.value = test->value,
                                      .min = test->min,
                                      .max = test->max,
                                      .sparsity = test->sparsity};
      mc_edges_t *got = mc_getEdgesInt64 (args, status);
      if (test->expectError != NULL) {
         ASSERT_OR_PRINT_MSG (NULL == got, "expected error, got success");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
         mongocrypt_status_destroy (status);
         continue;
      }
      ASSERT_OK_STATUS (got != NULL, status);

      size_t numGot = mc_edges_len (got);
      size_t numExpected = 0;
      while (test->expectEdges[numExpected] != NULL) {
         numExpected += 1;
      }

      if (numExpected != numGot) {
         print_edges_compared (got, test->expectEdges);
         TEST_ERROR (
            "got %zu edges, expected %zu edges\n", numGot, numExpected);
      }

      for (size_t gotI = 0; gotI < numGot; gotI++) {
         const char *edgeGot = mc_edges_get (got, gotI);
         const char *edgeExpected = test->expectEdges[gotI];
         if (0 == strcmp (edgeGot, edgeExpected)) {
            continue;
         }
         print_edges_compared (got, test->expectEdges);
         TEST_ERROR ("edge mismatch at index %zu. %s != %s\n",
                     gotI,
                     edgeGot,
                     edgeExpected);
      }
      mc_edges_destroy (got);
      mongocrypt_status_destroy (status);
   }
}

static void
_test_count_leading_zeros (_mongocrypt_tester_t *tester)
{
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u64 (UINT64_C (0)), ==, 64);
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u64 (UINT64_C (1)), ==, 63);
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u64 (UINT64_MAX), ==, 0);
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u64 ((~UINT64_C (0)) >> 1), ==, 1);

   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u32 (UINT32_C (0)), ==, 32);
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u32 (UINT32_C (1)), ==, 31);
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u32 (UINT32_MAX), ==, 0);
   ASSERT_CMPSIZE_T (mc_count_leading_zeros_u32 ((~UINT32_C (0)) >> 1), ==, 1);
}

typedef struct {
   uint32_t in;
   const char *expect;
} bitstring_u32_test;

typedef struct {
   uint64_t in;
   const char *expect;
} bitstring_u64_test;

static void
_test_convert_to_bitstring (_mongocrypt_tester_t *tester)
{
   // Test uint32_t.
   {
      bitstring_u32_test tests[] = {
         {.in = 0, .expect = "00000000000000000000000000000000"},
         {.in = 1, .expect = "00000000000000000000000000000001"},
         {.in = 123, .expect = "00000000000000000000000001111011"},
         {.in = UINT32_MAX, .expect = "11111111111111111111111111111111"}};
      for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
         bitstring_u32_test *test = tests + i;
         char *got = mc_convert_to_bitstring_u32 (test->in);
         ASSERT_STREQUAL (test->expect, got);
         bson_free (got);
      }
   }
   // Test uint64_t.
   {
      bitstring_u64_test tests[] = {
         {.in = 0,
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
                    "111111"}};
      for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
         bitstring_u64_test *test = tests + i;
         char *got = mc_convert_to_bitstring_u64 (test->in);
         ASSERT_STREQUAL (test->expect, got);
         bson_free (got);
      }
   }
}

void
_mongocrypt_tester_install_range_edge_generation (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_getEdgesInt32);
   INSTALL_TEST (_test_getEdgesInt64);
   INSTALL_TEST (_test_count_leading_zeros);
   INSTALL_TEST (_test_convert_to_bitstring);
}

MC_END_CONVERSION_ERRORS
