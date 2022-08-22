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
#include "mc-range-edge-generation-private.h"

/* Enable -Wconversion as error for only this file.
 * Other libmongocrypt files warn for -Wconversion. */
MC_BEGIN_CONVERSION_ERRORS

#define MAX_INT32_EDGES 33
typedef struct {
   mc_getEdgesInt32_args_t args;
   const char *expectError;
   // expectEdges includes a trailing NULL pointer.
   const char *expectEdges[MAX_INT32_EDGES + 1];
} Int32Test;
#undef MAX_INT32_EDGES

static void
print_edges_compared (mc_edges_t *edgesGot, const char *edgesExpected[])
{
   fprintf (stderr, "edges got ... begin\n");
   for (size_t i = 0; i < mc_edges_len (edgesGot); i++) {
      fprintf (stderr, "  %s\n", mc_edges_get (i));
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
   mongocrypt_status_t *const status = mongocrypt_status_new ();
   Int32Test tests[] = {{.args = {.value = INT32_C (123)},
                         .expectEdges = {"root",
                                         "1",
                                         "10",
                                         "100",
                                         "1000",
                                         "10000",
                                         "100000",
                                         "1000000",
                                         "10000000",
                                         "100000000",
                                         "1000000000",
                                         "10000000000",
                                         "100000000000",
                                         "1000000000000",
                                         "10000000000000",
                                         "100000000000000",
                                         "1000000000000000",
                                         "10000000000000000",
                                         "100000000000000000",
                                         "1000000000000000000",
                                         "10000000000000000000",
                                         "100000000000000000000",
                                         "1000000000000000000000",
                                         "10000000000000000000000",
                                         "100000000000000000000000",
                                         "1000000000000000000000000",
                                         "10000000000000000000000001",
                                         "100000000000000000000000011",
                                         "1000000000000000000000000111",
                                         "10000000000000000000000001111",
                                         "100000000000000000000000011110",
                                         "1000000000000000000000000111101"}}};

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      Int32Test *test = tests + i;
      mc_edges_t *got = mc_getEdgesInt32 (test->args, status);
      if (test->expectError != NULL) {
         ASSERT_OR_PRINT_MSG (NULL == got, "expected error, got success");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
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

      for (i = 0; i < numGot; i++) {
         const char *edgeGot = mc_edges_get (i);
         const char *edgeExpected = test->expectEdges[i];
         if (0 == strcmp (edgeGot, edgeExpected)) {
            continue;
         }
         print_edges_compared (got, test->expectEdges);
         TEST_ERROR (
            "edge mismatch at index %zu. %s != %s\n", i, edgeGot, edgeExpected);
      }
   }
   mongocrypt_status_destroy (status);
}

static void
_test_getEdgesInt64 (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *const status = mongocrypt_status_new ();
   mc_edges_t *edges = mc_getEdgesInt64 (
      (mc_getEdgesInt64_args_t){.value = INT64_C (123)}, status);
   ASSERT_OK_STATUS (edges != NULL, status);
   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_range_edge_generation (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_getEdgesInt32);
   INSTALL_TEST (_test_getEdgesInt64);
}

MC_END_CONVERSION_ERRORS
