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
#include "mc-range-mincover-private.h"
#include "mc-array-private.h"

/* Enable -Wconversion as error for only this file.
 * Other libmongocrypt files warn for -Wconversion. */
MC_BEGIN_CONVERSION_ERRORS

typedef struct {
   int32_t range_min;
   int32_t range_max;
   mc_optional_int32_t min;
   mc_optional_int32_t max;
   size_t sparsity;
   /* expectMincoverString is newline delimitted list of strings. */
   const char *expectMincoverString;
   mc_array_t expectMincover;
   const char *expectError;
} Int32Test;

static void
Int32Test_dump (Int32Test *test, mc_mincover_t *got)
{
   fflush (stdout); // Avoid incomplete stdout output from prior tests on error
   fprintf (stderr,
            "testcase: range_min=%" PRId32 " range_max=%" PRId32,
            test->range_min,
            test->range_max);
   if (test->min.set) {
      fprintf (stderr, " min=%" PRId32, test->min.value);
   }
   if (test->max.set) {
      fprintf (stderr, " max=%" PRId32, test->max.value);
   }
   fprintf (stderr, " sparsity=%zu", test->sparsity);
   fprintf (stderr, " expected mincover:\n%s", test->expectMincoverString);
   fprintf (stderr, "mincover got ... begin\n");
   for (size_t i = 0; i < mc_mincover_len (got); i++) {
      fprintf (stderr, "  %s\n", mc_mincover_get (got, i));
   }
   fprintf (stderr, "mincover got ... end\n");
}

static void
expectMincover_init (mc_array_t *expectMincover,
                     const char *expectMincoverString)
{
   _mc_array_init (expectMincover, sizeof (char *));

   const char *curr = expectMincoverString;
   const char *ptr = expectMincoverString;
   size_t nchars = 0;
   while (true) {
      if (*ptr == '\n') {
         if (nchars > 0) {
            char *got = bson_strndup (curr, nchars);
            _mc_array_append_val (expectMincover, got);
         }
         curr = ptr + 1;
         ++ptr;
         nchars = 0;
         continue;
      }
      if (*ptr == '\0') {
         if (nchars > 0) {
            char *got = bson_strndup (curr, nchars);
            _mc_array_append_val (expectMincover, got);
         }
         return;
      }
      ++ptr;
      ++nchars;
   }
}

static void
expectMincover_cleanup (mc_array_t *expectMincover)
{
   for (size_t i = 0; i < expectMincover->len; i++) {
      char *got = _mc_array_index (expectMincover, char *, i);
      bson_free (got);
   }
   _mc_array_destroy (expectMincover);
}

static void
_test_getMincoverInt32 (_mongocrypt_tester_t *tester)
{
   Int32Test tests[] = {
      {.range_min = 1,
       .range_max = 3,
       .min = OPT_I32 (0),
       .max = OPT_I32 (7),
       .sparsity = 1,
       .expectMincoverString = "001\n"
                               "01\n"},
      {.range_min = 3,
       .range_max = 3,
       .min = OPT_I32 (0),
       .max = OPT_I32 (7),
       .sparsity = 1,
       .expectMincoverString = "011\n"},
      {.range_min = 4,
       .range_max = 3,
       .min = OPT_I32 (0),
       .max = OPT_I32 (7),
       .sparsity = 1,
       .expectError = "must be less than or equal to"},
      {.range_min = 1,
       .range_max = 8,
       .min = OPT_I32 (0),
       .max = OPT_I32 (7),
       .sparsity = 1,
       .expectError = "less than or equal to the maximum value"},

#include "./data/range-min-cover/mincover_int32.cstruct"

   };

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      mongocrypt_status_t *const status = mongocrypt_status_new ();
      Int32Test *test = tests + i;
      mc_getMincoverInt32_args_t args = {.range_min = test->range_min,
                                         .range_max = test->range_max,
                                         .min = test->min,
                                         .max = test->max,
                                         .sparsity = test->sparsity};
      mc_mincover_t *got = mc_getMincoverInt32 (args, status);
      if (test->expectError != NULL) {
         ASSERT_OR_PRINT_MSG (NULL == got, "expected error, got success");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
         mongocrypt_status_destroy (status);
         continue;
      }
      ASSERT_OK_STATUS (got != NULL, status);

      expectMincover_init (&test->expectMincover, test->expectMincoverString);
      size_t numGot = mc_mincover_len (got);
      size_t numExpected = test->expectMincover.len;

      if (numExpected != numGot) {
         Int32Test_dump (test, got);
         TEST_ERROR ("test %zu: got %zu mincover, expected %zu mincover\n",
                     i,
                     numGot,
                     numExpected);
      }

      for (size_t gotI = 0; gotI < numGot; gotI++) {
         const char *edgeGot = mc_mincover_get (got, gotI);
         const char *edgeExpected =
            _mc_array_index (&test->expectMincover, const char *, gotI);
         if (0 == strcmp (edgeGot, edgeExpected)) {
            continue;
         }
         Int32Test_dump (test, got);
         TEST_ERROR ("test %zu: edge mismatch at index %zu. %s != %s\n",
                     i,
                     gotI,
                     edgeGot,
                     edgeExpected);
      }

      expectMincover_cleanup (&test->expectMincover);
      mc_mincover_destroy (got);
      mongocrypt_status_destroy (status);
   }
}

typedef struct {
   int64_t range_min;
   int64_t range_max;
   mc_optional_int64_t min;
   mc_optional_int64_t max;
   size_t sparsity;
   /* expectMincoverString is newline delimitted list of strings. */
   const char *expectMincoverString;
   mc_array_t expectMincover;
   const char *expectError;
} Int64Test;

static void
Int64Test_dump (Int64Test *test, mc_mincover_t *got)
{
   fflush (stdout); // Avoid incomplete stdout output from prior tests on error
   fprintf (stderr,
            "testcase: range_min=%" PRId64 " range_max=%" PRId64,
            test->range_min,
            test->range_max);
   if (test->min.set) {
      fprintf (stderr, " min=%" PRId64, test->min.value);
   }
   if (test->max.set) {
      fprintf (stderr, " max=%" PRId64, test->max.value);
   }
   fprintf (stderr, " sparsity=%zu", test->sparsity);
   fprintf (stderr, " expected mincover:\n%s", test->expectMincoverString);
   fprintf (stderr, "mincover got ... begin\n");
   for (size_t i = 0; i < mc_mincover_len (got); i++) {
      fprintf (stderr, "  %s\n", mc_mincover_get (got, i));
   }
   fprintf (stderr, "mincover got ... end\n");
}

static void
_test_getMincoverInt64 (_mongocrypt_tester_t *tester)
{
   Int64Test tests[] = {
      {.range_min = 1,
       .range_max = 3,
       .min = OPT_I64 (0),
       .max = OPT_I64 (7),
       .sparsity = 1,
       .expectMincoverString = "001\n"
                               "01\n"},
      {.range_min = 3,
       .range_max = 3,
       .min = OPT_I64 (0),
       .max = OPT_I64 (7),
       .sparsity = 1,
       .expectMincoverString = "011\n"},
      {.range_min = 4,
       .range_max = 3,
       .min = OPT_I64 (0),
       .max = OPT_I64 (7),
       .sparsity = 1,
       .expectError = "must be less than or equal to"},
      {.range_min = 1,
       .range_max = 8,
       .min = OPT_I64 (0),
       .max = OPT_I64 (7),
       .sparsity = 1,
       .expectError = "less than or equal to the maximum value"},

#include "./data/range-min-cover/mincover_int64.cstruct"

   };

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      mongocrypt_status_t *const status = mongocrypt_status_new ();
      Int64Test *test = tests + i;
      mc_getMincoverInt64_args_t args = {.range_min = test->range_min,
                                         .range_max = test->range_max,
                                         .min = test->min,
                                         .max = test->max,
                                         .sparsity = test->sparsity};
      mc_mincover_t *got = mc_getMincoverInt64 (args, status);
      if (test->expectError != NULL) {
         ASSERT_OR_PRINT_MSG (NULL == got, "expected error, got success");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
         mongocrypt_status_destroy (status);
         continue;
      }
      ASSERT_OK_STATUS (got != NULL, status);

      expectMincover_init (&test->expectMincover, test->expectMincoverString);
      size_t numGot = mc_mincover_len (got);
      size_t numExpected = test->expectMincover.len;

      if (numExpected != numGot) {
         Int64Test_dump (test, got);
         TEST_ERROR ("test %zu: got %zu mincover, expected %zu mincover\n",
                     i,
                     numGot,
                     numExpected);
      }

      for (size_t gotI = 0; gotI < numGot; gotI++) {
         const char *edgeGot = mc_mincover_get (got, gotI);
         const char *edgeExpected =
            _mc_array_index (&test->expectMincover, const char *, gotI);
         if (0 == strcmp (edgeGot, edgeExpected)) {
            continue;
         }
         Int64Test_dump (test, got);
         TEST_ERROR ("test %zu: edge mismatch at index %zu. %s != %s\n",
                     i,
                     gotI,
                     edgeGot,
                     edgeExpected);
      }

      expectMincover_cleanup (&test->expectMincover);
      mc_mincover_destroy (got);
      mongocrypt_status_destroy (status);
   }
}

void
_mongocrypt_tester_install_range_mincover (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_getMincoverInt32);
   INSTALL_TEST (_test_getMincoverInt64);
}

MC_END_CONVERSION_ERRORS
