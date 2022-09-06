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

typedef struct _test_getMincover_args {
   mc_mincover_t *(*getMincover) (void *tests,
                                  size_t idx,
                                  mongocrypt_status_t *status);
   const char *(*expectError) (void *tests, size_t idx);
   void (*expectMincover_init) (void *tests, size_t idx);
   mc_array_t *(*expectMincover) (void *tests, size_t idx);
   void (*dump) (void *tests, size_t idx, mc_mincover_t *got);
} _test_getMincover_args;

static mc_mincover_t *
_test_getMincover32 (void *tests, size_t idx, mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (tests);

   Int32Test *test = (Int32Test *) tests + idx;

   return mc_getMincoverInt32 (
      (mc_getMincoverInt32_args_t){.range_min = test->range_min,
                                   .range_max = test->range_max,
                                   .min = test->min,
                                   .max = test->max,
                                   .sparsity = test->sparsity},
      status);
}

static mc_mincover_t *
_test_getMincover64 (void *tests, size_t idx, mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (tests);

   Int64Test *const test = (Int64Test *) tests + idx;

   return mc_getMincoverInt64 (
      (mc_getMincoverInt64_args_t){.range_min = test->range_min,
                                   .range_max = test->range_max,
                                   .min = test->min,
                                   .max = test->max,
                                   .sparsity = test->sparsity},
      status);
}

static const char *
_test_expectError32 (void *tests, size_t idx)
{
   BSON_ASSERT_PARAM (tests);
   return ((Int32Test *) tests + idx)->expectError;
}

static const char *
_test_expectError64 (void *tests, size_t idx)
{
   BSON_ASSERT_PARAM (tests);
   return ((Int64Test *) tests + idx)->expectError;
}

static void
_test_expectMincover_init32 (void *tests, size_t idx)
{
   BSON_ASSERT_PARAM (tests);
   Int32Test *const test = (Int32Test *) tests + idx;
   expectMincover_init (&test->expectMincover, test->expectMincoverString);
}

static void
_test_expectMincover_init64 (void *tests, size_t idx)
{
   BSON_ASSERT_PARAM (tests);
   Int64Test *const test = (Int64Test *) tests + idx;
   expectMincover_init (&test->expectMincover, test->expectMincoverString);
}

static mc_array_t *
_test_expectMincover32 (void *tests, size_t idx)
{
   BSON_ASSERT_PARAM (tests);
   return &((Int32Test *) tests + idx)->expectMincover;
}

static mc_array_t *
_test_expectMincover64 (void *tests, size_t idx)
{
   BSON_ASSERT_PARAM (tests);
   return &((Int64Test *) tests + idx)->expectMincover;
}

static void
_test_dump_32 (void *tests, size_t idx, mc_mincover_t *got)
{
   BSON_ASSERT_PARAM (tests);
   Int32Test *const test = (Int32Test *) tests + idx;
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
   fprintf (stderr, " sparsity=%zu\n", test->sparsity);
   fprintf (stderr, "mincover expected ... begin\n");
   fprintf (stderr, "%s", test->expectMincoverString);
   fprintf (stderr, "mincover expected ... end\n");
   fprintf (stderr, "mincover got ... begin\n");
   for (size_t i = 0; i < mc_mincover_len (got); i++) {
      fprintf (stderr, "  %s\n", mc_mincover_get (got, i));
   }
   fprintf (stderr, "mincover got ... end\n");
}

static void
_test_dump_64 (void *tests, size_t idx, mc_mincover_t *got)
{
   BSON_ASSERT_PARAM (tests);
   Int64Test *const test = (Int64Test *) tests + idx;
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
_test_getMincover_impl (void *tests,
                        size_t num_tests,
                        _test_getMincover_args args)
{
   BSON_ASSERT_PARAM (tests);

   for (size_t i = 0; i < num_tests; i++) {
      mongocrypt_status_t *const status = mongocrypt_status_new ();
      mc_mincover_t *got = args.getMincover (tests, i, status);
      const char *expectError = args.expectError (tests, i);
      if (expectError) {
         ASSERT_OR_PRINT_MSG (NULL == got, "expected error, got success");
         ASSERT_STATUS_CONTAINS (status, expectError);
         mongocrypt_status_destroy (status);
         continue;
      }
      ASSERT_OK_STATUS (got != NULL, status);

      args.expectMincover_init (tests, i);
      size_t numGot = mc_mincover_len (got);
      mc_array_t *expectMincover = args.expectMincover (tests, i);
      size_t numExpected = expectMincover->len;

      if (numExpected != numGot) {
         args.dump (tests, i, got);
         TEST_ERROR ("test %zu: got %zu mincover, expected %zu mincover\n",
                     i,
                     numGot,
                     numExpected);
      }

      for (size_t gotI = 0; gotI < numGot; gotI++) {
         const char *edgeGot = mc_mincover_get (got, gotI);
         const char *edgeExpected =
            _mc_array_index (expectMincover, const char *, gotI);
         if (0 == strcmp (edgeGot, edgeExpected)) {
            continue;
         }
         args.dump (tests, i, got);
         TEST_ERROR ("test %zu: edge mismatch at index %zu. %s != %s\n",
                     i,
                     gotI,
                     edgeGot,
                     edgeExpected);
      }

      expectMincover_cleanup (expectMincover);
      mc_mincover_destroy (got);
      mongocrypt_status_destroy (status);
   }
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

   _test_getMincover_impl (
      tests,
      sizeof (tests) / sizeof (tests[0]),
      (_test_getMincover_args){.getMincover = _test_getMincover32,
                               .expectMincover_init =
                                  _test_expectMincover_init32,
                               .expectMincover = _test_expectMincover32,
                               .expectError = _test_expectError32,
                               .dump = _test_dump_32});
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

   _test_getMincover_impl (
      tests,
      sizeof (tests) / sizeof (tests[0]),
      (_test_getMincover_args){.getMincover = _test_getMincover64,
                               .expectMincover_init =
                                  _test_expectMincover_init64,
                               .expectMincover = _test_expectMincover64,
                               .expectError = _test_expectError64,
                               .dump = _test_dump_64});
}

void
_mongocrypt_tester_install_range_mincover (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_getMincoverInt32);
   INSTALL_TEST (_test_getMincoverInt64);
}

MC_END_CONVERSION_ERRORS
