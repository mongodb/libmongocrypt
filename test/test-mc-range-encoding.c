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
#include "mc-range-encoding-private.h"

/* Enable -Wconversion for only this file.
 * Other libmongocrypt files warn for -Wconversion. */
MC_BEGIN_CHECK_CONVERSIONS

typedef struct {
   mc_getTypeInfo32_args_t args;
   mc_OSTType_Int32 expect;
   const char *expectError;
} Int32Test;

static void
_test_RangeTest_Encode_Int32 (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   Int32Test tests[] = {
      /* Test cases copied from server Int32_NoBounds test ... begin */
      {.args = {.value = 2147483647},
       .expect = {.value = 4294967295, .min = 0, .max = UINT32_MAX}},
      {.args = {.value = 1},
       .expect = {.value = 2147483649, .min = 0, .max = UINT32_MAX}},
      {.args = {.value = 0},
       .expect = {.value = 2147483648, .min = 0, .max = UINT32_MAX}},
      {.args = {.value = -1},
       .expect = {.value = 2147483647, .min = 0, .max = UINT32_MAX}},
      {.args = {.value = -2},
       .expect = {.value = 2147483646, .min = 0, .max = UINT32_MAX}},
      {.args = {.value = -2147483647},
       .expect = {.value = 1, .min = 0, .max = UINT32_MAX}},
      {.args = {.value = INT32_MIN},
       .expect = {.value = 0, .min = 0, .max = UINT32_MAX}},
      /* Test cases copied from server Int32_NoBounds test ... end */
      /* Test cases copied from server Int32_Bounds test .. begin */
      {.args = {.value = 1, .min = OPT_I32 (1), .max = OPT_I32 (3)},
       .expect = {.value = 0, 0, .max = 2}},
      {.args = {.value = 0, .min = OPT_I32 (0), .max = OPT_I32 (1)},
       .expect = {.value = 0, .min = 0, .max = 1}},
      {.args = {.value = -1, .min = OPT_I32 (-1), .max = OPT_I32 (0)},
       .expect = {.value = 0, .min = 0, .max = 1}},
      {.args = {.value = -2, .min = OPT_I32 (-2), .max = OPT_I32 (0)},
       .expect = {.value = 0, .min = 0, .max = 2}},
      {.args = {.value = -2147483647,
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (1)},
       .expect = {.value = 1, .min = 0, .max = 2147483649}},
      {.args = {.value = INT32_MIN,
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (0)},
       .expect = {.value = 0, .min = 0, .max = 2147483648}},
      {.args = {.value = 0, .min = OPT_I32 (INT32_MIN), .max = OPT_I32 (1)},
       .expect = {.value = 2147483648, .min = 0, .max = 2147483649}},
      {.args = {.value = 1, .min = OPT_I32 (INT32_MIN), .max = OPT_I32 (2)},
       .expect = {.value = 2147483649, .min = 0, .max = 2147483650}},
      {.args = {.value = 2147483647,
                .min = OPT_I32 (-2147483647),
                .max = OPT_I32 (2147483647)},
       .expect = {.value = 4294967294, .min = 0, .max = 4294967294}},
      {.args = {.value = 2147483647,
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (2147483647)},
       .expect = {.value = 4294967295, .min = 0, .max = 4294967295}},
      {.args = {.value = 15, .min = OPT_I32 (10), .max = OPT_I32 (26)},
       .expect = {.value = 5, .min = 0, .max = 16}},
      {.args = {.value = 15, .min = OPT_I32 (-10), .max = OPT_I32 (55)},
       .expect = {.value = 25, .min = 0, .max = 65}},
      /* Test cases copied from server Int32_Bounds test ... end */
      /* Test cases copied from server Int32_Errors test ... begin */
      {.args = {.value = 1, .max = OPT_I32 (2)},
       .expectError =
          "Must specify both a lower and upper bound or no bounds."},
      {.args = {.value = 1, .min = OPT_I32 (0)},
       .expectError =
          "Must specify both a lower and upper bound or no bounds."},
      {.args = {.value = 1, .min = OPT_I32 (2), .max = OPT_I32 (1)},
       .expectError = "The minimum value must be less than the maximum value"},
      {.args = {.value = 1, .min = OPT_I32 (2), .max = OPT_I32 (3)},
       .expectError = "Value must be greater than or equal to the minimum "
                      "value and less than or equal to the maximum value"},
      {.args = {.value = 4, .min = OPT_I32 (2), .max = OPT_I32 (3)},
       .expectError = "Value must be greater than or equal to the minimum "
                      "value and less than or equal to the maximum value"},
      {.args = {.value = 4,
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (INT32_MIN)},
       .expectError = "The minimum value must be less than the maximum value"},
      /* Test cases copied from server Int32_Errors test ... end */
   };

   status = mongocrypt_status_new ();

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      Int32Test *test = tests + i;

      // Print a description of the test case.
      printf ("_test_RangeTest_Encode_Int32: value=%" PRId32, test->args.value);
      if (test->args.min.set) {
         printf (" min=%" PRId32, test->args.min.value);
      }
      if (test->args.max.set) {
         printf (" max=%" PRId32, test->args.max.value);
      }
      printf ("\n");
      mc_OSTType_Int32 got;
      bool ok = mc_getTypeInfo32 (test->args, &got, status);
      if (NULL != test->expectError) {
         ASSERT_OR_PRINT_MSG (!ok, "expected error, but got none");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
         continue;
      }
      ASSERT_OK_STATUS (ok, status);
      ASSERT_CMPUINT32 (got.value, ==, test->expect.value);
      ASSERT_CMPUINT32 (got.min, ==, test->expect.min);
      ASSERT_CMPUINT32 (got.max, ==, test->expect.max);
   }

   mongocrypt_status_destroy (status);
}

typedef struct {
   mc_getTypeInfo64_args_t args;
   mc_OSTType_Int64 expect;
   const char *expectError;
} Int64Test;

static void
_test_RangeTest_Encode_Int64 (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   Int64Test tests[] = {
      /* Test cases copied from server Int64_NoBounds test ... begin */
      {.args = {.value = 9223372036854775807LL},
       .expect = {.value = 18446744073709551615ULL,
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = 1},
       .expect = {.value = 9223372036854775809ULL,
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = 0},
       .expect = {.value = 9223372036854775808ULL,
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = -1},
       .expect = {.value = 9223372036854775807ULL,
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = -2},
       .expect = {.value = 9223372036854775806ULL,
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = -9223372036854775807LL},
       .expect = {.value = 1, .min = 0, .max = UINT64_MAX}},
      {.args = {.value = INT64_MIN},
       .expect = {.value = 0, .min = 0, .max = UINT64_MAX}},
      /* Test cases copied from server Int64_NoBounds test ... end */
      /* Test cases copied from server Int64_Bounds test ... begin */
      {.args = {.value = 1, .min = OPT_I64 (1), .max = OPT_I64 (2)},
       .expect = {.value = 0, .min = 0, .max = 1}},
      {.args = {.value = 0, .min = OPT_I64 (0), .max = OPT_I64 (1)},
       .expect = {.value = 0, .min = 0, .max = 1}},
      {.args = {.value = -1, .min = OPT_I64 (-1), .max = OPT_I64 (0)},
       .expect = {.value = 0, .min = 0, .max = 1}},
      {.args = {.value = -2, .min = OPT_I64 (-2), .max = OPT_I64 (0)},
       .expect = {.value = 0, .min = 0, .max = 2}},
      {.args = {.value = -9223372036854775807LL,
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (1)},
       .expect = {.value = 1, .min = 0, .max = 9223372036854775809ULL}},
      {.args = {.value = INT64_MIN,
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (0)},
       .expect = {.value = 0, .min = 0, .max = 9223372036854775808ULL}},
      {.args = {.value = 0, .min = OPT_I64 (INT64_MIN), .max = OPT_I64 (37)},
       .expect = {.value = 9223372036854775808ULL,
                  .min = 0,
                  .max = 9223372036854775845ULL}},
      {.args = {.value = 1, .min = OPT_I64 (INT64_MIN), .max = OPT_I64 (42)},
       .expect = {.value = 9223372036854775809ULL,
                  .min = 0,
                  .max = 9223372036854775850ULL}},
      {.args = {.value = 9223372036854775807,
                .min = OPT_I64 (-9223372036854775807),
                .max = OPT_I64 (9223372036854775807)},
       .expect = {.value = 18446744073709551614ULL,
                  .min = 0,
                  .max = 18446744073709551614ULL}},
      {.args = {.value = 9223372036854775807,
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (9223372036854775807)},
       .expect = {.value = 18446744073709551615ULL,
                  .min = 0,
                  .max = 18446744073709551615ULL}},
      {.args = {.value = 15, .min = OPT_I64 (10), .max = OPT_I64 (26)},
       .expect = {.value = 5, .min = 0, .max = 16}},
      {.args = {.value = 15, .min = OPT_I64 (-10), .max = OPT_I64 (55)},
       .expect = {.value = 25, .min = 0, .max = 65}},
      /* Test cases copied from server Int64_Bounds test ... end */
      /* Test cases copied from server Int64_Errors test ... begin */
      {.args = {.value = 1, .max = OPT_I64 (2)},
       .expectError =
          "Must specify both a lower and upper bound or no bounds."},
      {.args = {.value = 1, .min = OPT_I64 (0)},
       .expectError =
          "Must specify both a lower and upper bound or no bounds."},
      {.args = {.value = 1, .min = OPT_I64 (2), .max = OPT_I64 (1)},
       .expectError = "The minimum value must be less than the maximum value"},
      {.args = {.value = 1, .min = OPT_I64 (2), .max = OPT_I64 (3)},
       .expectError = "Value must be greater than or equal to the minimum "
                      "value and less than or equal to the maximum value"},
      {.args = {.value = 4, .min = OPT_I64 (2), .max = OPT_I64 (3)},
       .expectError = "Value must be greater than or equal to the minimum "
                      "value and less than or equal to the maximum value"},
      {.args = {.value = 4,
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (INT64_MIN)},
       .expectError = "The minimum value must be less than the maximum value"},
      /* Test cases copied from server Int64_Errors test ... end */
   };

   status = mongocrypt_status_new ();

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      Int64Test *test = tests + i;

      // Print a description of the test case.
      printf ("_test_RangeTest_Encode_Int64: value=%" PRId64, test->args.value);
      if (test->args.min.set) {
         printf (" min=%" PRId64, test->args.min.value);
      }
      if (test->args.max.set) {
         printf (" max=%" PRId64, test->args.max.value);
      }
      printf ("\n");
      mc_OSTType_Int64 got;
      bool ok = mc_getTypeInfo64 (test->args, &got, status);
      if (NULL != test->expectError) {
         ASSERT_OR_PRINT_MSG (!ok, "expected error, but got none");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
         continue;
      }
      ASSERT_OK_STATUS (ok, status);
      ASSERT_CMPUINT64 (got.value, ==, test->expect.value);
      ASSERT_CMPUINT64 (got.min, ==, test->expect.min);
      ASSERT_CMPUINT64 (got.max, ==, test->expect.max);
   }

   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_range_encoding (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_RangeTest_Encode_Int32);
   INSTALL_TEST (_test_RangeTest_Encode_Int64);
}

MC_END_CHECK_CONVERSIONS
