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

#include <float.h> // DBL_MAX
#include <math.h>  // INFINITY, NAN

typedef struct {
   mc_getTypeInfo32_args_t args;
   mc_OSTType_Int32 expect;
   const char *expectError;
} Int32Test;

static void
_test_RangeTest_Encode_Int32 (_mongocrypt_tester_t *tester)
{
   Int32Test tests[] = {
      /* Test cases copied from server Int32_NoBounds test ... begin */
      {.args = {.value = INT32_C (2147483647)},
       .expect = {.value = UINT32_C (4294967295), .min = 0, .max = UINT32_MAX}},
      {.args = {.value = 1},
       .expect = {.value = UINT32_C (2147483649), .min = 0, .max = UINT32_MAX}},
      {.args = {.value = 0},
       .expect = {.value = UINT32_C (2147483648), .min = 0, .max = UINT32_MAX}},
      {.args = {.value = -1},
       .expect = {.value = UINT32_C (2147483647), .min = 0, .max = UINT32_MAX}},
      {.args = {.value = -2},
       .expect = {.value = UINT32_C (2147483646), .min = 0, .max = UINT32_MAX}},
      {.args = {.value = INT32_C (-2147483647)},
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
      {.args = {.value = INT32_C (-2147483647),
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (1)},
       .expect = {.value = 1, .min = 0, .max = UINT32_C (2147483649)}},
      {.args = {.value = INT32_MIN,
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (0)},
       .expect = {.value = 0, .min = 0, .max = UINT32_C (2147483648)}},
      {.args = {.value = 0, .min = OPT_I32 (INT32_MIN), .max = OPT_I32 (1)},
       .expect = {.value = UINT32_C (2147483648),
                  .min = 0,
                  .max = UINT32_C (2147483649)}},
      {.args = {.value = 1, .min = OPT_I32 (INT32_MIN), .max = OPT_I32 (2)},
       .expect = {.value = UINT32_C (2147483649),
                  .min = 0,
                  .max = UINT32_C (2147483650)}},
      {.args = {.value = INT32_C (2147483647),
                .min = OPT_I32 (-2147483647),
                .max = OPT_I32 (2147483647)},
       .expect = {.value = UINT32_C (4294967294),
                  .min = 0,
                  .max = UINT32_C (4294967294)}},
      {.args = {.value = INT32_C (2147483647),
                .min = OPT_I32 (INT32_MIN),
                .max = OPT_I32 (2147483647)},
       .expect = {.value = UINT32_C (4294967295),
                  .min = 0,
                  .max = UINT32_C (4294967295)}},
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

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      Int32Test *test = tests + i;
      mongocrypt_status_t *const status = mongocrypt_status_new ();

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
      const bool ok = mc_getTypeInfo32 (test->args, &got, status);
      if (test->expectError) {
         ASSERT_OR_PRINT_MSG (!ok, "expected error, but got none");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
      } else {
         ASSERT_OK_STATUS (ok, status);
         ASSERT_CMPUINT32 (got.value, ==, test->expect.value);
         ASSERT_CMPUINT32 (got.min, ==, test->expect.min);
         ASSERT_CMPUINT32 (got.max, ==, test->expect.max);
      }
      mongocrypt_status_destroy (status);
   }
}

typedef struct {
   mc_getTypeInfo64_args_t args;
   mc_OSTType_Int64 expect;
   const char *expectError;
} Int64Test;

static void
_test_RangeTest_Encode_Int64 (_mongocrypt_tester_t *tester)
{
   Int64Test tests[] = {
      /* Test cases copied from server Int64_NoBounds test ... begin */
      {.args = {.value = INT64_C (9223372036854775807)},
       .expect = {.value = UINT64_C (18446744073709551615),
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = 1},
       .expect = {.value = UINT64_C (9223372036854775809),
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = 0},
       .expect = {.value = UINT64_C (9223372036854775808),
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = -1},
       .expect = {.value = UINT64_C (9223372036854775807),
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = -2},
       .expect = {.value = UINT64_C (9223372036854775806),
                  .min = 0,
                  .max = UINT64_MAX}},
      {.args = {.value = INT64_C (-9223372036854775807)},
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
      {.args = {.value = INT64_C (-9223372036854775807),
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (1)},
       .expect = {.value = 1, .min = 0, .max = UINT64_C (9223372036854775809)}},
      {.args = {.value = INT64_MIN,
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (0)},
       .expect = {.value = 0, .min = 0, .max = UINT64_C (9223372036854775808)}},
      {.args = {.value = 0, .min = OPT_I64 (INT64_MIN), .max = OPT_I64 (37)},
       .expect = {.value = UINT64_C (9223372036854775808),
                  .min = 0,
                  .max = UINT64_C (9223372036854775845)}},
      {.args = {.value = 1, .min = OPT_I64 (INT64_MIN), .max = OPT_I64 (42)},
       .expect = {.value = UINT64_C (9223372036854775809),
                  .min = 0,
                  .max = UINT64_C (9223372036854775850)}},
      {.args = {.value = INT64_C (9223372036854775807),
                .min = OPT_I64 (-9223372036854775807),
                .max = OPT_I64 (9223372036854775807)},
       .expect = {.value = UINT64_C (18446744073709551614),
                  .min = 0,
                  .max = UINT64_C (18446744073709551614)}},
      {.args = {.value = INT64_C (9223372036854775807),
                .min = OPT_I64 (INT64_MIN),
                .max = OPT_I64 (9223372036854775807)},
       .expect = {.value = UINT64_C (18446744073709551615),
                  .min = 0,
                  .max = UINT64_C (18446744073709551615)}},
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

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      Int64Test *test = tests + i;
      mongocrypt_status_t *const status = mongocrypt_status_new ();

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
      const bool ok = mc_getTypeInfo64 (test->args, &got, status);
      if (test->expectError) {
         ASSERT_OR_PRINT_MSG (!ok, "expected error, but got none");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
      } else {
         ASSERT_OK_STATUS (ok, status);
         ASSERT_CMPUINT64 (got.value, ==, test->expect.value);
         ASSERT_CMPUINT64 (got.min, ==, test->expect.min);
         ASSERT_CMPUINT64 (got.max, ==, test->expect.max);
      }
      mongocrypt_status_destroy (status);
   }
}

typedef struct {
   double value;
   mc_optional_double_t min;
   mc_optional_double_t max;
   mc_optional_uint32_t precision;
   uint64_t expect;
   mc_optional_uint64_t expectMax;
   const char *expectError;
} DoubleTest;

static void
_test_RangeTest_Encode_Double (_mongocrypt_tester_t *tester)
{
   DoubleTest tests[] = {
      /* Test cases copied from server Double_Bounds test ... begin */
      // Larger numbers map to larger uint64
      {.value = -1111, .expect = UINT64_C (4570770991734587392)},
      {.value = -111, .expect = UINT64_C (4585860689314185216)},
      {.value = -11, .expect = UINT64_C (4600989969312382976)},
      {.value = -10, .expect = UINT64_C (4601552919265804288)},
      {.value = -3, .expect = UINT64_C (4609434218613702656)},
      {.value = -2, .expect = UINT64_C (4611686018427387904)},

      {.value = -1, .expect = UINT64_C (4616189618054758400)},
      {.value = 1, .expect = UINT64_C (13830554455654793216)},
      {.value = 22, .expect = UINT64_C (13850257704024539136)},
      {.value = 333, .expect = UINT64_C (13867937850999177216)},

      // Larger exponents map to larger uint64
      {.value = 33E56, .expect = UINT64_C (14690973652625833878)},
      {.value = 22E57, .expect = UINT64_C (14703137697061005818)},
      {.value = 11E58, .expect = UINT64_C (14713688953586463292)},

      // Smaller exponents map to smaller uint64
      {.value = 1E-6, .expect = UINT64_C (13740701229962882445)},
      {.value = 1E-7, .expect = UINT64_C (13725520251343122248)},
      {.value = 1E-8, .expect = UINT64_C (13710498295186492474)},
      {.value = 1E-56, .expect = UINT64_C (12992711961033031890)},
      {.value = 1E-57, .expect = UINT64_C (12977434315086142017)},
      {.value = 1E-58, .expect = UINT64_C (12962510038552207822)},

      // Smaller negative exponents map to smaller uint64
      {.value = -1E-06, .expect = UINT64_C (4706042843746669171)},
      {.value = -1E-07, .expect = UINT64_C (4721223822366429368)},
      {.value = -1E-08, .expect = UINT64_C (4736245778523059142)},
      {.value = -1E-56, .expect = UINT64_C (5454032112676519726)},
      {.value = -1E-57, .expect = UINT64_C (5469309758623409599)},
      {.value = -1E-58, .expect = UINT64_C (5484234035157343794)},

      // Larger exponents map to larger uint64
      {.value = -33E+56, .expect = UINT64_C (3755770421083717738)},
      {.value = -22E+57, .expect = UINT64_C (3743606376648545798)},
      {.value = -11E+58, .expect = UINT64_C (3733055120123088324)},

      {.value = 0, .expect = UINT64_C (9223372036854775808)},
      {.value = -0.0, .expect = UINT64_C (9223372036854775808)},
      /* Test cases copied from server Double_Bounds test ... end */
      /* Test cases copied from server Double_Errors test ... begin */
      {.value = INFINITY,
       .expectError = "Infinity and NaN double values are not supported."},
      {.value = NAN,
       .expectError = "Infinity and NaN double values are not supported."},
      /* Test cases copied from server Double_Errors test ... end */

      /* Test cases copied from Double_Bounds_Precision ... begin */
      {.value = 3.141592653589,
       .precision = OPT_U32_C (1),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = UINT64_C (1000031),
       .expectMax = OPT_U64_C (2097151)},
      {.value = 3.141592653589,
       .precision = OPT_U32_C (2),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = 10000314,
       .expectMax = OPT_U64_C (33554431)},
      {.value = 3.141592653589,
       .precision = OPT_U32_C (3),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = 100003141,
       .expectMax = OPT_U64_C (268435455)},
      {.value = 3.141592653589,
       .precision = OPT_U32_C (4),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = 1000031415,
       .expectMax = OPT_U64_C (2147483647)},
      {.value = 3.141592653589,
       .precision = OPT_U32_C (5),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = 10000314159,
       .expectMax = OPT_U64_C (34359738367)},
      {.value = 3.141592653589,
       .precision = OPT_U32_C (6),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = 100003141592,
       .expectMax = OPT_U64_C (274877906943)},
      {.value = 3.141592653589,
       .precision = OPT_U32_C (7),
       .min = OPT_DOUBLE_C (-100000),
       .max = OPT_DOUBLE_C (100000),
       .expect = 1000031415926,
       .expectMax = OPT_U64_C (2199023255551)},
      {.value = 0,
       .max = OPT_DOUBLE_C (1),
       .min = OPT_DOUBLE_C (-1),
       .precision = OPT_U32_C (3),
       .expect = 1000,
       .expectMax = OPT_U64_C (4095)},
      {.value = 0,
       .max = OPT_DOUBLE_C (1),
       .min = OPT_DOUBLE_C (-1E5),
       .precision = OPT_U32_C (3),
       .expect = 100000000,
       .expectMax = OPT_U64_C (134217727)},
      {.value = -1E-33,
       .max = OPT_DOUBLE_C (1),
       .min = OPT_DOUBLE_C (-1E5),
       .precision = OPT_U32_C (3),
       .expect = 100000000,
       .expectMax = OPT_U64_C (134217727)},
      {.value = 0,
       .max = OPT_DOUBLE_C (DBL_MAX),
       .min = OPT_DOUBLE_C (-DBL_MAX),
       .precision = OPT_U32_C (3),
       .expect = UINT64_C (9223372036854775808),
       // Expect precision not to be used.
       .expectMax = OPT_U64_C (UINT64_MAX)},
      {.value = 3.141592653589,
       .max = OPT_DOUBLE_C (5),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (0),
       .expect = 3,
       .expectMax = OPT_U64_C (7)},
      {.value = 3.141592653589,
       .max = OPT_DOUBLE_C (5),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (1),
       .expect = 31,
       .expectMax = OPT_U64_C (63)},
      {.value = 3.141592653589,
       .max = OPT_DOUBLE_C (5),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (2),
       .expect = 314,
       .expectMax = OPT_U64_C (1023)},
      {.value = 3.141592653589,
       .max = OPT_DOUBLE_C (5),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (3),
       .expect = 3141,
       .expectMax = OPT_U64_C (8191)},
      {.value = 3.141592653589,
       .max = OPT_DOUBLE_C (5),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (16),
       .expect = 31415926535890000,
       .expectMax = OPT_U64_C (72057594037927935)},
      {.value = -5,
       .max = OPT_DOUBLE_C (-1),
       .min = OPT_DOUBLE_C (-10),
       .precision = OPT_U32_C (3),
       .expect = 5000,
       .expectMax = OPT_U64_C (16383)},
      {.value = 1E100,
       .max = OPT_DOUBLE_C (DBL_MAX),
       .min = OPT_DOUBLE_C (-DBL_MAX),
       .precision = OPT_U32_C (3),
       .expect = 15326393489903895421ULL,
       // Expect precision not to be used.
       .expectMax = OPT_U64_C (UINT64_MAX)},
      {.value = 1E9,
       .max = OPT_DOUBLE_C (1E10),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (3),
       .expect = 1000000000000,
       .expectMax = OPT_U64_C (17592186044415)},
      {.value = 1E9,
       .max = OPT_DOUBLE_C (1E10),
       .min = OPT_DOUBLE_C (0),
       .precision = OPT_U32_C (0),
       .expect = 1000000000,
       .expectMax = OPT_U64_C (17179869183)},
      {.value = -5,
       .max = OPT_DOUBLE_C (10),
       .min = OPT_DOUBLE_C (-10),
       .precision = OPT_U32_C (0),
       .expect = 5,
       .expectMax = OPT_U64_C (31)},
      {.value = -5,
       .max = OPT_DOUBLE_C (10),
       .min = OPT_DOUBLE_C (-10),
       .precision = OPT_U32_C (2),
       .expect = 500,
       .expectMax = OPT_U64_C (4095)},
      {.value = 1E-30,
       .max = OPT_DOUBLE_C (10E-30),
       .min = OPT_DOUBLE_C (1E-30),
       .precision = OPT_U32_C (35),
       .expect = 13381399884061196960ULL,
       // Expect precision not to be used.
       .expectMax = OPT_U64_C (UINT64_MAX)},
      /* Test cases copied from Double_Bounds_Precision ... end */
      {.value = -1,
       .min = OPT_DOUBLE_C (0),
       .max = OPT_DOUBLE_C (200),
       .precision = OPT_U32_C (1),
       .expectError = "greater than or equal to the minimum value"},
      {.value = -1,
       .min = OPT_DOUBLE_C (0),
       .max = OPT_DOUBLE_C (201),
       .precision = OPT_U32_C (1),
       .expectError = "less than or equal to the maximum value"}};

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      DoubleTest *test = tests + i;
      mongocrypt_status_t *const status = mongocrypt_status_new ();

      if (test->min.set && test->max.set && test->precision.set) {
         printf ("_test_RangeTest_Encode_Double: value=%f, min=%f, max=%f, "
                 "precision=%" PRIu32 "\n",
                 test->value,
                 test->min.value,
                 test->max.value,
                 test->precision.value);
      } else {
         printf ("_test_RangeTest_Encode_Double: value=%f\n", test->value);
      }

      mc_OSTType_Double got;
      const bool ok = mc_getTypeInfoDouble (
         (mc_getTypeInfoDouble_args_t){.value = test->value,
                                       .min = test->min,
                                       .max = test->max,
                                       .precision = test->precision},
         &got,
         status);
      if (test->expectError) {
         ASSERT_OR_PRINT_MSG (!ok, "expected error, but got none");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
      } else {
         ASSERT_OK_STATUS (ok, status);
         ASSERT_CMPUINT64 (got.value, ==, test->expect);
         ASSERT_CMPUINT64 (got.min, ==, 0);
         ASSERT_CMPUINT64 (got.max,
                           ==,
                           test->expectMax.set ? test->expectMax.value
                                               : UINT64_MAX);
      }
      mongocrypt_status_destroy (status);
   }
}


typedef struct {
   mc_dec128 value;
   mc_optional_dec128_t min;
   mc_optional_dec128_t max;
   mc_optional_uint32_t precision;
   mlib_int128 expect;
   mc_optional_int128_t expectMax;
   const char *expectError;
} Decimal128Test;

static void
_test_RangeTest_Encode_Decimal128 (_mongocrypt_tester_t *tester)
{
   Decimal128Test tests[] = {
#define CASE(Value, ExpectStr)                               \
   (Decimal128Test){.value = mc_dec128_from_string (#Value), \
                    .expect = mlib_int128_from_string (ExpectStr, NULL)}
      /* Test cases copied from server Decimal128_Bounds test ... begin */
      // Larger numbers map to larger int128
      CASE (-1234567890E7, "108549948892579231731687303715884111887"),
      CASE (-1234567890E6, "108559948892579231731687303715884111886"),
      CASE (-1234567890E5, "108569948892579231731687303715884111885"),
      CASE (-1234567890E4, "108579948892579231731687303715884111884"),
      CASE (-1234567890E3, "108589948892579231731687303715884111883"),
      CASE (-1234567890E2, "108599948892579231731687303715884111882"),
      CASE (-1234567890E1, "108609948892579231731687303715884111881"),
      CASE (-123456789012345, "108569948892579108281687303715884111885"),
      CASE (-12345678901234, "108579948892579108331687303715884111884"),
      CASE (-1234567890123, "108589948892579108731687303715884111883"),
      CASE (-123456789012, "108599948892579111731687303715884111882"),
      CASE (-12345678901, "108609948892579131731687303715884111881"),
      CASE (-1234567890, "108619948892579231731687303715884111880"),
      CASE (-99999999, "108631183460569231731687303715884111878"),
      CASE (-8888888, "108642294572469231731687303715884111877"),
      CASE (-777777, "108653405690469231731687303715884111876"),
      CASE (-66666, "108664516860469231731687303715884111875"),
      CASE (-5555, "108675628460469231731687303715884111874"),
      CASE (-444, "108686743460469231731687303715884111873"),
      CASE (-334, "108687843460469231731687303715884111873"),
      CASE (-333, "108687853460469231731687303715884111873"),
      CASE (-44, "108696783460469231731687303715884111872"),
      CASE (-33, "108697883460469231731687303715884111872"),
      CASE (-22, "108698983460469231731687303715884111872"),
      CASE (-5, "108706183460469231731687303715884111871"),
      CASE (-4, "108707183460469231731687303715884111871"),
      CASE (-3, "108708183460469231731687303715884111871"),
      CASE (-2, "108709183460469231731687303715884111871"),
      CASE (-1, "108710183460469231731687303715884111871"),
      CASE (0, "170141183460469231731687303715884105728"),
      CASE (1, "231572183460469231731687303715884099585"),
      CASE (2, "231573183460469231731687303715884099585"),
      CASE (3, "231574183460469231731687303715884099585"),
      CASE (4, "231575183460469231731687303715884099585"),
      CASE (5, "231576183460469231731687303715884099585"),
      CASE (22, "231583383460469231731687303715884099584"),
      CASE (33, "231584483460469231731687303715884099584"),
      CASE (44, "231585583460469231731687303715884099584"),
      CASE (333, "231594513460469231731687303715884099583"),
      CASE (334, "231594523460469231731687303715884099583"),
      CASE (444, "231595623460469231731687303715884099583"),
      CASE (5555, "231606738460469231731687303715884099582"),
      CASE (66666, "231617850060469231731687303715884099581"),
      CASE (777777, "231628961230469231731687303715884099580"),
      CASE (8888888, "231640072348469231731687303715884099579"),
      CASE (33E56, "232144483460469231731687303715884099528"),
      CASE (22E57, "232153383460469231731687303715884099527"),
      CASE (11E58, "232162283460469231731687303715884099526"),

      // Smaller exponents map to smaller int128
      CASE (1E-6, "231512183460469231731687303715884099591"),
      CASE (1E-7, "231502183460469231731687303715884099592"),
      CASE (1E-8, "231492183460469231731687303715884099593"),
      CASE (1E-56, "231012183460469231731687303715884099641"),
      CASE (1E-57, "231002183460469231731687303715884099642"),
      CASE (1E-58, "230992183460469231731687303715884099643"),

      // Smaller negative exponents map to smaller int128
      CASE (-1E-6, "108770183460469231731687303715884111865"),
      CASE (-1E-7, "108780183460469231731687303715884111864"),
      CASE (-1E-8, "108790183460469231731687303715884111863"),
      CASE (-1E-56, "109270183460469231731687303715884111815"),
      CASE (-1E-57, "109280183460469231731687303715884111814"),
      CASE (-1E-58, "109290183460469231731687303715884111813"),

      // Larger exponents map to larger int128
      CASE (-33E56, "108137883460469231731687303715884111928"),
      CASE (-22E57, "108128983460469231731687303715884111929"),
      CASE (-11E58, "108120083460469231731687303715884111930"),

      (Decimal128Test){.value = MC_DEC128_LARGEST_POSITIVE,
                       .expect = mlib_int128_from_string (
                          "293021183460469231731687303715884093440", NULL)},
      (Decimal128Test){.value = MC_DEC128_SMALLEST_POSITIVE,
                       .expect = mlib_int128_from_string (
                          "170141183460469231731687303715884105729", NULL)},
      (Decimal128Test){.value = MC_DEC128_LARGEST_NEGATIVE,
                       .expect = mlib_int128_from_string (
                          "47261183460469231731687303715884118016", NULL)},
      (Decimal128Test){.value = MC_DEC128_SMALLEST_NEGATIVE,
                       .expect = mlib_int128_from_string (
                          "170141183460469231731687303715884105727", NULL)},
      (Decimal128Test){.value = MC_DEC128_NORMALIZED_ZERO,
                       .expect = mlib_int128_from_string (
                          "170141183460469231731687303715884105728", NULL)},
      (Decimal128Test){.value = MC_DEC128_NEGATIVE_EXPONENT_ZERO,
                       .expect = mlib_int128_from_string (
                          "170141183460469231731687303715884105728", NULL)},
   /* Test cases copied from server Decimal128_Bounds test ... end */

#define ERROR_CASE(Value, Min, Max, Precision, ErrorString) \
   (Decimal128Test){                                        \
      .value = Value,                                       \
      .min = Min,                                           \
      .max = Max,                                           \
      .precision = Precision,                               \
      .expectError = ErrorString,                           \
   }

      ERROR_CASE (
         MC_DEC128_C (1),
         OPT_NULLOPT,
         OPT_MC_DEC128 (MC_DEC128_C (2)),
         OPT_U32 (5),
         "min, max, and precision must all be set or must all be unset"),
      ERROR_CASE (
         MC_DEC128_C (1),
         OPT_MC_DEC128 (MC_DEC128_C (0)),
         OPT_NULLOPT,
         OPT_U32 (5),
         "min, max, and precision must all be set or must all be unset"),
      ERROR_CASE (MC_DEC128_C (1),
                  OPT_MC_DEC128 (MC_DEC128_C (2)),
                  OPT_MC_DEC128 (MC_DEC128_C (1)),
                  OPT_U32 (5),
                  "The minimum value must be less than the maximum value"),

      ERROR_CASE (MC_DEC128_C (1),
                  OPT_MC_DEC128 (MC_DEC128_C (2)),
                  OPT_MC_DEC128 (MC_DEC128_C (3)),
                  OPT_U32 (5),
                  "Value must be greater than or equal to the minimum value "
                  "and less than or equal to the maximum value"),
      ERROR_CASE (MC_DEC128_C (4),
                  OPT_MC_DEC128 (MC_DEC128_C (2)),
                  OPT_MC_DEC128 (MC_DEC128_C (3)),
                  OPT_U32 (5),
                  "Value must be greater than or equal to the minimum value "
                  "and less than or equal to the maximum value"),

      ERROR_CASE (MC_DEC128_POSITIVE_INFINITY,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  "Infinity and Nan double values are not supported."),
      ERROR_CASE (MC_DEC128_NEGATIVE_INFINITY,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  "Infinity and Nan double values are not supported."),

      ERROR_CASE (MC_DEC128_POSITIVE_NAN,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  "Infinity and Nan double values are not supported."),

      ERROR_CASE (MC_DEC128_NEGATIVE_NAN,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  OPT_NULLOPT,
                  "Infinity and Nan double values are not supported."),

/* Test cases copied from Decimal128_Bounds_Precision ... begin */
#define ASSERT_EIBP(Value, Precision, Expect)       \
   (Decimal128Test){                                \
      .value = mc_dec128_from_string (Value),       \
      .min = OPT_MC_DEC128 (MC_DEC128_C (-100000)), \
      .max = OPT_MC_DEC128 (MC_DEC128_C (100000)),  \
      .precision = OPT_U32 (Precision),             \
      .expect = MLIB_INT128 (Expect),               \
   }
      ASSERT_EIBP ("3.141592653589E-1", 10, 1000003141592653),
      ASSERT_EIBP ("31.41592653589E-2", 10, 1000003141592653),
      ASSERT_EIBP ("314.1592653589E-3", 10, 1000003141592653),
      ASSERT_EIBP ("3141.592653589E-4", 10, 1000003141592653),
      ASSERT_EIBP ("31415.92653589E-5", 10, 1000003141592653),
      ASSERT_EIBP ("314159.2653589E-6", 10, 1000003141592653),
      ASSERT_EIBP ("3141592.653589E-7", 10, 1000003141592653),
      ASSERT_EIBP ("31415926.53589E-8", 10, 1000003141592653),
#undef ASSERT_EIBP

#define ASSERT_EIBPL(Value, Precision, Expect)               \
   (Decimal128Test){                                         \
      .value = mc_dec128_from_string (Value),                \
      .min = OPT_MC_DEC128 (MC_DEC128_C (-100000)),          \
      .max = OPT_MC_DEC128 (mc_dec128_from_string ("1E22")), \
      .precision = OPT_U32 (Precision),                      \
      .expect = mlib_int128_from_string (Expect, NULL),      \
   }

      ASSERT_EIBPL ("3.1415926535897932384626433832795E20",
                    5,
                    "31415926535897942384626433"),
      ASSERT_EIBPL ("3.1415926535897932384626433832795E20",
                    6,
                    "314159265358979423846264338"),

      ASSERT_EIBPL ("3.1415926535897932384626433832795E20",
                    7,
                    "3141592653589794238462643383"),

      ASSERT_EIBPL ("3.1415926535897932384626433832795E20",
                    8,
                    "31415926535897942384626433832"),
#undef ASSERT_EIBPL

#define ASSERT_EIBP(Value, Precision, Expect)       \
   (Decimal128Test){                                \
      .value = mc_dec128_from_string (#Value),      \
      .min = OPT_MC_DEC128 (MC_DEC128_C (-100000)), \
      .max = OPT_MC_DEC128 (MC_DEC128_C (100000)),  \
      .precision = OPT_U32 (Precision),             \
      .expect = MLIB_INT128_CAST (Expect),          \
   }
      ASSERT_EIBP (3.141592653589, 1, 1000031),
      ASSERT_EIBP (3.141592653589, 2, 10000314),
      ASSERT_EIBP (3.141592653589, 3, 100003141),
      ASSERT_EIBP (3.141592653589, 4, 1000031415),
      ASSERT_EIBP (3.141592653589, 5, 10000314159),
      ASSERT_EIBP (3.141592653589, 6, 100003141592),
      ASSERT_EIBP (3.141592653589, 7, 1000031415926),
#undef ASSERT_EIBP

#define ASSERT_EIBB(Val, Max, Min, Precision, Expect)      \
   (Decimal128Test){                                       \
      .value = mc_dec128_from_string (#Val),               \
      .min = OPT_MC_DEC128 (mc_dec128_from_string (#Min)), \
      .max = OPT_MC_DEC128 (mc_dec128_from_string (#Max)), \
      .precision = OPT_U32 (Precision),                    \
      .expect = MLIB_INT128_CAST (Expect),                 \
   }

#define ASSERT_EIBB_OVERFLOW(Val, Max, Min, Precision, Expect) \
   (Decimal128Test)                                            \
   {                                                           \
      .value = mc_dec128_from_string (#Val),                   \
      .min = OPT_MC_DEC128 (mc_dec128_from_string (#Min)),     \
      .max = OPT_MC_DEC128 (mc_dec128_from_string (#Max)),     \
      .precision = OPT_U32 (Precision), .expect = Expect,      \
   }

      ASSERT_EIBB (0, 1, -1, 3, 1000),
      ASSERT_EIBB (0, 1, -1E5, 3, 100000000),

      ASSERT_EIBB (-1E-33, 1, -1E5, 3, 100000000),

      ASSERT_EIBB_OVERFLOW (
         0,
         MC_DEC128_LARGEST_POSITIVE,
         MC_DEC128_LARGEST_NEGATIVE,
         3,
         mlib_int128_from_string ("170141183460469231731687303715884105728",
                                  NULL)),
      ASSERT_EIBB_OVERFLOW (
         0,
         DBL_MAX,
         DBL_MIN,
         3,
         mlib_int128_from_string ("170141183460469231731687303715884105728",
                                  NULL)),

      ASSERT_EIBB (3.141592653589, 5, 0, 0, 3),
      ASSERT_EIBB (3.141592653589, 5, 0, 1, 31),

      ASSERT_EIBB (3.141592653589, 5, 0, 2, 314),

      ASSERT_EIBB (3.141592653589, 5, 0, 3, 3141),
      ASSERT_EIBB (3.141592653589, 5, 0, 16, 31415926535890000),

      ASSERT_EIBB (-5, -1, -10, 3, 5000),

      ASSERT_EIBB_OVERFLOW (
         1E100,
         DBL_MAX,
         DBL_MIN,
         3,
         mlib_int128_from_string ("232572183460469231731687303715884099485",
                                  NULL)),

      ASSERT_EIBB (1E9, 1E10, 0, 3, 1000000000000),
      ASSERT_EIBB (1E9, 1E10, 0, 0, 1000000000),


      ASSERT_EIBB (-5, 10, -10, 0, 5),
      ASSERT_EIBB (-5, 10, -10, 2, 500),

      ASSERT_EIBB (5E-30, 10E-30, 1E-30, 35, 400000),

      // Test a range that requires > 64 bits.
      ASSERT_EIBB (5, 18446744073709551616, .1, 1, 49),
      // Test a range that requires > 64 bits.
      // min has more places after the decimal than precision.
      ASSERT_EIBB (5, 18446744073709551616, .01, 1, 49),

#undef ASSERT_EIBB
#undef ASSERT_EIBB_OVERFLOW

      /* Test cases copied from Decimal128_Bounds_Precision ... end */
   };

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      Decimal128Test *test = tests + i;
      mongocrypt_status_t *const status = mongocrypt_status_new ();

      if (test->min.set && test->max.set && test->precision.set) {
         printf ("_test_RangeTest_Encode_Decimal128: value=%s, min=%s, max=%s, "
                 "precision=%" PRIu32 "\n",
                 mc_dec128_to_string (test->value).str,
                 mc_dec128_to_string (test->min.value).str,
                 mc_dec128_to_string (test->max.value).str,
                 test->precision.value);
      } else {
         printf ("_test_RangeTest_Encode_Decimal128: value=%s\n",
                 mc_dec128_to_string (test->value).str);
      }
      fflush (stdout);
      mc_OSTType_Decimal128 got;
      const bool ok = mc_getTypeInfoDecimal128 (
         (mc_getTypeInfoDecimal128_args_t){.value = test->value,
                                           .min = test->min,
                                           .max = test->max,
                                           .precision = test->precision},
         &got,
         status);
      if (test->expectError) {
         ASSERT_OR_PRINT_MSG (!ok, "expected error, but got none");
         ASSERT_STATUS_CONTAINS (status, test->expectError);
      } else {
         ASSERT_OK_STATUS (ok, status);

         ASSERT_CMPINT128_EQ (got.value, test->expect);
         ASSERT_CMPINT128_EQ (got.min, MLIB_INT128 (0));
         if (test->expectMax.set) {
            ASSERT_CMPINT128_EQ (got.max, test->expectMax.value);
         }
      }
      mongocrypt_status_destroy (status);
   }
}

void
_mongocrypt_tester_install_range_encoding (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_RangeTest_Encode_Int32);
   INSTALL_TEST (_test_RangeTest_Encode_Int64);
   INSTALL_TEST (_test_RangeTest_Encode_Double);
   INSTALL_TEST (_test_RangeTest_Encode_Decimal128);
}
