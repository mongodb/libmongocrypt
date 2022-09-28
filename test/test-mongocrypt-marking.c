/*
 * Copyright 2019-present MongoDB, Inc.
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

/* For each field, check a valid value, invalid value, missing value */

#include "bson/bson.h"
#include "mongocrypt-marking-private.h"
#include "test-mongocrypt.h"


/* Create a basis marking buffer with valid values for the given fields. */
static void
_make_marking (bson_t *bson, _mongocrypt_buffer_t *buf)
{
   buf->len = bson->len + 1;
   buf->data = bson_malloc (buf->len);
   BSON_ASSERT (buf->data);

   buf->data[0] = 0;
   buf->owned = true;
   memcpy (buf->data + 1, bson_get_data (bson), bson->len);
}


static void
_parse_ok (_mongocrypt_buffer_t *marking_buf, _mongocrypt_marking_t *out)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   memset (out, 0, sizeof (*out));
   ASSERT_OK_STATUS (
      _mongocrypt_marking_parse_unowned (marking_buf, out, status), status);

   mongocrypt_status_destroy (status);
}


static void
_parse_fails (_mongocrypt_buffer_t *marking_buf,
              const char *msg,
              _mongocrypt_marking_t *out)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   memset (out, 0, sizeof (*out));
   ASSERT_FAILS_STATUS (
      _mongocrypt_marking_parse_unowned (marking_buf, out, status),
      status,
      msg);

   mongocrypt_status_destroy (status);
}

static void
test_mongocrypt_marking_parse (_mongocrypt_tester_t *tester)
{
   bson_t *marking_bson;
   _mongocrypt_buffer_t marking_buf;
   _mongocrypt_marking_t marking;

   /* successful case. */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_ok (&marking_buf, &marking);
   BSON_ASSERT (marking.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
   BSON_ASSERT (0 == strcmp ("abc", bson_iter_utf8 (&marking.v_iter, NULL)));
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* buffer < 6 bytes */
   marking_buf.data = (uint8_t *) "abc";
   marking_buf.len = 3;
   marking_buf.owned = false;
   _parse_fails (&marking_buf, "invalid marking, length < 6", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* bad first byte */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   marking_buf.data[0] = 1;
   _parse_fails (&marking_buf, "invalid marking", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* unrecognized fields. */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt', 'extra': 1}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "unrecognized field 'extra'", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* malformed BSON. */
   marking_bson = TMP_BSON ("{}");
   ((uint8_t *) bson_get_data (marking_bson))[4] = 0xFF;
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "invalid BSON", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* a: missing */
   marking_bson = TMP_BSON ("{'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "no 'a' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   /* a: wrong type */
   marking_bson = TMP_BSON ("{'a': 'abc', 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (
      &marking_buf, "invalid marking, 'a' must be an int32", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   /* a: wrong integer */
   marking_bson = TMP_BSON ("{'a': -1, 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "invalid algorithm value: -1", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* v: missing */
   marking_bson = TMP_BSON ("{'a': 2, 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "no 'v' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* Not testing IV per CDRIVER-3127. TODO: remove this comment. */

   /* ki+ka: missing */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "neither 'ki' nor 'ka' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   /* ki+ka: both present */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt' }");
   BSON_APPEND_BINARY (
      marking_bson, "ki", BSON_SUBTYPE_UUID, (TEST_BIN (16))->data, 16);
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "both 'ki' and 'ka' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* ki: wrong type */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ki': 'abc' }");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "key id must be a UUID", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* ki: wrong subtype */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc' }");
   BSON_APPEND_BINARY (
      marking_bson, "ki", BSON_SUBTYPE_BINARY, (TEST_BIN (16))->data, 16);
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "key id must be a UUID", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* ka: wrong type */
   marking_bson = TMP_BSON ("{'v': 'abc', 'ka': 1}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "key alt name must be a UTF8", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
}


#define RAW_STRING(...) #__VA_ARGS__

#define ASSERT_MINCOVER_EQ(got, expectString)                                  \
   if (1) {                                                                    \
      bson_string_t *gotStr = bson_string_new ("");                            \
      for (size_t i = 0; i < mc_mincover_len (got); i++) {                     \
         bson_string_append_printf (gotStr, "%s\n", mc_mincover_get (got, i)); \
      }                                                                        \
      ASSERT_STREQUAL (gotStr->str, expectString);                             \
      bson_string_free (gotStr, true);                                         \
   } else                                                                      \
      ((void) 0)

/* test_mc_get_mincover_from_FLE2RangeFindSpec tests processing an
 * FLE2RangeFindSpec into a mincover. It is is analogous to the
 * MinCoverInterfaceTest in the server code:
 * https://github.com/mongodb/mongo/blob/a4a3eba2a0e0a839ca6213491361269b42e12761/src/mongo/crypto/fle_crypto_test.cpp#L2585
 */
static void
test_mc_get_mincover_from_FLE2RangeFindSpec (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status = mongocrypt_status_new ();
   bson_error_t error;

   typedef struct {
      const char *description; // May be NULL.
      const char *findSpecJSON;
      const char *expectedMinCover;
      mc_optional_int64_t sparsity;
   } testcase_t;

   testcase_t tests[] = {
      {.description = "Int32 Bounds included",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberInt" : "7"},
          "lbIncluded" : true,
          "upperBound" : {"$numberInt" : "32"},
          "ubIncluded" : true,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "000111\n"
                           "001\n"
                           "01\n"
                           "100000\n"},

      {.description = "Int32 Bounds excluded",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberInt" : "7"},
          "lbIncluded" : false,
          "upperBound" : {"$numberInt" : "32"},
          "ubIncluded" : false,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "001\n"
                           "01\n"},
      {.description = "Int32 Upper bound excluded",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberInt" : "7"},
          "lbIncluded" : true,
          "upperBound" : {"$numberInt" : "32"},
          "ubIncluded" : false,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "000111\n"
                           "001\n"
                           "01\n"},
      {.description = "Int32 Lower bound excluded",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberInt" : "7"},
          "lbIncluded" : false,
          "upperBound" : {"$numberInt" : "32"},
          "ubIncluded" : true,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "001\n"
                           "01\n"
                           "100000\n"},
      {.description = "Int32 Infinite upper bound",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberInt" : "7"},
          "lbIncluded" : true,
          "upperBound" : {"$numberDouble" : "Infinity"},
          "ubIncluded" : true,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "000111\n"
                           "001\n"
                           "01\n"
                           "100000\n"},
      {.description = "Int32 Infinite lower bound",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberDouble" : "-Infinity"},
          "lbIncluded" : true,
          "upperBound" : {"$numberInt" : "8"},
          "ubIncluded" : true,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "000\n"
                           "001000\n"},
      {.description = "Int32 Infinite both bounds",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberDouble" : "-Infinity"},
          "lbIncluded" : true,
          "upperBound" : {"$numberDouble" : "Infinity"},
          "ubIncluded" : true,
          "indexMin" : {"$numberInt" : "0"},
          "indexMax" : {"$numberInt" : "32"}
       }),
       .expectedMinCover = "0\n"
                           "100000\n"},
      {.description = "Int64 Bounds included",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberLong" : "0"},
          "lbIncluded" : true,
          "upperBound" : {"$numberLong" : "823"},
          "ubIncluded" : true,
          "indexMin" : {"$numberLong" : "-1000000000000000"},
          "indexMax" : {"$numberLong" : "8070450532247928832"}
       }),
       .expectedMinCover =
          "000000000000011100011010111111010100100110001101000000\n"
          "00000000000001110001101011111101010010011000110100000100\n"
          "00000000000001110001101011111101010010011000110100000101\n"
          "0000000000000111000110101111110101001001100011010000011000\n"
          "000000000000011100011010111111010100100110001101000001100100\n"
          "000000000000011100011010111111010100100110001101000001100101\n"
          "000000000000011100011010111111010100100110001101000001100110\n",
       .sparsity = OPT_I64 (2)},

      {.description = "Int64 Bounds excluded",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberLong" : "0"},
          "lbIncluded" : false,
          "upperBound" : {"$numberLong" : "823"},
          "ubIncluded" : false,
          "indexMin" : {"$numberLong" : "-1000000000000000"},
          "indexMax" : {"$numberLong" : "8070450532247928832"}
       }),
       .expectedMinCover =
          "000000000000011100011010111111010100100110001101000000000000001\n"
          "00000000000001110001101011111101010010011000110100000000000001\n"
          "00000000000001110001101011111101010010011000110100000000000010\n"
          "00000000000001110001101011111101010010011000110100000000000011\n"
          "000000000000011100011010111111010100100110001101000000000001\n"
          "000000000000011100011010111111010100100110001101000000000010\n"
          "000000000000011100011010111111010100100110001101000000000011\n"
          "0000000000000111000110101111110101001001100011010000000001\n"
          "0000000000000111000110101111110101001001100011010000000010\n"
          "0000000000000111000110101111110101001001100011010000000011\n"
          "00000000000001110001101011111101010010011000110100000001\n"
          "00000000000001110001101011111101010010011000110100000010\n"
          "00000000000001110001101011111101010010011000110100000011\n"
          "00000000000001110001101011111101010010011000110100000100\n"
          "00000000000001110001101011111101010010011000110100000101\n"
          "0000000000000111000110101111110101001001100011010000011000\n"
          "000000000000011100011010111111010100100110001101000001100100\n"
          "000000000000011100011010111111010100100110001101000001100101\n"
          "00000000000001110001101011111101010010011000110100000110011000\n"
          "00000000000001110001101011111101010010011000110100000110011001\n"
          "00000000000001110001101011111101010010011000110100000110011010\n"
          "000000000000011100011010111111010100100110001101000001100110110\n",
       .sparsity = OPT_I64 (2)},

      {.description = "Int64 Upper bound excluded",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberLong" : "0"},
          "lbIncluded" : true,
          "upperBound" : {"$numberLong" : "823"},
          "ubIncluded" : false,
          "indexMin" : {"$numberLong" : "-1000000000000000"},
          "indexMax" : {"$numberLong" : "8070450532247928832"}
       }),
       .expectedMinCover =
          "000000000000011100011010111111010100100110001101000000\n"
          "00000000000001110001101011111101010010011000110100000100\n"
          "00000000000001110001101011111101010010011000110100000101\n"
          "0000000000000111000110101111110101001001100011010000011000\n"
          "000000000000011100011010111111010100100110001101000001100100\n"
          "000000000000011100011010111111010100100110001101000001100101\n"
          "00000000000001110001101011111101010010011000110100000110011000\n"
          "00000000000001110001101011111101010010011000110100000110011001\n"
          "00000000000001110001101011111101010010011000110100000110011010\n"
          "000000000000011100011010111111010100100110001101000001100110110\n",
       .sparsity = OPT_I64 (2)},

      {.description = "Int64 Lower bound excluded",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberLong" : "0"},
          "lbIncluded" : false,
          "upperBound" : {"$numberLong" : "823"},
          "ubIncluded" : true,
          "indexMin" : {"$numberLong" : "-1000000000000000"},
          "indexMax" : {"$numberLong" : "8070450532247928832"}
       }),
       .expectedMinCover =
          "000000000000011100011010111111010100100110001101000000000000001\n"
          "00000000000001110001101011111101010010011000110100000000000001\n"
          "00000000000001110001101011111101010010011000110100000000000010\n"
          "00000000000001110001101011111101010010011000110100000000000011\n"
          "000000000000011100011010111111010100100110001101000000000001\n"
          "000000000000011100011010111111010100100110001101000000000010\n"
          "000000000000011100011010111111010100100110001101000000000011\n"
          "0000000000000111000110101111110101001001100011010000000001\n"
          "0000000000000111000110101111110101001001100011010000000010\n"
          "0000000000000111000110101111110101001001100011010000000011\n"
          "00000000000001110001101011111101010010011000110100000001\n"
          "00000000000001110001101011111101010010011000110100000010\n"
          "00000000000001110001101011111101010010011000110100000011\n"
          "00000000000001110001101011111101010010011000110100000100\n"
          "00000000000001110001101011111101010010011000110100000101\n"
          "0000000000000111000110101111110101001001100011010000011000\n"
          "000000000000011100011010111111010100100110001101000001100100\n"
          "000000000000011100011010111111010100100110001101000001100101\n"
          "000000000000011100011010111111010100100110001101000001100110\n",
       .sparsity = OPT_I64 (2)},
      {.description = "Int64 Infinite upper bound",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberLong" : "1"},
          "lbIncluded" : true,
          "upperBound" : {"$numberDouble" : "Infinity"},
          "ubIncluded" : true,
          "indexMin" : {"$numberLong" : "0"},
          "indexMax" : {"$numberLong" : "7"}
       }),
       .expectedMinCover = "001\n"
                           "01\n"
                           "1\n"},
      {.description = "Int64 Infinite lower bound",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberDouble" : "-Infinity"},
          "lbIncluded" : true,
          "upperBound" : {"$numberLong" : "5"},
          "ubIncluded" : true,
          "indexMin" : {"$numberLong" : "0"},
          "indexMax" : {"$numberLong" : "7"}
       }),
       .expectedMinCover = "0\n"
                           "10\n"},
      {.description = "Int64 Infinite both bounds",
       .findSpecJSON = RAW_STRING ({
          "lowerBound" : {"$numberDouble" : "-Infinity"},
          "lbIncluded" : true,
          "upperBound" : {"$numberDouble" : "Infinity"},
          "ubIncluded" : true,
          "indexMin" : {"$numberLong" : "0"},
          "indexMax" : {"$numberLong" : "7"}
       }),
       .expectedMinCover = "root\n"},
   };

   for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++) {
      testcase_t *test = tests + i;
      mc_FLE2RangeFindSpec_t findSpec;

      if (test->description) {
         printf ("  %zu: %s\n", i, test->description);
      } else {
         printf ("  %zu\n", i);
      }

      bson_t *findSpecVal =
         bson_new_from_json ((const uint8_t *) test->findSpecJSON, -1, &error);
      if (!findSpecVal) {
         TEST_ERROR ("failed to parse JSON: %s", error.message);
      }

      bson_t *findSpecDoc = bson_new ();
      BSON_APPEND_DOCUMENT (findSpecDoc, "findSpec", findSpecVal);

      bson_iter_t findSpecIter;
      ASSERT (bson_iter_init_find (&findSpecIter, findSpecDoc, "findSpec"));

      ASSERT_OK_STATUS (
         mc_FLE2RangeFindSpec_parse (&findSpec, &findSpecIter, status), status);

      size_t sparsity = 1;
      if (test->sparsity.set) {
         sparsity = (size_t) test->sparsity.value;
      }

      mc_mincover_t *mc =
         mc_get_mincover_from_FLE2RangeFindSpec (&findSpec, sparsity, status);

      ASSERT_OK_STATUS (mc, status);
      ASSERT_MINCOVER_EQ (mc, test->expectedMinCover);
      mc_mincover_destroy (mc);

      bson_destroy (findSpecDoc);
      bson_destroy (findSpecVal);
   }
   mongocrypt_status_destroy (status);
}


void
_mongocrypt_tester_install_marking (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_mongocrypt_marking_parse);
   INSTALL_TEST (test_mc_get_mincover_from_FLE2RangeFindSpec);
}
