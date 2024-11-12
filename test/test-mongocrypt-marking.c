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
#include "mc-fle-blob-subtype-private.h"
#include "mc-tokens-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-marking-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"
#include <stdbool.h>

/* Create a basis marking buffer with valid values for the given fields. */
static void _make_marking(bson_t *bson, _mongocrypt_buffer_t *buf) {
    buf->len = bson->len + 1;
    buf->data = bson_malloc(buf->len);
    BSON_ASSERT(buf->data);

    buf->data[0] = 0;
    buf->owned = true;
    memcpy(buf->data + 1, bson_get_data(bson), bson->len);
}

static void _parse_ok(_mongocrypt_buffer_t *marking_buf, _mongocrypt_marking_t *out) {
    mongocrypt_status_t *status;

    status = mongocrypt_status_new();
    memset(out, 0, sizeof(*out));
    ASSERT_OK_STATUS(_mongocrypt_marking_parse_unowned(marking_buf, out, status), status);

    mongocrypt_status_destroy(status);
}

static void _parse_fails(_mongocrypt_buffer_t *marking_buf, const char *msg, _mongocrypt_marking_t *out) {
    mongocrypt_status_t *status;

    status = mongocrypt_status_new();
    memset(out, 0, sizeof(*out));
    ASSERT_FAILS_STATUS(_mongocrypt_marking_parse_unowned(marking_buf, out, status), status, msg);

    mongocrypt_status_destroy(status);
}

static void test_mongocrypt_marking_parse(_mongocrypt_tester_t *tester) {
    bson_t *marking_bson;
    _mongocrypt_buffer_t marking_buf;
    _mongocrypt_marking_t marking;

    /* successful case. */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc', 'ka': 'alt'}");
    _make_marking(marking_bson, &marking_buf);
    _parse_ok(&marking_buf, &marking);
    BSON_ASSERT(marking.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
    BSON_ASSERT(0 == strcmp("abc", bson_iter_utf8(&marking.v_iter, NULL)));
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* buffer < 6 bytes */
    marking_buf.data = (uint8_t *)"abc";
    marking_buf.len = 3;
    marking_buf.owned = false;
    _parse_fails(&marking_buf, "invalid marking, length < 6", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* bad first byte */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc', 'ka': 'alt'}");
    _make_marking(marking_bson, &marking_buf);
    _mongocrypt_marking_cleanup(&marking);
    marking_buf.data[0] = 1;
    _parse_fails(&marking_buf, "invalid marking", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* unrecognized fields. */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc', 'ka': 'alt', 'extra': 1}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "unrecognized field 'extra'", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* malformed BSON. */
    marking_bson = TMP_BSON("{}");
    ((uint8_t *)bson_get_data(marking_bson))[4] = 0xFF;
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "invalid BSON", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* a: missing */
    marking_bson = TMP_BSON("{'v': 'abc', 'ka': 'alt'}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "no 'a' specified", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);
    /* a: wrong type */
    marking_bson = TMP_BSON("{'a': 'abc', 'v': 'abc', 'ka': 'alt'}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "invalid marking, 'a' must be an int32", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);
    /* a: wrong integer */
    marking_bson = TMP_BSON("{'a': -1, 'v': 'abc', 'ka': 'alt'}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "invalid algorithm value: -1", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* v: missing */
    marking_bson = TMP_BSON("{'a': 2, 'ka': 'alt'}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "no 'v' specified", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* Not testing IV per CDRIVER-3127. TODO: remove this comment. */

    /* ki+ka: missing */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc'}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "neither 'ki' nor 'ka' specified", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);
    /* ki+ka: both present */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc', 'ka': 'alt' }");
    BSON_APPEND_BINARY(marking_bson, "ki", BSON_SUBTYPE_UUID, (TEST_BIN(16))->data, 16);
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "both 'ki' and 'ka' specified", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* ki: wrong type */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc', 'ki': 'abc' }");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "key id must be a UUID", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* ki: wrong subtype */
    marking_bson = TMP_BSON("{'a': 2, 'v': 'abc' }");
    BSON_APPEND_BINARY(marking_bson, "ki", BSON_SUBTYPE_BINARY, (TEST_BIN(16))->data, 16);
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "key id must be a UUID", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);

    /* ka: wrong type */
    marking_bson = TMP_BSON("{'v': 'abc', 'ka': 1}");
    _make_marking(marking_bson, &marking_buf);
    _parse_fails(&marking_buf, "key alt name must be a UTF8", &marking);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);
}

#define RAW_STRING(...) #__VA_ARGS__

#define ASSERT_MINCOVER_EQ(got, expectString)                                                                          \
    if (1) {                                                                                                           \
        char *gotStr = bson_strdup("");                                                                                \
        for (size_t i = 0; i < mc_mincover_len(got); i++) {                                                            \
            char *previous = gotStr;                                                                                   \
            gotStr = bson_strdup_printf("%s%s\n", gotStr, mc_mincover_get(got, i));                                    \
            bson_free(previous);                                                                                       \
        }                                                                                                              \
        ASSERT_STREQUAL(gotStr, expectString);                                                                         \
        bson_free(gotStr);                                                                                             \
    } else                                                                                                             \
        ((void)0)

/* test_mc_get_mincover_from_FLE2RangeFindSpec tests processing an
 * FLE2RangeFindSpec into a mincover. It is is analogous to the
 * MinCoverInterfaceTest in the server code:
 * https://github.com/mongodb/mongo/blob/a4a3eba2a0e0a839ca6213491361269b42e12761/src/mongo/crypto/fle_crypto_test.cpp#L2585
 */
static void test_mc_get_mincover_from_FLE2RangeFindSpec(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *description; // May be NULL.
        const char *findSpecJSON;
        const char *expectedMinCover;
        mc_optional_int64_t sparsity;
        const char *expectedError;
        const char *expectedErrorAtParseTime;
        bool disableRangeV2;
    } testcase_t;

    testcase_t tests[] = {
        {.description = "Range V2 disabled w/ trim factor fails",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "32"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .disableRangeV2 = true,
         .expectedErrorAtParseTime = "'trimFactor' is not supported for QE range v1"},
        {.description = "Range V2 disabled w/ no trim factor succeeds",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "32"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"}
         }),
         .disableRangeV2 = true,
         .expectedMinCover = "000111\n"
                             "001\n"
                             "01\n"
                             "100000\n"},
        {.description = "Int32 Bounds included",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "32"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000111\n"
                             "001\n"
                             "01\n"
                             "100000\n"},

        {.description = "Int32 Bounds excluded",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : false,
             "upperBound" : {"$numberInt" : "32"},
             "ubIncluded" : false,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "001\n"
                             "01\n"},
        {.description = "Int32 Upper bound excluded",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "32"},
             "ubIncluded" : false,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000111\n"
                             "001\n"
                             "01\n"},
        {.description = "Int32 Lower bound excluded",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : false,
             "upperBound" : {"$numberInt" : "32"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "001\n"
                             "01\n"
                             "100000\n"},
        {.description = "Int32 Infinite upper bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000111\n"
                             "001\n"
                             "01\n"
                             "100000\n"},
        {.description = "Int32 Infinite lower bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "8"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000\n"
                             "001000\n"},
        {.description = "Int32 Infinite both bounds",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "0\n"
                             "100000\n"},
        {.description = "Int32 mincover=root no trimming",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "31"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "root\n"},
        {.description = "Int32 mincover=root TF=1",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "31"},
             "trimFactor" : 1
         }),
         .expectedMinCover = "0\n"
                             "1\n"},
        {.description = "Int32 mincover=root TF=3",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "31"},
             "trimFactor" : 3
         }),
         .expectedMinCover = "000\n"
                             "001\n"
                             "010\n"
                             "011\n"
                             "100\n"
                             "101\n"
                             "110\n"
                             "111\n"},
        {.description = "Int32 infinite both bounds SP=2",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .sparsity = OPT_I64(2),
         .expectedMinCover = "00\n"
                             "01\n"
                             "100000\n"},
        {.description = "Int32 infinite both bounds TF=1",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 1
         }),
         .expectedMinCover = "0\n"
                             "100000\n"},
        {.description = "Int32 infinite both bounds TF=2",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 2
         }),
         .expectedMinCover = "00\n"
                             "01\n"
                             "100000\n"},

        {.description = "Int32 infinite both bounds TF=3",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 3
         }),
         .expectedMinCover = "000\n"
                             "001\n"
                             "010\n"
                             "011\n"
                             "100000\n"},
        {.description = "Int32 infinite both bounds SP=2 TF=3",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 3
         }),
         .sparsity = OPT_I64(2),
         .expectedMinCover = "0000\n"
                             "0001\n"
                             "0010\n"
                             "0011\n"
                             "0100\n"
                             "0101\n"
                             "0110\n"
                             "0111\n"
                             "100000\n"},
        {.description = "Too large trim factor fails",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 6
         }),
         .expectedError =
             "Trim factor must be less than the number of bits (6) used to represent an element of the domain"},
        {.description = "Negative trim factor fails",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : -1
         }),
         .expectedErrorAtParseTime = "'trimFactor' must be non-negative"},
        {.description = "Int64 Bounds included",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "0"},
             "lbIncluded" : true,
             "upperBound" : {"$numberLong" : "823"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "-1000000000000000"},
             "indexMax" : {"$numberLong" : "8070450532247928832"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000000000000011100011010111111010100100110001101000000\n"
                             "00000000000001110001101011111101010010011000110100000100\n"
                             "00000000000001110001101011111101010010011000110100000101\n"
                             "0000000000000111000110101111110101001001100011010000011000\n"
                             "000000000000011100011010111111010100100110001101000001100100\n"
                             "000000000000011100011010111111010100100110001101000001100101\n"
                             "000000000000011100011010111111010100100110001101000001100110\n",
         .sparsity = OPT_I64(2)},

        {.description = "Int64 Bounds excluded",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "0"},
             "lbIncluded" : false,
             "upperBound" : {"$numberLong" : "823"},
             "ubIncluded" : false,
             "indexMin" : {"$numberLong" : "-1000000000000000"},
             "indexMax" : {"$numberLong" : "8070450532247928832"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000000000000011100011010111111010100100110001101000000000000001\n"
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
         .sparsity = OPT_I64(2)},

        {.description = "Int64 Upper bound excluded",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "0"},
             "lbIncluded" : true,
             "upperBound" : {"$numberLong" : "823"},
             "ubIncluded" : false,
             "indexMin" : {"$numberLong" : "-1000000000000000"},
             "indexMax" : {"$numberLong" : "8070450532247928832"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000000000000011100011010111111010100100110001101000000\n"
                             "00000000000001110001101011111101010010011000110100000100\n"
                             "00000000000001110001101011111101010010011000110100000101\n"
                             "0000000000000111000110101111110101001001100011010000011000\n"
                             "000000000000011100011010111111010100100110001101000001100100\n"
                             "000000000000011100011010111111010100100110001101000001100101\n"
                             "00000000000001110001101011111101010010011000110100000110011000\n"
                             "00000000000001110001101011111101010010011000110100000110011001\n"
                             "00000000000001110001101011111101010010011000110100000110011010\n"
                             "000000000000011100011010111111010100100110001101000001100110110\n",
         .sparsity = OPT_I64(2)},

        {.description = "Int64 Lower bound excluded",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "0"},
             "lbIncluded" : false,
             "upperBound" : {"$numberLong" : "823"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "-1000000000000000"},
             "indexMax" : {"$numberLong" : "8070450532247928832"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "000000000000011100011010111111010100100110001101000000000000001\n"
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
         .sparsity = OPT_I64(2)},
        {.description = "Int64 Infinite upper bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "1"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "7"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "001\n"
                             "01\n"
                             "1\n"},
        {.description = "Int64 Infinite lower bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberLong" : "5"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "7"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "0\n"
                             "10\n"},
        {.description = "Int64 Infinite both bounds",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "-Infinity"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "Infinity"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "7"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "root\n"},
        {.description = "Mismatched types",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "1"},
             "lbIncluded" : true,
             "upperBound" : {"$numberLong" : "2"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "7"},
             "trimFactor" : 0
         }),
         .expectedError = "expected lowerBound to match index type"},
        {.description = "Int32 exclusive lower bound > upper bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : false,
             "upperBound" : {"$numberInt" : "7"},
             "ubIncluded" : true,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be less than or equal to range max"},
        {.description = "Int64 exclusive lower bound > upper bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "7"},
             "lbIncluded" : false,
             "upperBound" : {"$numberLong" : "7"},
             "ubIncluded" : true,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be less than or equal to range max"},
        {.description = "Int32 exclusive upper bound < lower bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "7"},
             "ubIncluded" : false,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be less than or equal to range max"},
        {.description = "Int64 exclusive upper bound < lower bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "7"},
             "lbIncluded" : true,
             "upperBound" : {"$numberLong" : "7"},
             "ubIncluded" : false,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be less than or equal to range max"},
        {.description = "Int32 exclusive bounds cross",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "7"},
             "lbIncluded" : false,
             "upperBound" : {"$numberInt" : "7"},
             "ubIncluded" : false,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be less than or equal to range max"},
        {.description = "Int64 exclusive bounds cross",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberLong" : "7"},
             "lbIncluded" : false,
             "upperBound" : {"$numberLong" : "7"},
             "ubIncluded" : false,
             "indexMin" : {"$numberLong" : "0"},
             "indexMax" : {"$numberLong" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be less than or equal to range max"},
        {.description = "Int32 exclusive upper bound is 0",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberInt" : "0"},
             "lbIncluded" : true,
             "upperBound" : {"$numberInt" : "0"},
             "ubIncluded" : false,
             "indexMin" : {"$numberInt" : "0"},
             "indexMax" : {"$numberInt" : "32"},
             "trimFactor" : 0
         }),
         .expectedError = "must be greater than the range minimum"},
        {.description = "Double inclusive bounds",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "23.5"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "35.25"},
             "ubIncluded" : true,
             "indexMin" : {"$numberDouble" : "0"},
             "indexMax" : {"$numberDouble" : "1000"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "11000000001101111\n"
                             "1100000000111\n"
                             "1100000001000000\n"
                             "11000000010000010\n"
                             "1100000001000001100\n"
                             "110000000100000110100000000000000000000000000000000"
                             "0000000000000\n"},
        {.description = "Double exclusive bounds",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "23.5"},
             "lbIncluded" : false,
             "upperBound" : {"$numberDouble" : "35.25"},
             "ubIncluded" : false,
             "indexMin" : {"$numberDouble" : "0"},
             "indexMax" : {"$numberDouble" : "1000"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "1100000000110111100000000000000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000001\n"
                             "110000000011011110000000000000000000000001\n"
                             "11000000001101111000000000000000000000001\n"
                             "1100000000110111100000000000000000000001\n"
                             "110000000011011110000000000000000000001\n"
                             "11000000001101111000000000000000000001\n"
                             "1100000000110111100000000000000000001\n"
                             "110000000011011110000000000000000001\n"
                             "11000000001101111000000000000000001\n"
                             "1100000000110111100000000000000001\n"
                             "110000000011011110000000000000001\n"
                             "11000000001101111000000000000001\n"
                             "1100000000110111100000000000001\n"
                             "110000000011011110000000000001\n"
                             "11000000001101111000000000001\n"
                             "1100000000110111100000000001\n"
                             "110000000011011110000000001\n"
                             "11000000001101111000000001\n"
                             "1100000000110111100000001\n"
                             "110000000011011110000001\n"
                             "11000000001101111000001\n"
                             "1100000000110111100001\n"
                             "110000000011011110001\n"
                             "11000000001101111001\n"
                             "1100000000110111101\n"
                             "110000000011011111\n"
                             "1100000000111\n"
                             "1100000001000000\n"
                             "11000000010000010\n"
                             "1100000001000001100\n"},
        {.description = "Double exclusive upper bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "23.5"},
             "lbIncluded" : true,
             "upperBound" : {"$numberDouble" : "35.25"},
             "ubIncluded" : false,
             "indexMin" : {"$numberDouble" : "0"},
             "indexMax" : {"$numberDouble" : "1000"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "11000000001101111\n"
                             "1100000000111\n"
                             "1100000001000000\n"
                             "11000000010000010\n"
                             "1100000001000001100\n"},
        {.description = "Double exclusive lower bound",
         .findSpecJSON = RAW_STRING({
             "lowerBound" : {"$numberDouble" : "23.5"},
             "lbIncluded" : false,
             "upperBound" : {"$numberDouble" : "35.25"},
             "ubIncluded" : true,
             "indexMin" : {"$numberDouble" : "0"},
             "indexMax" : {"$numberDouble" : "1000"},
             "trimFactor" : 0
         }),
         .expectedMinCover = "1100000000110111100000000000000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000000001\n"
                             "110000000011011110000000000000000000000000001\n"
                             "11000000001101111000000000000000000000000001\n"
                             "1100000000110111100000000000000000000000001\n"
                             "110000000011011110000000000000000000000001\n"
                             "11000000001101111000000000000000000000001\n"
                             "1100000000110111100000000000000000000001\n"
                             "110000000011011110000000000000000000001\n"
                             "11000000001101111000000000000000000001\n"
                             "1100000000110111100000000000000000001\n"
                             "110000000011011110000000000000000001\n"
                             "11000000001101111000000000000000001\n"
                             "1100000000110111100000000000000001\n"
                             "110000000011011110000000000000001\n"
                             "11000000001101111000000000000001\n"
                             "1100000000110111100000000000001\n"
                             "110000000011011110000000000001\n"
                             "11000000001101111000000000001\n"
                             "1100000000110111100000000001\n"
                             "110000000011011110000000001\n"
                             "11000000001101111000000001\n"
                             "1100000000110111100000001\n"
                             "110000000011011110000001\n"
                             "11000000001101111000001\n"
                             "1100000000110111100001\n"
                             "110000000011011110001\n"
                             "11000000001101111001\n"
                             "1100000000110111101\n"
                             "110000000011011111\n"
                             "1100000000111\n"
                             "1100000001000000\n"
                             "11000000010000010\n"
                             "1100000001000001100\n"
                             "1100000001000001101000000000000000000000000000000000000000000000\n"},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        bson_error_t error = {0};
        testcase_t *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();

        if (test->description) {
            printf("  %zu: %s\n", i, test->description);
        } else {
            printf("  %zu\n", i);
        }

        bson_t *findSpecVal = bson_new_from_json((const uint8_t *)test->findSpecJSON, -1, &error);
        if (!findSpecVal) {
            TEST_ERROR("failed to parse JSON: %s", error.message);
        }

        bson_t *findSpecDoc = BCON_NEW("findSpec",
                                       "{",
                                       "edgesInfo",
                                       BCON_DOCUMENT(findSpecVal),
                                       "firstOperator", // Use a dummy firstOperator. It is not used for
                                                        // minCover.
                                       BCON_INT32(1),
                                       "payloadId", // Use a dummy payloadId. It is not used for minCover.
                                       BCON_INT32(1234),
                                       "}");

        bson_iter_t findSpecIter;
        ASSERT(bson_iter_init_find(&findSpecIter, findSpecDoc, "findSpec"));

        mc_FLE2RangeFindSpec_t findSpec;
        bool res = mc_FLE2RangeFindSpec_parse(&findSpec, &findSpecIter, !test->disableRangeV2, status);
        if (test->expectedErrorAtParseTime) {
            ASSERT(!res);
            ASSERT_STATUS_CONTAINS(status, test->expectedErrorAtParseTime);
            goto cleanup;
        } else {
            ASSERT_OK_STATUS(res, status);
        }

        size_t sparsity = 1;
        if (test->sparsity.set) {
            sparsity = (size_t)test->sparsity.value;
        }

        const bool use_range_v2 = !test->disableRangeV2;
        mc_mincover_t *mc = mc_get_mincover_from_FLE2RangeFindSpec(&findSpec, sparsity, status, use_range_v2);

        if (test->expectedError) {
            ASSERT(NULL == mc);
            ASSERT_STATUS_CONTAINS(status, test->expectedError);
        } else {
            ASSERT_OK_STATUS(mc, status);
            ASSERT_MINCOVER_EQ(mc, test->expectedMinCover);
        }
        mc_mincover_destroy(mc);

    cleanup:
        bson_destroy(findSpecDoc);
        bson_destroy(findSpecVal);
        mongocrypt_status_destroy(status);
    }
}

// Runs _mongocrypt_marking_to_ciphertext to compute the ciphertext for the given marking.
static void get_ciphertext_from_marking_json(_mongocrypt_tester_t *tester,
                                             mongocrypt_t *crypt,
                                             const char *markingJSON,
                                             _mongocrypt_ciphertext_t *out) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    // Set up encryption environment
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    // Add a test key
    _mongocrypt_buffer_t keyId;
    _mongocrypt_buffer_from_binary(&keyId, TEST_BIN(16));
    keyId.subtype = BSON_SUBTYPE_UUID;
    _mongocrypt_key_broker_add_test_key(&ctx->kb, &keyId);

    _mongocrypt_buffer_t marking_buf;
    _mongocrypt_marking_t marking;
    bson_t *marking_bson = TMP_BSON(markingJSON);
    // Add key identifier info to the marking
    BSON_APPEND_BINARY(marking_bson, "ki", BSON_SUBTYPE_UUID, (TEST_BIN(16))->data, 16);
    BSON_APPEND_BINARY(marking_bson, "ku", BSON_SUBTYPE_UUID, (TEST_BIN(16))->data, 16);
    _make_marking(marking_bson, &marking_buf);
    // Use FLE2 as the subtype (default is FLE1)
    marking_buf.data[0] = MC_SUBTYPE_FLE2EncryptionPlaceholder;
    _parse_ok(&marking_buf, &marking);

    ASSERT_OK_STATUS(_mongocrypt_marking_to_ciphertext((void *)&ctx->kb, &marking, out, status), status);

    mongocrypt_status_destroy(status);
    _mongocrypt_buffer_cleanup(&marking_buf);
    _mongocrypt_marking_cleanup(&marking);
    mongocrypt_ctx_destroy(ctx);
}

// Assert that the encryptedTokens fields in V2 insert/update ciphertext matches our expectations. Specifically, checks
// that the length of these fields are what we expect, and that the "isLeaf" token is appended when using range V2.
static void assert_correctness_of_ciphertext(_mongocrypt_ciphertext_t *ciphertext,
                                             mongocrypt_t *crypt,
                                             mc_ECOCToken_t *ecocToken,
                                             bool useRangeV2,
                                             uint32_t expectedEdges) {
    uint32_t expectedPLength = useRangeV2 ? 33 : 32;
    const _mongocrypt_value_encryption_algorithm_t *fle2alg = _mcFLE2Algorithm();
    mongocrypt_status_t *status = mongocrypt_status_new();

    bson_t ciphertextBSON;
    bson_iter_t iter;
    ASSERT(_mongocrypt_buffer_to_bson(&ciphertext->data, &ciphertextBSON));

    // 'p' field should be available, length should be 16 bytes of IV + expected bytes
    bson_iter_init_find(&iter, &ciphertextBSON, "p");
    ASSERT(BSON_ITER_HOLDS_BINARY(&iter));
    uint32_t p_len;
    const uint8_t *p_data;
    bson_iter_binary(&iter, NULL, &p_len, &p_data);
    ASSERT_CMPUINT32(p_len, ==, 16 + expectedPLength);

    if (useRangeV2) {
        _mongocrypt_buffer_t p_buf, decrypted_buf;
        ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&p_buf, p_data, p_len));
        _mongocrypt_buffer_init_size(&decrypted_buf, expectedPLength);
        uint32_t decryptedBytes;
        // Decrypt p. When using range V2, last byte should be 0.
        ASSERT_OK_STATUS(fle2alg->do_decrypt(crypt->crypto,
                                             NULL,
                                             mc_ECOCToken_get(ecocToken),
                                             &p_buf,
                                             &decrypted_buf,
                                             &decryptedBytes,
                                             status),
                         status);
        ASSERT_CMPUINT32(decryptedBytes, ==, expectedPLength);
        ASSERT_CMPUINT8(decrypted_buf.data[decrypted_buf.len - 1], ==, 0);
        _mongocrypt_buffer_cleanup(&decrypted_buf);
        _mongocrypt_buffer_cleanup(&p_buf);
    }

    // 'g' field should be available
    bson_iter_init_find(&iter, &ciphertextBSON, "g");
    ASSERT(BSON_ITER_HOLDS_ARRAY(&iter));
    uint32_t g_buf_len;
    const uint8_t *g_buf;
    bson_t g_arr;
    bson_iter_array(&iter, &g_buf_len, &g_buf);
    ASSERT(bson_init_static(&g_arr, g_buf, g_buf_len));

    bson_iter_t g_iter;
    bson_iter_init(&g_iter, &g_arr);
    size_t g_count = 0, leaf_count = 0;
    // Iterate through each edge token set and check p for each
    while (bson_iter_next(&g_iter)) {
        g_count++;
        ASSERT(BSON_ITER_HOLDS_DOCUMENT(&g_iter));
        uint32_t subdoc_len;
        const uint8_t *subdoc_buf;
        bson_t subdoc;
        bson_iter_document(&g_iter, &subdoc_len, &subdoc_buf);
        ASSERT(bson_init_static(&subdoc, subdoc_buf, subdoc_len));

        bson_iter_t sub_iter;
        bson_iter_init_find(&sub_iter, &subdoc, "p");
        ASSERT(BSON_ITER_HOLDS_BINARY(&sub_iter));
        bson_iter_binary(&sub_iter, NULL, &p_len, &p_data);
        ASSERT_CMPUINT32(p_len, ==, 16 + expectedPLength);

        if (useRangeV2) {
            _mongocrypt_buffer_t p_buf, decrypted_buf;
            ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&p_buf, p_data, p_len));
            _mongocrypt_buffer_init_size(&decrypted_buf, expectedPLength);

            // Decrypt p. If useRangeV2, the last byte should be 0 or 1, depending on whether isLeaf.
            uint32_t decrypted_bytes;
            ASSERT_OK_STATUS(fle2alg->do_decrypt(crypt->crypto,
                                                 NULL,
                                                 mc_ECOCToken_get(ecocToken),
                                                 &p_buf,
                                                 &decrypted_buf,
                                                 &decrypted_bytes,
                                                 status),
                             status);
            ASSERT_CMPUINT32(decrypted_bytes, ==, expectedPLength);
            if (decrypted_buf.data[decrypted_buf.len - 1] == 1) {
                leaf_count++;
            } else {
                ASSERT_CMPUINT8(decrypted_buf.data[decrypted_buf.len - 1], ==, 0)
            }

            _mongocrypt_buffer_cleanup(&decrypted_buf);
            _mongocrypt_buffer_cleanup(&p_buf);
        }
    }
    ASSERT_CMPSIZE_T(g_count, ==, expectedEdges);
    if (useRangeV2) {
        // There should be exactly one leaf in any insert call.
        ASSERT_CMPSIZE_T(leaf_count, ==, 1);
    }
    bson_destroy(&ciphertextBSON);
    mongocrypt_status_destroy(status);
}

// Get the ECOC token to use in decryption.
static mc_ECOCToken_t *getECOCToken(mongocrypt_t *crypt) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    // Test token key that we added earlier is all zeros.
    _mongocrypt_buffer_t tokenKey;
    _mongocrypt_buffer_init_size(&tokenKey, MONGOCRYPT_TOKEN_KEY_LEN);
    memset(tokenKey.data, 0, MONGOCRYPT_TOKEN_KEY_LEN);

    mc_CollectionsLevel1Token_t *collectionsLevel1Token =
        mc_CollectionsLevel1Token_new(crypt->crypto, &tokenKey, status);
    mc_ECOCToken_t *ecocToken = mc_ECOCToken_new(crypt->crypto, collectionsLevel1Token, status);
    ASSERT(mongocrypt_status_ok(status));

    mc_CollectionsLevel1Token_destroy(collectionsLevel1Token);
    _mongocrypt_buffer_cleanup(&tokenKey);
    mongocrypt_status_destroy(status);
    return ecocToken;
}

static void test_mc_marking_to_ciphertext(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        printf("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    // Test that whether range V2 is enabled or disabled, the ciphertext matches our expectations.
    {
        const char markingJSON[] = RAW_STRING({
            't' : 1,
            'a' : 3,
            'v' : {'min' : 0, 'max' : 7, 'v' : 5},
            's' : {'$numberLong' : '1'},
            'cm' : {'$numberLong' : '1'}
        });
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

        get_ciphertext_from_marking_json(tester, crypt, markingJSON, &ciphertext);

        mc_ECOCToken_t *ecocToken = getECOCToken(crypt);
        assert_correctness_of_ciphertext(&ciphertext, crypt, ecocToken, false, 4);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        mc_ECOCToken_destroy(ecocToken);
        mongocrypt_destroy(crypt);
    }
    {
        const char markingJSON[] = RAW_STRING({
            't' : 1,
            'a' : 3,
            'v' : {'min' : 0, 'max' : 7, 'v' : 5, 'trimFactor' : 0},
            's' : {'$numberLong' : '1'},
            'cm' : {'$numberLong' : '1'}
        });
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_WITH_RANGE_V2);

        get_ciphertext_from_marking_json(tester, crypt, markingJSON, &ciphertext);

        mc_ECOCToken_t *ecocToken = getECOCToken(crypt);
        assert_correctness_of_ciphertext(&ciphertext, crypt, ecocToken, true, 4);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        mc_ECOCToken_destroy(ecocToken);

        mongocrypt_destroy(crypt);
    }
}

void _mongocrypt_tester_install_marking(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mongocrypt_marking_parse);
    INSTALL_TEST(test_mc_get_mincover_from_FLE2RangeFindSpec);
    INSTALL_TEST(test_mc_marking_to_ciphertext);
}
