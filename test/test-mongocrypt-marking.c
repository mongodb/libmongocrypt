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
#include "mc-fle2-find-text-payload-private.h"
#include "mc-tokens-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-marking-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"
#include <stdbool.h>
#include <string.h>

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
    BSON_ASSERT(marking.u.fle1.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
    BSON_ASSERT(0 == strcmp("abc", bson_iter_utf8(&marking.u.fle1.v_iter, NULL)));
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
    } testcase_t;

    testcase_t tests[] = {
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
            TEST_PRINTF("  %zu: %s\n", i, test->description);
        } else {
            TEST_PRINTF("  %zu\n", i);
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
        bool res = mc_FLE2RangeFindSpec_parse(&findSpec, &findSpecIter, status);
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

        mc_mincover_t *mc = mc_get_mincover_from_FLE2RangeFindSpec(&findSpec, sparsity, status);

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

// Helper for get_ciphertext_from_marking_json when we don't want to use extra test buffer space.
static void get_ciphertext_from_marking_json_with_bufs(mongocrypt_t *crypt,
                                                       bson_t *marking_bson,
                                                       _mongocrypt_ciphertext_t *out,
                                                       mongocrypt_binary_t *cmd,
                                                       mongocrypt_binary_t *keyIdSpace,
                                                       mongocrypt_binary_t *kiSpace,
                                                       mongocrypt_binary_t *kuSpace) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    // Set up encryption environment
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, cmd), ctx);
    // Add a test key
    _mongocrypt_buffer_t keyId;
    _mongocrypt_buffer_from_binary(&keyId, keyIdSpace);
    keyId.subtype = BSON_SUBTYPE_UUID;
    _mongocrypt_key_broker_add_test_key(&ctx->kb, &keyId);

    _mongocrypt_buffer_t marking_buf;
    _mongocrypt_marking_t marking;
    // Add key identifier info to the marking
    BSON_APPEND_BINARY(marking_bson, "ki", BSON_SUBTYPE_UUID, (kiSpace)->data, 16);
    BSON_APPEND_BINARY(marking_bson, "ku", BSON_SUBTYPE_UUID, (kuSpace)->data, 16);
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

// Runs _mongocrypt_marking_to_ciphertext to compute the ciphertext for the given marking.
static void get_ciphertext_from_marking_json(_mongocrypt_tester_t *tester,
                                             mongocrypt_t *crypt,
                                             const char *markingJSON,
                                             _mongocrypt_ciphertext_t *out) {
    get_ciphertext_from_marking_json_with_bufs(crypt,
                                               TMP_BSON_STR(markingJSON),
                                               out,
                                               TEST_FILE("./test/example/cmd.json"),
                                               TEST_BIN(16),
                                               TEST_BIN(16),
                                               TEST_BIN(16));
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

static mc_ServerDataEncryptionLevel1Token_t *getSDEL1Token(mongocrypt_t *crypt) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    // Test token key that we added earlier is all zeros.
    _mongocrypt_buffer_t tokenKey;
    _mongocrypt_buffer_init_size(&tokenKey, MONGOCRYPT_TOKEN_KEY_LEN);
    memset(tokenKey.data, 0, MONGOCRYPT_TOKEN_KEY_LEN);

    mc_ServerDataEncryptionLevel1Token_t *token =
        mc_ServerDataEncryptionLevel1Token_new(crypt->crypto, &tokenKey, status);
    ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_buffer_cleanup(&tokenKey);
    mongocrypt_status_destroy(status);
    return token;
}

static void
validate_and_get_bindata(bson_t *obj, const char *field, bson_subtype_t expected_type, mongocrypt_binary_t *bin_out) {
    bson_iter_t iter;
    ASSERT(bson_iter_init_find(&iter, obj, field));
    ASSERT(BSON_ITER_HOLDS_BINARY(&iter));

    uint32_t bin_len;
    const uint8_t *bin = NULL;
    bson_subtype_t bin_subtype;
    bson_iter_binary(&iter, &bin_subtype, &bin_len, &bin);
    ASSERT(bin_subtype == expected_type);
    bin_out->data = (void *)bin;
    bin_out->len = bin_len;
}

static void validate_encrypted_token(mongocrypt_t *crypt,
                                     mongocrypt_binary_t *encrypted_token_bin,
                                     mongocrypt_binary_t *expected_esc_token,
                                     bool expect_is_leaf,
                                     uint8_t *is_leaf_out) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_ECOCToken_t *ecocToken = getECOCToken(crypt);
    const _mongocrypt_value_encryption_algorithm_t *fle2alg = _mcFLE2Algorithm();

    _mongocrypt_buffer_t p_buf, decrypt_buf;
    uint32_t expect_decrypt_size = expected_esc_token->len + (expect_is_leaf ? 1 : 0);
    ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&p_buf, encrypted_token_bin->data, encrypted_token_bin->len));

    _mongocrypt_buffer_init_size(&decrypt_buf, expect_decrypt_size);

    uint32_t decrypt_size;
    ASSERT_OK_STATUS(
        fle2alg
            ->do_decrypt(crypt->crypto, NULL, mc_ECOCToken_get(ecocToken), &p_buf, &decrypt_buf, &decrypt_size, status),
        status);
    ASSERT_CMPUINT32(decrypt_size, ==, decrypt_buf.len);
    ASSERT_CMPUINT32(decrypt_size, ==, expect_decrypt_size);

    ASSERT(0 == memcmp(decrypt_buf.data, expected_esc_token->data, expected_esc_token->len));

    if (expect_is_leaf && is_leaf_out) {
        *is_leaf_out = decrypt_buf.data[decrypt_buf.len - 1];
    }

    _mongocrypt_buffer_cleanup(&decrypt_buf);
    _mongocrypt_buffer_cleanup(&p_buf);
    mc_ECOCToken_destroy(ecocToken);
    mongocrypt_status_destroy(status);
}

typedef struct {
    mongocrypt_binary_t d;
    mongocrypt_binary_t s;
    mongocrypt_binary_t p;
    mongocrypt_binary_t u;
    mongocrypt_binary_t v;
    mongocrypt_binary_t e;
    mongocrypt_binary_t l;
    uint32_t t;
    uint64_t k;
} iupv2_fields_common;

static iupv2_fields_common validate_iupv2_common(bson_t *iup_bson) {
    iupv2_fields_common res;
    memset(&res, 0, sizeof(res));

    bson_iter_t iter;
#define ASSERT_EXISTS_BINDATA_OF_SUBTYPE(Field, Subtype) validate_and_get_bindata(iup_bson, #Field, Subtype, &res.Field)

#define ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN(Field, Subtype, Len)                                                  \
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE(Field, Subtype);                                                                  \
    ASSERT(res.Field.len == Len)

    ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN(d, BSON_SUBTYPE_BINARY, MONGOCRYPT_HMAC_SHA256_LEN);
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN(s, BSON_SUBTYPE_BINARY, MONGOCRYPT_HMAC_SHA256_LEN);
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE(p, BSON_SUBTYPE_BINARY);
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN(u, BSON_SUBTYPE_UUID, 16);
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE(v, BSON_SUBTYPE_BINARY);
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN(e, BSON_SUBTYPE_BINARY, MONGOCRYPT_HMAC_SHA256_LEN);
    ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN(l, BSON_SUBTYPE_BINARY, MONGOCRYPT_HMAC_SHA256_LEN);

#undef ASSERT_EXISTS_BINDATA_OF_SUBTYPE_AND_LEN
#undef ASSERT_EXISTS_AND_BINDATA_OF_LEN

    ASSERT(bson_iter_init_find(&iter, iup_bson, "t"));
    ASSERT(BSON_ITER_HOLDS_INT32(&iter));
    res.t = bson_iter_int32(&iter);

    ASSERT(bson_iter_init_find(&iter, iup_bson, "k"));
    ASSERT(BSON_ITER_HOLDS_INT64(&iter));
    res.k = bson_iter_int64(&iter);

    return res;
}

// Assert that the encryptedTokens fields in V2 insert/update ciphertext matches our expectations. Specifically, checks
// that the length of these fields are what we expect, and that the "isLeaf" token is appended when using range V2.
static void
validate_range_ciphertext(_mongocrypt_ciphertext_t *ciphertext, mongocrypt_t *crypt, uint32_t expectedEdges) {
    uint32_t expectedPLength = (MONGOCRYPT_HMAC_SHA256_LEN + 1);

    bson_t ciphertextBSON;
    bson_iter_t iter;
    ASSERT(_mongocrypt_buffer_to_bson(&ciphertext->data, &ciphertextBSON));

    ASSERT(ciphertext->blob_subtype == MC_SUBTYPE_FLE2InsertUpdatePayloadV2);
    ASSERT(ciphertext->original_bson_type == 0); // unset
    ASSERT(ciphertext->key_id.len == 0);         // unset

    iupv2_fields_common res = validate_iupv2_common(&ciphertextBSON);

    // 'p' field should be available, length should be 16 bytes of IV + expected bytes
    ASSERT(res.p.len == 16 + expectedPLength);

    // validate crypto of 'p'
    uint8_t is_leaf = 255;
    validate_encrypted_token(crypt, &res.p, &res.s, true, &is_leaf);
    // isLeaf byte should be 0.
    ASSERT(is_leaf == 0);

    // 'g' field should be available
    ASSERT(bson_iter_init_find(&iter, &ciphertextBSON, "g"));
    ASSERT(BSON_ITER_HOLDS_ARRAY(&iter));
    bson_t g_arr;
    {
        uint32_t g_buf_len;
        const uint8_t *g_buf;
        bson_iter_array(&iter, &g_buf_len, &g_buf);
        ASSERT(bson_init_static(&g_arr, g_buf, g_buf_len));
    }

    bson_iter_t g_iter;
    bson_iter_init(&g_iter, &g_arr);
    size_t g_count = 0, leaf_count = 0;
    // Iterate through each edge token set and check p for each
    while (bson_iter_next(&g_iter)) {
        g_count++;
        ASSERT(BSON_ITER_HOLDS_DOCUMENT(&g_iter));
        bson_t subdoc;
        {
            uint32_t subdoc_len;
            const uint8_t *subdoc_buf;
            bson_iter_document(&g_iter, &subdoc_len, &subdoc_buf);
            ASSERT(bson_init_static(&subdoc, subdoc_buf, subdoc_len));
        }

        mongocrypt_binary_t encrypted_token_bin, esc_token_bin;
        validate_and_get_bindata(&subdoc, "p", BSON_SUBTYPE_BINARY, &encrypted_token_bin);
        validate_and_get_bindata(&subdoc, "s", BSON_SUBTYPE_BINARY, &esc_token_bin);
        ASSERT_CMPUINT32(encrypted_token_bin.len, ==, 16 + expectedPLength);
        ASSERT_CMPUINT32(esc_token_bin.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);

        uint8_t is_leaf = 255;
        validate_encrypted_token(crypt, &encrypted_token_bin, &esc_token_bin, true, &is_leaf);
        // isLeaf byte should be either 0 or 1.
        if (is_leaf == 1) {
            leaf_count++;
        } else {
            ASSERT_CMPUINT8(is_leaf, ==, 0);
        }
    }
    ASSERT_CMPSIZE_T(g_count, ==, expectedEdges);
    // There should be exactly one leaf in any insert call.
    ASSERT_CMPSIZE_T(leaf_count, ==, 1);
    bson_destroy(&ciphertextBSON);
}

static void test_mc_marking_to_ciphertext_fle2_range(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    // Test that ciphertext matches our expectations.
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
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

        get_ciphertext_from_marking_json(tester, crypt, markingJSON, &ciphertext);

        validate_range_ciphertext(&ciphertext, crypt, 4);
        _mongocrypt_ciphertext_cleanup(&ciphertext);

        mongocrypt_destroy(crypt);
    }
}

static void validate_text_search_token_set_common(bson_iter_t *iter_at_token_set_obj, mongocrypt_t *crypt) {
    ASSERT(BSON_ITER_HOLDS_DOCUMENT(iter_at_token_set_obj));
    bson_t ts_bson;
    {
        uint32_t len;
        const uint8_t *buf;
        bson_iter_document(iter_at_token_set_obj, &len, &buf);
        ASSERT(bson_init_static(&ts_bson, buf, len));
    }

    mongocrypt_binary_t token_bin;
    mongocrypt_binary_t esc_token_bin;
    mongocrypt_binary_t encrypted_token_bin;

    validate_and_get_bindata(&ts_bson, "d", BSON_SUBTYPE_BINARY, &token_bin);
    ASSERT_CMPUINT32(token_bin.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);

    validate_and_get_bindata(&ts_bson, "l", BSON_SUBTYPE_BINARY, &token_bin);
    ASSERT_CMPUINT32(token_bin.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);

    validate_and_get_bindata(&ts_bson, "s", BSON_SUBTYPE_BINARY, &esc_token_bin);
    ASSERT_CMPUINT32(esc_token_bin.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);

    validate_and_get_bindata(&ts_bson, "p", BSON_SUBTYPE_BINARY, &encrypted_token_bin);
    ASSERT_CMPUINT32(encrypted_token_bin.len, ==, (16 + MONGOCRYPT_HMAC_SHA256_LEN));

    // validate crypto of p
    validate_encrypted_token(crypt, &encrypted_token_bin, &esc_token_bin, false, NULL);
}

static size_t validate_text_search_token_set_array_common(bson_iter_t *iter_at_array, mongocrypt_t *crypt) {
    ASSERT(BSON_ITER_HOLDS_ARRAY(iter_at_array));
    bson_t arr_bson;
    {
        uint32_t subdoc_len;
        const uint8_t *subdoc_buf;
        bson_iter_array(iter_at_array, &subdoc_len, &subdoc_buf);
        ASSERT(bson_init_static(&arr_bson, subdoc_buf, subdoc_len));
    }

    bson_iter_t iter;
    bson_iter_init(&iter, &arr_bson);

    size_t count = 0;
    while (bson_iter_next(&iter)) {
        count++;
        validate_text_search_token_set_common(&iter, crypt);
    }
    return count;
}

typedef struct {
    size_t substrings;
    size_t suffixes;
    size_t prefixes;
} text_search_expected_token_counts;

// Assert that the fields in a insert/update payload V2 for text search match our expectations.
// Specifically, checks that the length of these fields, and the values of deterministic fields,
// are what we expect.
static void validate_text_search_ciphertext(_mongocrypt_tester_t *tester,
                                            _mongocrypt_ciphertext_t *ciphertext,
                                            mongocrypt_t *crypt,
                                            mc_FLE2TextSearchInsertSpec_t *spec,
                                            mongocrypt_fle2_placeholder_type_t type,
                                            uint64_t contention_max,
                                            text_search_expected_token_counts *expected_tag_counts) {
    bson_t payload_bson;
    bson_iter_t iter;
    ASSERT(_mongocrypt_buffer_to_bson(&ciphertext->data, &payload_bson));

    mc_ServerDataEncryptionLevel1Token_t *sdel1Token = getSDEL1Token(crypt);
    const mongocrypt_binary_t *keyId = TEST_BIN(16); // don't free!

    if (type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT) {
        ASSERT_CMPUINT8(ciphertext->blob_subtype, ==, MC_SUBTYPE_FLE2InsertUpdatePayloadV2);
        ASSERT_CMPUINT8(ciphertext->original_bson_type, ==, 0); // unset
        ASSERT_CMPUINT32(ciphertext->key_id.len, ==, 0);        // unset

        iupv2_fields_common res = validate_iupv2_common(&payload_bson);

        // validate u, t, k have correct values
        ASSERT_CMPBYTES(keyId->data, keyId->len, res.u.data, res.u.len);
        ASSERT_CMPUINT32(res.t, ==, BSON_TYPE_UTF8);
        ASSERT_CMPUINT64(res.k, <=, contention_max);

        // validate e is ServerDataEncryptionLevel1Token = HMAC(RootKey, 3)
        ASSERT_CMPUINT32(res.e.len, ==, mc_ServerDataEncryptionLevel1Token_get(sdel1Token)->len);
        ASSERT(memcmp(res.e.data, mc_ServerDataEncryptionLevel1Token_get(sdel1Token)->data, res.e.len) == 0);

        // validate crypto of p
        ASSERT(res.p.len == 16 + MONGOCRYPT_HMAC_SHA256_LEN);
        validate_encrypted_token(crypt, &res.p, &res.s, false, NULL);

        // validate v decrypts cleanly
        {
            mongocrypt_status_t *status = mongocrypt_status_new();

            const _mongocrypt_value_encryption_algorithm_t *fle2alg = _mcFLE2v2AEADAlgorithm();
            // assert first 16 bytes == userKeyId == indexKeyId
            ASSERT_CMPUINT32(res.v.len, >, 16);
            ASSERT_CMPBYTES(keyId->data, keyId->len, res.v.data, 16);

            _mongocrypt_buffer_t key, aad, ctext, ptext;
            _mongocrypt_buffer_init_size(&key, MONGOCRYPT_KEY_LEN);
            memset(key.data, 0, key.len);
            ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&aad, res.v.data, 16));
            ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&ctext, ((uint8_t *)res.v.data) + 16, res.v.len - 16));
            uint32_t plen = fle2alg->get_plaintext_len(res.v.len - 16, status);
            _mongocrypt_buffer_init_size(&ptext, plen);

            uint32_t pbytes;
            ASSERT_OK_STATUS(fle2alg->do_decrypt(crypt->crypto, &aad, &key, &ctext, &ptext, &pbytes, status), status);

            // BSON strings have 5 (4 for size + 1 null terminator) bytes of overhead
            ASSERT_CMPUINT32(pbytes, >=, 5);
            ASSERT_CMPSIZE_T(spec->len, ==, (pbytes - 5));
            ASSERT_STREQUAL(spec->v, ((char *)(ptext.data + 4)));

            _mongocrypt_buffer_cleanup(&ptext);
            _mongocrypt_buffer_cleanup(&ctext);
            _mongocrypt_buffer_cleanup(&aad);
            _mongocrypt_buffer_cleanup(&key);
            mongocrypt_status_destroy(status);
        }

        // assert b exists with correct fields
        ASSERT(bson_iter_init_find(&iter, &payload_bson, "b"));
        ASSERT(BSON_ITER_HOLDS_DOCUMENT(&iter));

        bson_t b_bson;
        bson_iter_t b_iter;
        {
            uint32_t subdoc_len;
            const uint8_t *subdoc_buf;
            bson_iter_document(&iter, &subdoc_len, &subdoc_buf);
            ASSERT(bson_init_static(&b_bson, subdoc_buf, subdoc_len));
        }

        ASSERT(bson_iter_init_find(&b_iter, &b_bson, "e"));
        validate_text_search_token_set_common(&b_iter, crypt);

        size_t tscount = 0;
        ASSERT(bson_iter_init_find(&b_iter, &b_bson, "s"));
        tscount = validate_text_search_token_set_array_common(&b_iter, crypt);
        ASSERT_CMPSIZE_T(expected_tag_counts->substrings, ==, tscount);

        ASSERT(bson_iter_init_find(&b_iter, &b_bson, "u"));
        tscount = validate_text_search_token_set_array_common(&b_iter, crypt);
        ASSERT_CMPSIZE_T(expected_tag_counts->suffixes, ==, tscount);

        ASSERT(bson_iter_init_find(&b_iter, &b_bson, "p"));
        tscount = validate_text_search_token_set_array_common(&b_iter, crypt);
        ASSERT_CMPSIZE_T(expected_tag_counts->prefixes, ==, tscount);
    } else {
        ASSERT_CMPUINT8(ciphertext->blob_subtype, ==, MC_SUBTYPE_FLE2FindTextPayload);
        ASSERT_CMPUINT8(ciphertext->original_bson_type, ==, 0); // unset
        ASSERT_CMPUINT32(ciphertext->key_id.len, ==, 0);        // unset
        mc_FLE2FindTextPayload_t parsed;
        mongocrypt_status_t *status = mongocrypt_status_new();

        ASSERT_OK_STATUS(mc_FLE2FindTextPayload_parse(&parsed, &payload_bson, status), status);
        ASSERT_CMPUINT64(parsed.maxContentionFactor, ==, contention_max);
        ASSERT(parsed.caseFold == spec->casef);
        ASSERT(parsed.diacriticFold == spec->diacf);

        bool exact = !(spec->prefix.set || spec->suffix.set || spec->substr.set);
        ASSERT(parsed.tokenSets.prefix.set == spec->prefix.set);
        ASSERT(parsed.tokenSets.substring.set == spec->substr.set);
        ASSERT(parsed.tokenSets.suffix.set == spec->suffix.set);
        ASSERT(parsed.tokenSets.exact.set == exact);
        ASSERT(parsed.prefixSpec.set == spec->prefix.set);
        ASSERT(parsed.substringSpec.set == spec->substr.set);
        ASSERT(parsed.suffixSpec.set == spec->suffix.set);

#define CHECK_TOKENS(Type)                                                                                             \
    if (parsed.tokenSets.Type.set) {                                                                                   \
        ASSERT_CMPUINT32(parsed.tokenSets.Type.value.edcDerivedToken.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);             \
        ASSERT_CMPUINT32(parsed.tokenSets.Type.value.escDerivedToken.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);             \
        ASSERT_CMPUINT32(parsed.tokenSets.Type.value.serverDerivedFromDataToken.len, ==, MONGOCRYPT_HMAC_SHA256_LEN);  \
    }
        CHECK_TOKENS(prefix);
        CHECK_TOKENS(suffix);
        CHECK_TOKENS(substring);
        CHECK_TOKENS(exact);
#undef CHECK_TOKENS
        if (parsed.prefixSpec.set) {
            ASSERT_CMPUINT32(parsed.prefixSpec.value.lb, ==, spec->prefix.value.lb);
            ASSERT_CMPUINT32(parsed.prefixSpec.value.ub, ==, spec->prefix.value.ub);
        }
        if (parsed.suffixSpec.set) {
            ASSERT_CMPUINT32(parsed.suffixSpec.value.lb, ==, spec->suffix.value.lb);
            ASSERT_CMPUINT32(parsed.suffixSpec.value.ub, ==, spec->suffix.value.ub);
        }
        if (parsed.substringSpec.set) {
            ASSERT_CMPUINT32(parsed.substringSpec.value.mlen, ==, spec->substr.value.mlen);
            ASSERT_CMPUINT32(parsed.substringSpec.value.lb, ==, spec->substr.value.lb);
            ASSERT_CMPUINT32(parsed.substringSpec.value.ub, ==, spec->substr.value.ub);
        }
        mongocrypt_status_destroy(status);
        mc_FLE2FindTextPayload_cleanup(&parsed);
    }

    mc_ServerDataEncryptionLevel1Token_destroy(sdel1Token);
    bson_destroy(&payload_bson);
}

static size_t calculate_expected_substring_tag_count(size_t beta, size_t mlen, size_t ub, size_t lb) {
    ASSERT_CMPSIZE_T(beta, <=, (SIZE_MAX - 15));
    ASSERT_CMPSIZE_T(lb, <=, ub);
    ASSERT_CMPSIZE_T(mlen, >=, ub);

    size_t padded_len = 16 * ((beta + 5 + 15) / 16) - 5;
    if (beta > mlen || lb > padded_len) {
        return 0;
    }
    size_t maxkgram1 = 0;
    size_t maxkgram2 = 0;
    for (size_t j = lb; j <= ub; j++) {
        maxkgram1 += (mlen - j + 1);
    }
    for (size_t j = lb; j <= BSON_MIN(ub, padded_len); j++) {
        maxkgram2 += (padded_len - j + 1);
    }
    return BSON_MIN(maxkgram1, maxkgram2); // msize
}

static size_t calculate_expected_nfix_tag_count(size_t beta, size_t ub, size_t lb) {
    ASSERT_CMPSIZE_T(beta, <=, (SIZE_MAX - 15));
    ASSERT_CMPSIZE_T(lb, <=, ub);
    size_t padded_len = 16 * ((beta + 5 + 15) / 16) - 5;
    if (lb > padded_len) {
        return 0;
    }
    return BSON_MIN(ub, padded_len) - lb + 1;
}

// Runs _mongocrypt_marking_to_ciphertext to compute the ciphertext for the given marking.
static bool test_text_search_marking_to_ciphertext(_mongocrypt_tester_t *tester,
                                                   mongocrypt_t *crypt,
                                                   _mongocrypt_ciphertext_t *out,
                                                   mongocrypt_fle2_placeholder_type_t type,
                                                   int64_t contention_max,
                                                   mc_FLE2TextSearchInsertSpec_t *test_spec,
                                                   mongocrypt_status_t *status) {
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

    bson_t *marking_bson = bson_new();
    BSON_APPEND_INT32(marking_bson, "t", type);
    BSON_APPEND_INT32(marking_bson, "a", MONGOCRYPT_FLE2_ALGORITHM_TEXT_SEARCH);
    BSON_APPEND_INT64(marking_bson, "cm", contention_max);
    bson_t text_spec;
    BSON_APPEND_DOCUMENT_BEGIN(marking_bson, "v", &text_spec);
    bson_append_utf8(&text_spec, "v", 1, test_spec->v, test_spec->len);
    BSON_APPEND_BOOL(&text_spec, "casef", test_spec->casef);
    BSON_APPEND_BOOL(&text_spec, "diacf", test_spec->diacf);
    if (test_spec->prefix.set) {
        bson_t subspec;
        BSON_APPEND_DOCUMENT_BEGIN(&text_spec, "prefix", &subspec);
        BSON_APPEND_INT32(&subspec, "ub", test_spec->prefix.value.ub);
        BSON_APPEND_INT32(&subspec, "lb", test_spec->prefix.value.lb);
        ASSERT(bson_append_document_end(&text_spec, &subspec));
    }
    if (test_spec->substr.set) {
        bson_t subspec;
        BSON_APPEND_DOCUMENT_BEGIN(&text_spec, "substr", &subspec);
        BSON_APPEND_INT32(&subspec, "mlen", test_spec->substr.value.mlen);
        BSON_APPEND_INT32(&subspec, "ub", test_spec->substr.value.ub);
        BSON_APPEND_INT32(&subspec, "lb", test_spec->substr.value.lb);
        ASSERT(bson_append_document_end(&text_spec, &subspec));
    }
    if (test_spec->suffix.set) {
        bson_t subspec;
        BSON_APPEND_DOCUMENT_BEGIN(&text_spec, "suffix", &subspec);
        BSON_APPEND_INT32(&subspec, "ub", test_spec->suffix.value.ub);
        BSON_APPEND_INT32(&subspec, "lb", test_spec->suffix.value.lb);
        ASSERT(bson_append_document_end(&text_spec, &subspec));
    }
    ASSERT(bson_append_document_end(marking_bson, &text_spec));

    // Add key identifier info to the marking
    BSON_APPEND_BINARY(marking_bson, "ki", BSON_SUBTYPE_UUID, (TEST_BIN(16))->data, 16);
    BSON_APPEND_BINARY(marking_bson, "ku", BSON_SUBTYPE_UUID, (TEST_BIN(16))->data, 16);
    _make_marking(marking_bson, &marking_buf);
    // Use FLE2 as the subtype (default is FLE1)
    marking_buf.data[0] = MC_SUBTYPE_FLE2EncryptionPlaceholder;
    _parse_ok(&marking_buf, &marking);

    bool result = _mongocrypt_marking_to_ciphertext((void *)&ctx->kb, &marking, out, status);

    _mongocrypt_buffer_cleanup(&marking_buf);
    bson_destroy(marking_bson);
    _mongocrypt_marking_cleanup(&marking);
    mongocrypt_ctx_destroy(ctx);
    return result;
}

static void test_mc_marking_to_ciphertext_fle2_text_search(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    // Test substring
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foobar",
                                              .len = 6,
                                              .substr.set = true,
                                              .substr.value = {.mlen = 1000, .ub = 100, .lb = 10}};
        text_search_expected_token_counts counts = {0};
        counts.substrings = calculate_expected_substring_tag_count(6, 1000, 100, 10);

        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                2,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                        2,
                                        &counts);

        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test suffix + prefix
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foobar",
                                              .len = 6,
                                              .suffix.set = true,
                                              .suffix.value = {.ub = 100, .lb = 10},
                                              .prefix.set = true,
                                              .prefix.value = {.ub = 100, .lb = 10}};
        text_search_expected_token_counts counts = {0};
        counts.suffixes = counts.prefixes = calculate_expected_nfix_tag_count(6, 100, 10);

        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                2,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                        2,
                                        &counts);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test empty string
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "",
                                              .len = 0,
                                              .prefix.set = true,
                                              .prefix.value = {.ub = 100, .lb = 10}};
        text_search_expected_token_counts counts = {0};

        // beta is 1 for empty strings
        counts.prefixes = calculate_expected_nfix_tag_count(1, 100, 10);

        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                2,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                        2,
                                        &counts);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test string cbc-padded length is less than lb (ie. substring/suffix/prefix tag sets will be
    // empty)
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foobar",
                                              .len = 6,
                                              .substr.set = true,
                                              .substr.value = {.mlen = 1000, .ub = 100, .lb = 20},
                                              .prefix.set = true,
                                              .prefix.value = {.ub = 100, .lb = 20},
                                              .suffix.set = true,
                                              .suffix.value = {.ub = 100, .lb = 20}};
        text_search_expected_token_counts counts = {0};

        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                2,
                                                                &spec,
                                                                status),
                         status);

        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                        2,
                                        &counts);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test string exceeds mlen
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foobar",
                                              .len = 6,
                                              .substr.set = true,
                                              .substr.value = {.mlen = 3, .ub = 1, .lb = 1}};
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            "longer than the maximum length for substring indexing");

        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test string is not valid utf-8
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        const char *expected_msg = "String passed in was not valid UTF-8";
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foob\xffr",
                                              .len = 6,
                                              .substr.set = true,
                                              .substr.value = {.mlen = INT32_MAX, .ub = 1, .lb = 1}};

        // invalid utf-8 byte 0xff
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);
        _mongocrypt_status_reset(status);

        // embedded null byte
        spec.v = "foob\x00r";
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);
        _mongocrypt_status_reset(status);

        // overlong encoding of 'a' (\x61)
        spec.v = "foob\xE0\x81\xA1r";
        spec.len = 8;
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);

        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test string is too large
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        const char *expected_msg = "String passed in was too long";
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.substr.set = true,
                                              .substr.value = {.mlen = INT32_MAX, .ub = 1, .lb = 1}};

        int len = (16 * 1024 * 1024) + 2;
        char *large_str = bson_malloc(len);
        memset(large_str, 'a', len);
        large_str[len - 1] = '\0';
        spec.v = large_str;
        spec.len = len - 1;

        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);
        bson_free(large_str);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test insert placeholder missing substring/suffix/prefix spec
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        const char *expected_msg = "missing a substring, suffix, or prefix index specification";
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foo", .len = 3};
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test find placeholder has multiple query specs
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        const char *expected_msg = "cannot contain multiple query type specifications";
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foo",
                                              .len = 3,
                                              .substr.set = true,
                                              .substr.value = {.mlen = 3, .ub = 1, .lb = 1},
                                              .prefix.set = true,
                                              .prefix.value = {.ub = 1, .lb = 1}};

        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test find placeholder has invalid UTF-8 string
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        const char *expected_msg = "String passed in was not valid UTF-8";
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foob\xffr",
                                              .len = 6,
                                              .substr.set = true,
                                              .substr.value = {.mlen = 50, .ub = 30, .lb = 1}};

        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                   2,
                                                                   &spec,
                                                                   status),
                            status,
                            expected_msg);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test exact match find
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foo", .len = 3, .diacf = true, .casef = true};
        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                7,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                        7,
                                        NULL);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        _mongocrypt_ciphertext_init(&ciphertext);

        // Test empty string case
        spec.v = "";
        spec.len = 0;
        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                7,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                        7,
                                        NULL);

        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
    }

    // Test substring find
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foo",
                                              .len = 3,
                                              .diacf = true,
                                              .substr.set = true,
                                              .substr.value = {.mlen = 300, .ub = 200, .lb = 2}};
        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                8,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                        8,
                                        NULL);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        _mongocrypt_ciphertext_init(&ciphertext);

        // Test empty string case
        spec.v = "";
        spec.len = 0;
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                   8,
                                                                   &spec,
                                                                   status),
                            status,
                            "string value cannot be empty");
        mongocrypt_status_destroy(status);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        mongocrypt_destroy(crypt);
    }

    // Test suffix find
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foo",
                                              .len = 3,
                                              .casef = true,
                                              .suffix.set = true,
                                              .suffix.value = {.ub = 100, .lb = 1}};
        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                9,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                        9,
                                        NULL);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        _mongocrypt_ciphertext_init(&ciphertext);

        // Test empty string case
        spec.v = "";
        spec.len = 0;
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                   8,
                                                                   &spec,
                                                                   status),
                            status,
                            "string value cannot be empty");
        mongocrypt_status_destroy(status);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        mongocrypt_destroy(crypt);
    }

    // Test prefix find
    {
        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec = {.v = "foo",
                                              .len = 3,
                                              .prefix.set = true,
                                              .prefix.value = {.ub = 300, .lb = 3}};
        ASSERT_OK_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                crypt,
                                                                &ciphertext,
                                                                MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                10,
                                                                &spec,
                                                                status),
                         status);
        validate_text_search_ciphertext(tester,
                                        &ciphertext,
                                        crypt,
                                        &spec,
                                        MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                        10,
                                        NULL);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        _mongocrypt_ciphertext_init(&ciphertext);

        // Test empty string case
        spec.v = "";
        spec.len = 0;
        ASSERT_FAILS_STATUS(test_text_search_marking_to_ciphertext(tester,
                                                                   crypt,
                                                                   &ciphertext,
                                                                   MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND,
                                                                   8,
                                                                   &spec,
                                                                   status),
                            status,
                            "string value cannot be empty");
        mongocrypt_status_destroy(status);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        mongocrypt_destroy(crypt);
    }
}

static void test_ciphertext_len_steps_fle2_text_search(_mongocrypt_tester_t *tester) {
#define MARKING_JSON_FORMAT                                                                                            \
    RAW_STRING({                                                                                                       \
        't' : 1,                                                                                                       \
        'a' : 4,                                                                                                       \
        'v' : {                                                                                                        \
            'v' : "%s",                                                                                                \
            'casef' : false,                                                                                           \
            'diacf' : false,                                                                                           \
            'suffix' : {'ub' : {'$numberInt' : '2'}, 'lb' : {'$numberInt' : '1'}}                                      \
        },                                                                                                             \
        'cm' : {'$numberLong' : '2'}                                                                                   \
    })

    size_t last_len = 0;
    mongocrypt_binary_t *cmd = TEST_FILE("./test/example/cmd.json");
    mongocrypt_binary_t *key_file = TEST_BIN(16);
    mongocrypt_binary_t *ki = TEST_BIN(16);
    mongocrypt_binary_t *ku = TEST_BIN(16);

    for (size_t str_len = 0; str_len < 256; str_len++) {
        char *v = bson_malloc0(str_len + 1);
        memset(v, 'a', str_len);
        size_t bufsize = snprintf(NULL, 0, MARKING_JSON_FORMAT, v) + 1;
        char *markingJSON = bson_malloc(bufsize);
        sprintf(markingJSON, MARKING_JSON_FORMAT, v);
        bson_t *marking_bson = TMP_BSON_STR(markingJSON);

        _mongocrypt_ciphertext_t ciphertext;
        _mongocrypt_ciphertext_init(&ciphertext);
        mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

        get_ciphertext_from_marking_json_with_bufs(crypt, marking_bson, &ciphertext, cmd, key_file, ki, ku);

        // Get res.v, and make sure its size steps when we expect.
        bson_t ciphertext_bson;
        ASSERT(_mongocrypt_buffer_to_bson(&ciphertext.data, &ciphertext_bson));
        iupv2_fields_common res = validate_iupv2_common(&ciphertext_bson);
        if (str_len != 0) {
            // We expect a step in ciphertext len iff str_len + 5 goes from 16k-1 to 16k. 5 is the number of overhead
            // bytes from the BSON header + null byte.
            if ((str_len + 5) % 16 == 0) {
                ASSERT_CMPSIZE_T(res.v.len, ==, last_len + 16);
            } else {
                ASSERT_CMPSIZE_T(res.v.len, ==, last_len);
            }
        }
        last_len = res.v.len;

        bson_destroy(&ciphertext_bson);
        bson_free(markingJSON);
        bson_free(v);
        mongocrypt_destroy(crypt);
        _mongocrypt_ciphertext_cleanup(&ciphertext);
        // Clean up marking_bson and decrement the tester bson_count so we can reuse the space.
        bson_destroy(marking_bson);
        tester->bson_count--;
    }

#undef MARKING_JSON_FORMAT
}

void _mongocrypt_tester_install_marking(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mongocrypt_marking_parse);
    INSTALL_TEST(test_mc_get_mincover_from_FLE2RangeFindSpec);
    INSTALL_TEST(test_mc_marking_to_ciphertext_fle2_range);
    INSTALL_TEST(test_mc_marking_to_ciphertext_fle2_text_search);
    INSTALL_TEST(test_ciphertext_len_steps_fle2_text_search);
}
