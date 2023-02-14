/*
 * Copyright 2021-present MongoDB, Inc.
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

#ifndef TEST_MONGOCRYPT_ASSERT_H
#define TEST_MONGOCRYPT_ASSERT_H

#include "test-mongocrypt-util.h"

#include "mongocrypt.h"

#include <bson/bson.h>

#include <stdio.h>

#define TEST_ERROR(...)                                                        \
   do {                                                                        \
      fprintf (                                                                \
         stderr, "test error %s:%d %s(): ", __FILE__, __LINE__, __FUNCTION__); \
      fprintf (stderr, __VA_ARGS__);                                           \
      fprintf (stderr, "\n");                                                  \
      fflush (stderr);                                                         \
      abort ();                                                                \
   } while (0)

#define ASSERT(stmt)                             \
   if (!(stmt)) {                                \
      TEST_ERROR ("statement failed %s", #stmt); \
   }

#define ASSERT_OR_PRINT_MSG(_statement, msg)                        \
   do {                                                             \
      if (!(_statement)) {                                          \
         TEST_ERROR ("%s failed with msg: %s", #_statement, (msg)); \
      }                                                             \
   } while (0)

#define ASSERT_OR_PRINT(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, mongocrypt_status_message (_err, NULL))

#define ASSERT_OK_STATUS(_stmt, _status)                                   \
   do {                                                                    \
      bool _retval = (_stmt);                                              \
      bool _status_ok = mongocrypt_status_ok (_status);                    \
      const char *_msg = mongocrypt_status_message (_status, NULL);        \
      if (!_retval) {                                                      \
         TEST_ERROR ("%s failed with msg: %s\n", #_stmt, _msg);            \
      } else if (!_status_ok) {                                            \
         TEST_ERROR (                                                      \
            "%s resulted in unexpected error status: %s\n", #_stmt, _msg); \
      }                                                                    \
   } while (0)

#define ASSERT_FAILS_STATUS(_stmt, _status, _msg_pattern)                      \
   do {                                                                        \
      bool _retval = (_stmt);                                                  \
      bool _status_ok = mongocrypt_status_ok (_status);                        \
      const char *_msg = mongocrypt_status_message (_status, NULL);            \
      bool _found_msg = _msg && strstr (_msg, _msg_pattern) != NULL;           \
      if (_retval) {                                                           \
         TEST_ERROR ("%s succeeded (but should have failed) with msg: '%s'\n", \
                     #_stmt,                                                   \
                     _msg_pattern);                                            \
      } else if (_status_ok) {                                                 \
         TEST_ERROR (                                                          \
            "%s resulted in unexpected ok status: %s\n", #_stmt, _msg);        \
      } else if (!_found_msg) {                                                \
         TEST_ERROR ("'%s' does not contain '%s'\n", _msg, _msg_pattern);      \
      }                                                                        \
   } while (0)

#define ASSERT_OK(_stmt, _obj) ASSERT_OK_STATUS (_stmt, (_obj)->status)

#define ASSERT_FAILS(_stmt, _obj, _msg_pattern) \
   ASSERT_FAILS_STATUS (_stmt, (_obj)->status, _msg_pattern)

#define ASSERT_OR_PRINT_BSON(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, _err.message)

#define ASSERT_STATUS_CONTAINS(status, _msg_pattern) \
   ASSERT_FAILS_STATUS (false, status, _msg_pattern)

#define ASSERT_STREQUAL(_expr_a, _expr_b)                                  \
   do {                                                                    \
      const char *_str_a = (_expr_a);                                      \
      const char *_str_b = (_expr_b);                                      \
      ASSERT (_str_a);                                                     \
      ASSERT (_str_b);                                                     \
      int _ret = strcmp (_str_a, _str_b);                                  \
      if (_ret != 0) {                                                     \
         TEST_ERROR ("strings not equal:\n%s\nvs.\n%s\n", _str_a, _str_b); \
      }                                                                    \
   } while (0);

#define ASSERT_STRCONTAINS(_expr_a, _expr_b)                             \
   do {                                                                  \
      const char *_str_a = (_expr_a);                                    \
      const char *_str_b = (_expr_b);                                    \
      char *_ret = strstr (_str_a, _str_b);                              \
      if (_ret == NULL) {                                                \
         TEST_ERROR ("string %s does not contain %s\n", _str_a, _str_b); \
      }                                                                  \
   } while (0);

#define ASSERT_STATE_EQUAL(actual, expected)                       \
   do {                                                            \
      if (actual != expected) {                                    \
         TEST_ERROR ("actual state: %s, but expected state: %s\n", \
                     mongocrypt_ctx_state_to_string (actual),      \
                     mongocrypt_ctx_state_to_string (expected));   \
         abort ();                                                 \
      }                                                            \
   } while (0)

#define ASSERT_CMPBYTES(                                                \
   expected_bytes, expected_len, actual_bytes, actual_len)              \
   do {                                                                 \
      char *_actual_hex = data_to_hex (actual_bytes, actual_len);       \
      char *_expected_hex = data_to_hex (expected_bytes, expected_len); \
      ASSERT_STREQUAL (_actual_hex, _expected_hex);                     \
      free (_actual_hex);                                               \
      free (_expected_hex);                                             \
   } while (0)

#define ASSERT_CMPBUF(expected, actual) \
   ASSERT_CMPBYTES (                    \
      (expected).data, (expected).len, (actual).data, (actual).len)

#define ASSERT_CMP_HELPER(_a, _operator, _b, fmt, type)      \
   do {                                                      \
      type _a_value = (_a);                                  \
      type _b_value = (_b);                                  \
      if (!(_a_value _operator _b_value)) {                  \
         TEST_ERROR ("comparison failed: %" fmt " %s %" fmt, \
                     _a_value,                               \
                     #_operator,                             \
                     _b_value);                              \
      }                                                      \
   } while (0);

#define ASSERT_CMPINT(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "d", int)
#define ASSERT_CMPUINT(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "u", unsigned int)
#define ASSERT_CMPLONG(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "ld", long)
#define ASSERT_CMPULONG(a, eq, b) \
   ASSERT_CMP_HELPER (a, eq, b, "lu", unsigned long)
#define ASSERT_CMPINT8(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, PRId8, int8_t)
#define ASSERT_CMPINT32(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, PRId32, int32_t)
#define ASSERT_CMPINT64(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, PRId64, int64_t)
#define ASSERT_CMPUINT8(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, PRIu8, uint8_t)
#define ASSERT_CMPUINT16(a, eq, b) \
   ASSERT_CMP_HELPER (a, eq, b, PRIu16, uint16_t)
#define ASSERT_CMPUINT32(a, eq, b) \
   ASSERT_CMP_HELPER (a, eq, b, PRIu32, uint32_t)
#define ASSERT_CMPUINT64(a, eq, b) \
   ASSERT_CMP_HELPER (a, eq, b, PRIu64, uint64_t)
#define ASSERT_CMPSIZE_T(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "zu", size_t)
#define ASSERT_CMPSSIZE_T(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "zd", ssize_t)
#define ASSERT_CMPDOUBLE(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "f", double)
#define ASSERT_CMPPTR(a, eq, b) ASSERT_CMP_HELPER (a, eq, b, "p", const void *)

#define ASSERT_CMPINT128_EQ(A, B)                              \
   if (1) {                                                    \
      mlib_int128 left = (A);                                  \
      mlib_int128 right = (B);                                 \
      const bool result = mlib_int128_eq (left, right);        \
      if (!result) {                                           \
         TEST_ERROR ("Comparison failed: %s == %s (%s != %s)", \
                     #A,                                       \
                     #B,                                       \
                     mlib_int128_format (left).str,            \
                     mlib_int128_format (right).str);          \
      }                                                        \
   } else                                                      \
      ((void) 0)

#define ASSERT_EQUAL_BSON(expected, actual)                                   \
   do {                                                                       \
      bson_t *_expected_bson = expected, *_actual_bson = actual;              \
      char *_expected_str, *_actual_str;                                      \
      _expected_str = bson_as_canonical_extended_json (_expected_bson, NULL); \
      _actual_str = bson_as_canonical_extended_json (_actual_bson, NULL);     \
      if (!bson_equal (_expected_bson, _actual_bson)) {                       \
         TEST_ERROR ("BSON unequal.\nExpected: %s\n     Got: %s",             \
                     _expected_str,                                           \
                     _actual_str);                                            \
      }                                                                       \
      bson_free (_actual_str);                                                \
      bson_free (_expected_str);                                              \
   } while (0)

#define ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(expected, actual)                  \
   do {                                                                        \
      bson_t _expected_bson, _actual_bson;                                     \
      char *_expected_str, *_actual_str;                                       \
      ASSERT (_mongocrypt_binary_to_bson (expected, &_expected_bson));         \
      ASSERT (_mongocrypt_binary_to_bson (actual, &_actual_bson));             \
      _expected_str = bson_as_canonical_extended_json (&_expected_bson, NULL); \
      _actual_str = bson_as_canonical_extended_json (&_actual_bson, NULL);     \
      if (!bson_equal (&_expected_bson, &_actual_bson)) {                      \
         TEST_ERROR ("BSON unequal.\nExpected: %s\n     Got: %s",              \
                     _expected_str,                                            \
                     _actual_str);                                             \
      }                                                                        \
      bson_free (_actual_str);                                                 \
      bson_free (_expected_str);                                               \
   } while (0)

#endif /* TEST_MONGOCRYPT_ASSERT_H */
