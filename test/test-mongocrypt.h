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

#ifndef TEST_MONGOCRYPT_H
#define TEST_MONGOCRYPT_H

#include <bson/bson.h>
#include <stdint.h>

#include "mongocrypt.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-kms-ctx-private.h"
#include "mongocrypt-key-broker-private.h"

struct __mongocrypt_tester_t;
typedef void (*_mongocrypt_test_fn) (struct __mongocrypt_tester_t *tester);

/* Arbitrary max of 1024 instances of temporary test data. Increase as needed.
 */
#define TEST_DATA_COUNT 1024
typedef struct __mongocrypt_tester_t {
   int test_count;
   char *test_names[TEST_DATA_COUNT];
   _mongocrypt_test_fn test_fns[TEST_DATA_COUNT];

   int file_count;
   char *file_paths[TEST_DATA_COUNT];
   _mongocrypt_buffer_t file_bufs[TEST_DATA_COUNT];

   int bson_count;
   bson_t test_bson[TEST_DATA_COUNT];

   int bin_count;
   mongocrypt_binary_t *test_bin[TEST_DATA_COUNT];

   int blob_count;
   uint8_t *test_blob[TEST_DATA_COUNT];

   char *key_file_path;

   /* Example encrypted doc. */
   _mongocrypt_buffer_t encrypted_doc;
} _mongocrypt_tester_t;


/* Load a .json file as bson */
void
_load_json_as_bson (const char *path, bson_t *out);


void
_mongocrypt_tester_satisfy_kms (_mongocrypt_tester_t *tester,
                                mongocrypt_kms_ctx_t *kms);


void
_mongocrypt_tester_run_ctx_to (_mongocrypt_tester_t *tester,
                               mongocrypt_ctx_t *ctx,
                               mongocrypt_ctx_state_t stop_state);


mongocrypt_binary_t *
_mongocrypt_tester_encrypted_doc (_mongocrypt_tester_t *tester);


/* Return a repeated character with no null terminator. */
char *
_mongocrypt_repeat_char (char c, uint32_t times);

void
_mongocrypt_tester_fill_buffer (_mongocrypt_buffer_t *buf, int n);


/* Return a new initialized mongocrypt_t for testing. */
mongocrypt_t *
_mongocrypt_tester_mongocrypt (void);


#define ASSERT_OR_PRINT_MSG(_statement, msg)          \
   do {                                               \
      if (!(_statement)) {                            \
         fprintf (stderr,                             \
                  "FAIL:%s:%d  %s()\n  %s\n  %s\n\n", \
                  __FILE__,                           \
                  __LINE__,                           \
                  BSON_FUNC,                          \
                  #_statement,                        \
                  (msg));                             \
         fflush (stderr);                             \
         abort ();                                    \
      }                                               \
   } while (0)


#define ASSERT_OR_PRINT(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, mongocrypt_status_message (_err, NULL))

#define ASSERT_OK_STATUS(_stmt, _status)                            \
   do {                                                             \
      bool _retval = (_stmt);                                       \
      bool _status_ok = mongocrypt_status_ok (_status);             \
      const char *_msg = mongocrypt_status_message (_status, NULL); \
      if (!_retval) {                                               \
         fprintf (stderr, "%s failed with msg: %s", #_stmt, _msg);  \
      } else if (!_status_ok) {                                     \
         fprintf (stderr,                                           \
                  "%s resulted in unexpected error status: %s\n",   \
                  #_stmt,                                           \
                  _msg);                                            \
      }                                                             \
      BSON_ASSERT (_retval &&_status_ok);                           \
   } while (0)

#define ASSERT_FAILS_STATUS(_stmt, _status, _msg_pattern)                      \
   do {                                                                        \
      bool _retval = (_stmt);                                                  \
      bool _status_ok = mongocrypt_status_ok (_status);                        \
      const char *_msg = mongocrypt_status_message (_status, NULL);            \
      bool _found_msg = _msg && strstr (_msg, _msg_pattern) != NULL;           \
      if (_retval) {                                                           \
         fprintf (stderr,                                                      \
                  "%s succeeded (but should have failed) with msg: '%s'",      \
                  #_stmt,                                                      \
                  _msg_pattern);                                               \
      } else if (_status_ok) {                                                 \
         fprintf (stderr,                                                      \
                  "%s resulted in unexpected ok status: %s\n",                 \
                  #_stmt,                                                      \
                  _msg);                                                       \
      } else if (!_found_msg) {                                                \
         fprintf (stderr, "'%s' does not contain '%s'\n", _msg, _msg_pattern); \
      }                                                                        \
      BSON_ASSERT (!_retval && !_status_ok && _found_msg);                     \
   } while (0)

#define ASSERT_OK(_stmt, _obj) ASSERT_OK_STATUS (_stmt, (_obj)->status)

#define ASSERT_FAILS(_stmt, _obj, _msg_pattern) \
   ASSERT_FAILS_STATUS (_stmt, (_obj)->status, _msg_pattern)

#define ASSERT_OR_PRINT_BSON(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, _err.message)

#define ASSERT_STATUS_CONTAINS(status, _msg_pattern) \
   ASSERT_FAILS_STATUS (false, status, _msg_pattern)

#define ASSERT_STREQUAL(_expr_a, _expr_b)                                 \
   do {                                                                   \
      const char *_str_a = (_expr_a);                                     \
      const char *_str_b = (_expr_b);                                     \
      int _ret = strcmp (_str_a, _str_b);                                 \
      if (_ret != 0) {                                                    \
         fprintf (                                                        \
            stderr, "strings not equal:\n%s\nvs.\n%s\n", _str_a, _str_b); \
      }                                                                   \
      BSON_ASSERT (0 == _ret);                                            \
   } while (0);

#define ASSERT_STRCONTAINS(_expr_a, _expr_b)                                  \
   do {                                                                       \
      const char *_str_a = (_expr_a);                                         \
      const char *_str_b = (_expr_b);                                         \
      char *_ret = strstr (_str_a, _str_b);                                   \
      if (_ret == NULL) {                                                     \
         fprintf (stderr, "string %s does not contain %s\n", _str_a, _str_b); \
      }                                                                       \
      BSON_ASSERT (NULL != _ret);                                             \
   } while (0);

void
_assert_bin_bson_equal (mongocrypt_binary_t *bin_a, mongocrypt_binary_t *bin_b);

void
_assert_match_bson (const bson_t *doc, const bson_t *pattern);

const char* mongocrypt_ctx_state_to_string (mongocrypt_ctx_state_t state);

#define ASSERT_STATE_EQUAL(actual, expected)                    \
   do {                                                         \
      if (actual != expected) {                                 \
         fprintf (stderr,                                       \
                  "actual state: %s, but expected state: %s\n", \
                  mongocrypt_ctx_state_to_string (actual),      \
                  mongocrypt_ctx_state_to_string (expected));   \
         abort ();                                              \
      }                                                         \
   } while (0)

typedef enum {
   CRYPTO_REQUIRED,
   CRYPTO_OPTIONAL,
   CRYPTO_PROHIBITED
} _mongocrypt_tester_crypto_spec_t;

void
_mongocrypt_tester_install (_mongocrypt_tester_t *tester,
                            char *name,
                            _mongocrypt_test_fn fn,
                            _mongocrypt_tester_crypto_spec_t crypto_spec);


const char *
_mongocrypt_tester_plaintext (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_crypto (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_log (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_data_key (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_ctx (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_ctx_encrypt (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_ctx_decrypt (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_ciphertext (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_key_broker (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_local_kms (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_cache (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_buffer (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_ctx_setopt (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_key (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_marking (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_traverse_util (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_crypto_hooks (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_key_cache (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_kms_responses (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_status (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_endpoint (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_kek (_mongocrypt_tester_t *tester);

void
_mongocrypt_tester_install_cache_oauth (_mongocrypt_tester_t *tester);

/* Conveniences for getting test data. */

/* Get a temporary bson_t from a JSON string. Do not free it. */
bson_t *
_mongocrypt_tester_bson_from_json (_mongocrypt_tester_t *tester,
                                   const char *json,
                                   ...);
#define TMP_BSON(...) _mongocrypt_tester_bson_from_json (tester, __VA_ARGS__)

/* Get a temporary binary from a JSON string. Do not free it. */
mongocrypt_binary_t *
_mongocrypt_tester_bin_from_json (_mongocrypt_tester_t *tester,
                                  const char *json,
                                  ...);
#define TEST_BSON(...) _mongocrypt_tester_bin_from_json (tester, __VA_ARGS__)

/* Return a binary blob with the repeating sequence of 123. Do not free it. */
mongocrypt_binary_t *
_mongocrypt_tester_bin (_mongocrypt_tester_t *tester, int size);
#define TEST_BIN(size) _mongocrypt_tester_bin (tester, size)

/* Return either a .json file as BSON or a .txt file as characters. Do not free
 * it. */
mongocrypt_binary_t *
_mongocrypt_tester_file (_mongocrypt_tester_t *tester, const char *path);
#define TEST_FILE(path) _mongocrypt_tester_file (tester, path)

#define INSTALL_TEST(fn) \
   _mongocrypt_tester_install (tester, #fn, fn, CRYPTO_REQUIRED)
#define INSTALL_TEST_CRYPTO(fn, crypto) \
   _mongocrypt_tester_install (tester, #fn, fn, crypto)

void
_load_json_as_bson (const char *path, bson_t *out);


#endif
