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

#include "mongocrypt-binary.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-encryptor-private.h"
#include "mongocrypt-key-broker-private.h"

struct __mongocrypt_tester_t;
typedef void (*_mongocrypt_test_fn) (struct __mongocrypt_tester_t *tester);


typedef struct __mongocrypt_tester_t {
   int test_count;
   /* Arbitrary max of 512 tests. Increase as needed. */
   char *test_names[512];
   _mongocrypt_test_fn test_fns[512];

   int file_count;
   /* Arbitrary max of 512 files. Increase as needed. */
   char *file_paths[512];
   _mongocrypt_buffer_t file_bufs[512];

   /* Example encrypted doc. */
   _mongocrypt_buffer_t encrypted_doc;
} _mongocrypt_tester_t;


/* Return either a .json file as BSON or a .txt file as characters. */
mongocrypt_binary_t *
_mongocrypt_tester_file (_mongocrypt_tester_t *tester, const char *path);


void
_mongocrypt_tester_satisfy_key_broker (_mongocrypt_tester_t *tester,
                                       mongocrypt_key_broker_t *key_broker);


void
_mongocrypt_tester_run_encryptor_to (_mongocrypt_tester_t *tester,
                                     mongocrypt_encryptor_t *encryptor,
                                     mongocrypt_encryptor_state_t stop_state);


mongocrypt_binary_t *
_mongocrypt_tester_encrypted_doc (_mongocrypt_tester_t *tester);


/* Return a repeated character with no null terminator. */
char *
_mongocrypt_repeat_char (char c, uint32_t times);


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
   ASSERT_OR_PRINT_MSG (_statement, mongocrypt_status_message (_err))


#define ASSERT_OR_PRINT_BSON(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, _err.message)

#define ASSERT_STATUS_CONTAINS(_str) \
   BSON_ASSERT (strstr (status->message, _str))


void
_mongocrypt_tester_install (_mongocrypt_tester_t *tester,
                            char *name,
                            _mongocrypt_test_fn fn);


void
_mongocrypt_tester_install_crypto (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_log (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_data_key (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_encryptor (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_decryptor (_mongocrypt_tester_t *tester);


void
_mongocrypt_tester_install_ciphertext (_mongocrypt_tester_t *tester);


#define INSTALL_TEST(fn) _mongocrypt_tester_install (tester, #fn, fn)

#endif