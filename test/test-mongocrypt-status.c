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

#include "mongocrypt.h"
#include "test-mongocrypt.h"

static void
_test_status_len (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   const char *out;
   char *somestring = "somestring";
   char *largestring;
   uint32_t out_len;
   const uint32_t errcode = 123;

   status = mongocrypt_status_new ();

   /* Due to legacy behavior, the string length, if not specified as -1, is 1 +
    * string's length + 1 */
   mongocrypt_status_set (status,
                          MONGOCRYPT_STATUS_ERROR_CLIENT,
                          errcode,
                          somestring,
                          3 /* strlen + 1 */);
   out = mongocrypt_status_message (status, &out_len);
   BSON_ASSERT (0 == strcmp ("so", out));
   /* But the returned length is normal. */
   BSON_ASSERT (2 == out_len);

   /* With passing -1, the entire string should be copied */
   mongocrypt_status_set (
      status, MONGOCRYPT_STATUS_ERROR_CLIENT, errcode, somestring, -1);
   out = mongocrypt_status_message (status, &out_len);
   BSON_ASSERT (0 == strcmp ("somestring", out));
   /* But the returned length is normal. */
   BSON_ASSERT (strlen (somestring) == out_len);

   /* Test setting a large string. */
   largestring = bson_malloc (4096);
   memset (largestring, 'a', 4096);
   mongocrypt_status_set (
      status, MONGOCRYPT_STATUS_ERROR_CLIENT, errcode, largestring, 4097);
   out = mongocrypt_status_message (status, &out_len);
   BSON_ASSERT (0 == strncmp (largestring, out, 4096));
   /* But the returned length is normal. */
   BSON_ASSERT (4096 == out_len);

   /* Test passing 0 as the length. Despite the fact that the length should be 1
    * + the string length, this is treated as a special case as if it were
    * passing the empty string. */
   mongocrypt_status_set (
      status, MONGOCRYPT_STATUS_ERROR_CLIENT, errcode, somestring, 0);
   out = mongocrypt_status_message (status, &out_len);
   BSON_ASSERT (0 == strcmp ("", out));
   BSON_ASSERT (0 == out_len);

   /* Test passing 1 as the length */
   mongocrypt_status_set (
      status, MONGOCRYPT_STATUS_ERROR_CLIENT, errcode, somestring, 1);
   out = mongocrypt_status_message (status, &out_len);
   BSON_ASSERT (0 == strcmp ("", out));
   BSON_ASSERT (0 == out_len);

   bson_free (largestring);
   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_status (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_status_len);
}