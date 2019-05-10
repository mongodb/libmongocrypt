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

#include <mongocrypt-marking-private.h>

#include "test-mongocrypt.h"

static void
_get_bytes (const void *in, char *out, int len)
{
   const unsigned char *src = in;
   char *dest = out;

   for (int i = 0; i < len; i++, dest += 3) {
      sprintf (dest, "%02X ", src[i]);
   }
   dest[-1] = '\0';
}

#define CLEANUP                                  \
   do {                                        \
      bson_value_destroy (&out);               \
      bson_destroy (&wrapper);                 \
      _mongocrypt_marking_cleanup (&marking);  \
      _mongocrypt_buffer_cleanup (&plaintext); \
   } while (0)

#define ASSERT_EXCESS_BYTES_REMOVED(key, wrapped, unwrapped)                            \
   do {                                                               \
      bson_iter_init_find (&iter, bson, key);                         \
      memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));          \
                                                                      \
      bson_append_iter (&wrapper, "", 0, &marking.v_iter);            \
      _get_bytes (bson_get_data (&wrapper), actual, wrapper.len);     \
      BSON_ASSERT (0 == strcmp (wrapped, actual));                    \
                                                                      \
      _mongocrypt_buffer_from_iter (&plaintext, &(&marking)->v_iter); \
      _get_bytes (plaintext.data, actual, plaintext.len);             \
      BSON_ASSERT (0 == strcmp (unwrapped, actual));                  \
   } while (0)

#define REINITIALIZE_VARS                   \
   do {                                     \
      CLEANUP;                              \
      bson_init (&wrapper);                 \
      _mongocrypt_buffer_init (&plaintext); \
      _mongocrypt_marking_init (&marking);  \
   } while (0)

static void
_test_mongocrypt_buffer_from_iter (_mongocrypt_tester_t *tester)
{
   /*
    * This section explains the purpose of each byte in a BSON document. This is
    * used to extract only the value of a BSON document for later storage. Below
    * is an example of the leftmost derivation of one of the BSON documents
    * used for this test.
    *
    * NOTES:
    * - When used as a unary operator, * means that the repetition can occur 0
    *   or more times.
    *
    * - int32     4 bytes (32-bit signed integer, two's complement)
    * - (byte*)   Zero or more modified UTF-8 encoded characters followed by
    *             '\x00'. The (byte*) MUST NOT contain '\x00', hence it is
    *             not full UTF-8.
    *
    * RULES:
    * 1. document ::=  int32 e_list "\x00"     int32 is the total number of
    *                                          bytes comprising the doc.
    * 2. e_list   ::=  element e_list
    *              |   ""
    * 3. element  ::=  "\x02" e_name string    UTF-8 string
    *              |   "\x10" e_name int32 	  32-bit integer
    * 4. e_name   ::=  cstring                 Key name
    * 5. string   ::=  int32 (byte*) "\x00"
    * 6. cstring  ::=  (byte*) "\x00"
    *
    * BELOW IS A LEFTMOST DERIVATION:
    * Let doc = { "" : "?????" }
    *
    * -  doc  ::= int32 e_list "\x00"
    *
    * -- rule2 -> int32 element e_list "\x00"
    * -- rule3 -> int32 "\x02" e_name string e_list "\x00"
    * -- rule4 -> int32 "\x02" cstring string e_list "\x00"
    * -- rule6 -> int32 "\x02" (byte*) "\x00" string e_list "\x00"
    * -- key   -> int32 "\x02" "" "\x00" string e_list "\x00"
    ** The key is an empty string, i.e. 0 bytes **
    * -- rule5 -> int32 "\x02" "" "\x00" int32 (byte*) "\x00" e_list "\x00"
    * -- value -> int32 "\x02" "" "\x00" int32=6 "?????" "\x00" e_list "\x00"
    ** Above, the value is set. The int32 before the value is the size of the **
    ** value in bytes, plus one for the the null char. **
    * -- rule2 -> int32=17 "\x02" "" "\x00" int32=6 "?????" "\x00" "" "\x00"
    *
    * Finally, we have the byte sequence:
    *    "11000000 02 "" 00 06000000 "?????" 00 00"
    *
    * Note, the hexcode for '?' is '3F'. Grouping the sequence by byte for
    * readability, more precisely we have:
    *    "11 00 00 00 02 00 06 00 00 00 3F 3F 3F 3F 3F 00 00"
    *
    * with the value, including its length and null terminator being:
    *    "06 00 00 00 3F 3F 3F 3F 3F 00".
    * This is what we will store.
    */

   _mongocrypt_buffer_t plaintext = {0};
   _mongocrypt_marking_t marking = {0};
   bson_iter_t iter;
   bson_t *bson;
   bson_t wrapper = BSON_INITIALIZER;
   bson_value_t out;
   char *expected_string = "?????"; /* 3F 3F 3F 3F 3F */
   char actual[100] = {0};
   int expected_int = 5555555; /* 54 C5 63 */

   bson = bson_new ();
   BSON_APPEND_UTF8 (bson, "str_key", expected_string);
   BSON_APPEND_INT32 (bson, "int_key", expected_int);

   ASSERT_EXCESS_BYTES_REMOVED (
      "str_key",
      "11 00 00 00 02 00 06 00 00 00 3F 3F 3F 3F 3F 00 00",
      /** no prefix **/ "06 00 00 00 3F 3F 3F 3F 3F 00");
   BSON_ASSERT (_mongocrypt_buffer_to_bson_value (
      &plaintext, 0x02 /* string type */, &out));

   BSON_ASSERT (0 == strcmp (expected_string, out.value.v_utf8.str));
   BSON_ASSERT (5 == out.value.v_utf8.len);


   REINITIALIZE_VARS;
   ASSERT_EXCESS_BYTES_REMOVED ("int_key",
                                "0B 00 00 00 10 00 63 C5 54 00 00",
                                /** no prefix **/ "63 C5 54 00");
   BSON_ASSERT (
      _mongocrypt_buffer_to_bson_value (&plaintext, 0x10 /* int type */, &out));

   BSON_ASSERT (expected_int == out.value.v_int32);

   REINITIALIZE_VARS;
   ASSERT_EXCESS_BYTES_REMOVED ("int_key",
                                "0B 00 00 00 10 00 63 C5 54 00 00",
                                /** no prefix **/ "63 C5 54 00");
   BSON_ASSERT (!_mongocrypt_buffer_to_bson_value (
      &plaintext, 0x99 /* invalid type */, &out));

   bson_destroy (bson);
   CLEANUP;
}

void
_mongocrypt_tester_install_buffer (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_mongocrypt_buffer_from_iter);
}
