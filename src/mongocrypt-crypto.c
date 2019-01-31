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

/*
 * Comments in this implementation refer to:
 * [MCGREW] https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
 */
#include "mongocrypt-private.h"

#include <bson/bson.h>

#ifdef MONGOC_ENABLE_SSL_OPENSSL
#include "mongocrypt-openssl-private.h"
#endif


/* ----------------------------------------------------------------------------
 *
 * _mongocrypt_calculate_ciphertext_len --
 *
 *    For a given plaintext length, return the length of the ciphertext.
 *    This includes IV and HMAC.
 *
 *    To compute that I'm following section 2.3 in [MCGREW]:
 *    L = 16 * ( floor(M / 16) + 2)
 *    This formula includes space for the IV, but not the sha512 HMAC.
 *    Add 32 for the sha512 HMAC.
 *
 * Parameters:
 *    @plaintext_len then length of the plaintext.
 *
 * Returns:
 *    The calculated length of the ciphertext.
 *
 * ----------------------------------------------------------------------------
 */
uint32_t
_mongocrypt_calculate_ciphertext_len (uint32_t plaintext_len)
{
   return 16 * ((plaintext_len / 16) + 2) + MONGOCRYPT_HMAC_LEN;
}


/* ----------------------------------------------------------------------------
 *
 * _mongocrypt_calculate_plaintext_len --
 *
 *    For a given ciphertext length, return the length of the plaintext.
 *    This excludes the IV and HMAC, but includes the padding.
 *
 * Parameters:
 *    @ciphertext_len then length of the ciphertext.
 *
 * Returns:
 *    The calculated length of the plaintext.
 *
 * ----------------------------------------------------------------------------
 */
uint32_t
_mongocrypt_calculate_plaintext_len (uint32_t ciphertext_len)
{
   BSON_ASSERT (ciphertext_len >= MONGOCRYPT_HMAC_LEN + MONGOCRYPT_IV_LEN +
                                     MONGOCRYPT_BLOCK_SIZE);
   return ciphertext_len - (MONGOCRYPT_IV_LEN + MONGOCRYPT_HMAC_LEN);
}


/* ----------------------------------------------------------------------------
 *
 * _mongocrypt_do_encryption --
 *
 *    Defer encryption to whichever crypto library libmongocrypt is using.
 *
 * Parameters:
 *    @iv a 16 byte IV.
 *    @associated_data associated data for the HMAC. May be NULL.
 *    @key a 32 byte key.
 *    @plaintext the plaintext to encrypt.
 *    @ciphertext a location for the resulting ciphertext and HMAC tag.
 *    @bytes_written a location for the resulting bytes written.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 * Preconditions:
 *    1. ciphertext->data has been pre-allocated with enough space for the
 *    resulting ciphertext. Use _mongocrypt_calculate_ciphertext_len.
 *
 * Postconditions:
 *    1. bytes_written is set to the length of the written ciphertext. This
 *    is the same as _mongocrypt_calculate_ciphertext_len (plaintext->len).
 *
 * ----------------------------------------------------------------------------
 */
bool
_mongocrypt_do_encryption (const _mongocrypt_buffer_t *iv,
                           const _mongocrypt_buffer_t *associated_data,
                           const _mongocrypt_buffer_t *key,
                           const _mongocrypt_buffer_t *plaintext,
                           _mongocrypt_buffer_t *ciphertext,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t empty_buffer = {0};

   CRYPT_ENTRY;

   if (!associated_data) {
      associated_data = &empty_buffer;
   }

   BSON_ASSERT (ciphertext->len >=
                _mongocrypt_calculate_ciphertext_len (plaintext->len));

#ifdef MONGOC_ENABLE_SSL_OPENSSL
   return _openssl_aes256_cbc_sha512_encrypt (
      iv, associated_data, key, plaintext, ciphertext, bytes_written, status);
#else
   CLIENT_ERR ("not configured with any supported crypto library");
   return false;
#endif
}


/* ----------------------------------------------------------------------------
 *
 * _mongocrypt_do_decryption --
 *
 *    Defer decryption to whichever crypto library libmongocrypt is using.
 *
 * Parameters:
 *    @associated_data associated data for the HMAC. May be NULL.
 *    @key a 32 byte key.
 *    @ciphertext the ciphertext to decrypt. This contains the IV prepended.
 *    @plaintext a location for the resulting plaintext.
 *    @bytes_written a location for the resulting bytes written.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 *  Preconditions:
 *    1. plaintext->data has been pre-allocated with enough space for the
 *    resulting plaintext and padding. See _mongocrypt_calculate_plaintext_len.
 *
 *  Postconditions:
 *    1. bytes_written is set to the length of the written plaintext, excluding
 *    padding. This may be less than
 *    _mongocrypt_calculate_plaintext_len (ciphertext->len).
 *
 * ----------------------------------------------------------------------------
 */
bool
_mongocrypt_do_decryption (const _mongocrypt_buffer_t *associated_data,
                           const _mongocrypt_buffer_t *key,
                           const _mongocrypt_buffer_t *ciphertext,
                           _mongocrypt_buffer_t *plaintext,
                           uint32_t *bytes_written,
                           mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t empty_buffer = {0};

   CRYPT_ENTRY;

   if (!associated_data) {
      associated_data = &empty_buffer;
   }

   BSON_ASSERT (plaintext->len >=
                _mongocrypt_calculate_plaintext_len (ciphertext->len));

#ifdef MONGOC_ENABLE_SSL_OPENSSL
   return _openssl_aes256_cbc_sha512_decrypt (
      associated_data, key, ciphertext, plaintext, bytes_written, status);
#else
   CLIENT_ERR ("not configured with any supported crypto library");
   return false;
#endif
}


/* Testing code below. */

/* Return a repeated character with no null terminator. */
static char *
_repeat_char (char c, uint32_t times)
{
   char *result;
   uint32_t i;

   result = bson_malloc (times);
   for (i = 0; i < times; i++) {
      result[i] = c;
   }

   return result;
}


/* Helper to print binary. */
void
_print_buf (const char *prefix, const _mongocrypt_buffer_t *buf)
{
   uint32_t i;

   printf ("%s has length: %d\n", prefix, buf->len);

   for (i = 0; i < buf->len; i++) {
      printf ("%02x", buf->data[i]);
   }
   printf ("\n");
}


void
_mongocrypt_test_roundtrip (void)
{
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key = {0}, iv = {0}, associated_data = {0},
                        plaintext = {0}, ciphertext = {0}, decrypted = {0};
   uint32_t bytes_written;
   bool ret;

   plaintext.data = (uint8_t *) "test";
   plaintext.len = 5; /* include NULL. */

   ciphertext.len = _mongocrypt_calculate_ciphertext_len (5);
   ciphertext.data = bson_malloc (ciphertext.len);
   ciphertext.owned = true;

   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   decrypted.owned = true;

   key.data = (uint8_t *) _repeat_char ('k', 64);
   key.len = 64;
   key.owned = true;

   iv.data = (uint8_t *) _repeat_char ('i', 16);
   iv.len = 16;
   iv.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (&iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);

   BSON_ASSERT (bytes_written == ciphertext.len);

   ret = _mongocrypt_do_decryption (
      &associated_data, &key, &ciphertext, &decrypted, &bytes_written, status);
   BSON_ASSERT (ret);


   BSON_ASSERT (bytes_written == plaintext.len);
   decrypted.len = bytes_written;
   BSON_ASSERT (0 == strcmp ((char *) decrypted.data, (char *) plaintext.data));

   /* Modify a bit in the ciphertext hash to ensure HMAC integrity check. */
   ciphertext.data[ciphertext.len - 1] &= 1;

   _mongocrypt_buffer_cleanup (&decrypted);
   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   decrypted.owned = true;

   ret = _mongocrypt_do_decryption (
      &associated_data, &key, &ciphertext, &decrypted, &bytes_written, status);
   BSON_ASSERT (!ret);
   BSON_ASSERT (0 == strcmp (status->message, "HMAC validation failure"));

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&decrypted);
   _mongocrypt_buffer_cleanup (&ciphertext);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
}


static void
_init_buffer (_mongocrypt_buffer_t *out, const char *hex_string)
{
   int i;

   out->len = strlen (hex_string) / 2;
   out->data = bson_malloc (out->len);
   out->owned = true;
   for (i = 0; i < out->len; i++) {
      int tmp;
      BSON_ASSERT (sscanf (hex_string + (2 * i), "%02x", &tmp));
      *(out->data + i) = (uint8_t) tmp;
   }
}


/* From [MCGREW], see comment at the top of this file. */
void
_mongocrypt_test_mcgrew (void)
{
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key, iv, associated_data, plaintext,
      ciphertext_expected, ciphertext_actual;
   uint32_t bytes_written;
   bool ret;

   _init_buffer (&key,
                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1"
                 "b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
                 "3738393a3b3c3d3e3f");
   _init_buffer (&iv, "1af38c2dc2b96ffdd86694092341bc04");
   _init_buffer (&plaintext,
                 "41206369706865722073797374656d206d757374206e6f742"
                 "0626520726571756972656420746f20626520736563726574"
                 "2c20616e64206974206d7573742062652061626c6520746f2"
                 "066616c6c20696e746f207468652068616e6473206f662074"
                 "686520656e656d7920776974686f757420696e636f6e76656"
                 "e69656e6365");
   _init_buffer (&associated_data,
                 "546865207365636f6e64207072696e6369706c65206"
                 "f662041756775737465204b6572636b686f666673");
   _init_buffer (&ciphertext_expected,
                 "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10f"
                 "fbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e"
                 "9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75"
                 "c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae4"
                 "96b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930"
                 "930806d0703b1f64dd3b4c088a7f45c216839645b2012bf2e6269a8c56a81"
                 "6dbc1b267761955bc5");

   ciphertext_actual.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext_actual.data = bson_malloc (ciphertext_actual.len);
   ciphertext_actual.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (&iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext_actual,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);
   BSON_ASSERT (ciphertext_actual.len == ciphertext_expected.len);
   BSON_ASSERT (0 == memcmp (ciphertext_actual.data,
                             ciphertext_expected.data,
                             ciphertext_actual.len));

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&ciphertext_expected);
   _mongocrypt_buffer_cleanup (&ciphertext_actual);
   mongocrypt_status_destroy (status);
}