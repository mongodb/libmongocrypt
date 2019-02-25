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

#include "mongocrypt-private.h"

#ifdef MONGOCRYPT_CRYPTO_COMMONCRYPTO

#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>
/* rumour has it this wasn't in standard Security.h in ~10.8 */
#include <Security/SecRandom.h>


static void
_print_buf (const char *prefix, const _mongocrypt_buffer_t *buf)
{
   uint32_t i;

   printf ("%s has length: %d\n", prefix, buf->len);

   for (i = 0; i < buf->len; i++) {
      printf ("%02x", buf->data[i]);
   }
   printf ("\n");
}

bool
_commoncrypto_aes256_cbc_sha512_encrypt (
   const _mongocrypt_buffer_t *iv,
   const _mongocrypt_buffer_t *associated_data,
   const _mongocrypt_buffer_t *key,
   const _mongocrypt_buffer_t *plaintext,
   _mongocrypt_buffer_t *ciphertext,
   uint32_t *bytes_written,
   mongocrypt_status_t *status)
{
   _print_buf ("ciphertext", ciphertext);
   
   return false;
}

bool
_commoncrypto_aes256_cbc_sha512_decrypt (
   const _mongocrypt_buffer_t *associated_data,
   const _mongocrypt_buffer_t *key,
   const _mongocrypt_buffer_t *ciphertext,
   _mongocrypt_buffer_t *plaintext,
   uint32_t *bytes_written,
   mongocrypt_status_t *status)
{
   return false;
}

bool
_commoncrypto_random_iv (_mongocrypt_buffer_t *out, mongocrypt_status_t *status)
{
   int ret;

   ret = SecRandomCopyBytes (kSecRandomDefault, 16, out->data);
   if (ret != 0) {
      CLIENT_ERR ("failed to generate random IV: %d", ret);
   }
   return true;
}

#endif