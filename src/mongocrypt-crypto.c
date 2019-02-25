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

#include <bson/bson.h>

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"

#if defined(MONGOCRYPT_CRYPTO_OPENSSL)
#include "mongocrypt-openssl-private.h"
#elif defined(MONGOCRYPT_CRYPTO_COMMONCRYPTO)
#include "mongocrypt-commoncrypto-private.h"
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
 * _aes256_cbc_encrypt --
 *
 *    Encrypts using AES256 CBC using a secret key and a known IV.
 *
 * Parameters:
 *    @iv a 16 byte IV.
 *    @key a 32 byte key.
 *    @plaintext the plaintext to encrypt.
 *    @ciphertext the resulting ciphertext.
 *    @bytes_written a location for the resulting number of bytes written into
 *    ciphertext->data.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 * Preconditions:
 *    1. ciphertext->data has been pre-allocated with enough space for the
 *    resulting ciphertext.
 *
 * Postconditions:
 *    1. bytes_written is set to the length of the written ciphertext. This
 *    is the same as _mongocrypt_calculate_ciphertext_len (plaintext->len).
 *
 * ----------------------------------------------------------------------------
 */
static bool
_aes256_cbc_encrypt (const _mongocrypt_buffer_t *iv,
                     const _mongocrypt_buffer_t *key,
                     const _mongocrypt_buffer_t *plaintext,
                     _mongocrypt_buffer_t *ciphertext,
                     uint32_t *bytes_written,
                     mongocrypt_status_t *status)
{
   void *ctx = NULL;
   bool ret = false;
   uint32_t intermediate_bytes_written;
   uint32_t padding_byte;
   _mongocrypt_buffer_t padding, intermediate;

   CRYPT_ENTRY;
   BSON_ASSERT (bytes_written);
   *bytes_written = 0;

   ctx = _crypto_encrypt_new (key, iv, status);
   if (!ctx) {
      goto done;
   }

   if (!_crypto_encrypt_update (
          ctx, plaintext, ciphertext, &intermediate_bytes_written, status)) {
      goto done;
   }

   *bytes_written += intermediate_bytes_written;

   /* [MCGREW]: "Prior to CBC encryption, the plaintext P is padded by appending
    * a padding string PS to that data, to ensure that len(P || PS) is a
    * multiple of 128". */
   padding_byte =
      MONGOCRYPT_BLOCK_SIZE - (plaintext->len % MONGOCRYPT_BLOCK_SIZE);
   if (!padding_byte) {
      padding_byte = MONGOCRYPT_BLOCK_SIZE;
   }

   padding.data = bson_malloc (padding_byte);
   memset (padding.data, padding_byte, padding_byte);
   padding.len = padding_byte;
   padding.owned = true;

   intermediate.data = ciphertext->data + *bytes_written;
   intermediate.len = ciphertext->len - *bytes_written;

   if (!_crypto_encrypt_update (
          ctx, &padding, &intermediate, &intermediate_bytes_written, status)) {
      goto done;
   }

   _mongocrypt_buffer_cleanup (&padding);
   *bytes_written += intermediate_bytes_written;
   BSON_ASSERT (*bytes_written % MONGOCRYPT_BLOCK_SIZE == 0);

   intermediate.data = ciphertext->data + *bytes_written;
   intermediate.len = ciphertext->len - *bytes_written;

   if (!_crypto_encrypt_finalize (
          ctx, &intermediate, &intermediate_bytes_written, status)) {
      goto done;
   }

   BSON_ASSERT (intermediate_bytes_written == 0);

   *bytes_written += intermediate_bytes_written;
   ret = true;

done:
   _crypto_encrypt_destroy (ctx);
   return ret;
}


/* ----------------------------------------------------------------------------
 *
 * _hmac_sha512 --
 *
 *    Compute the SHA512 HMAC with a secret key.
 *
 * Parameters:
 *    @key a 32 byte key.
 *    @associated_data associated data to add into the HMAC. This may be
 *    an empty buffer.
 *    @ciphertext the ciphertext to add into the HMAC.
 *    @out a location for the resulting HMAC tag.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 * Preconditions:
 *    1. out->data has been pre-allocated with at least 64 bytes.
 *
 * Postconditions:
 *    1. out->data will have a 64 byte tag appended.
 *
 * ----------------------------------------------------------------------------
 */
static bool
_hmac_sha512 (const _mongocrypt_buffer_t *key,
              const _mongocrypt_buffer_t *associated_data,
              const _mongocrypt_buffer_t *ciphertext,
              _mongocrypt_buffer_t *out,
              mongocrypt_status_t *status)
{
   void *ctx = NULL;
   bool ret = false;
   uint64_t associated_data_len_be;
   uint32_t bytes_written;
   uint8_t tag_storage[64];
   _mongocrypt_buffer_t tag, associated_data_len;

   CRYPT_ENTRY;
   BSON_ASSERT (MONGOCRYPT_MAC_KEY_LEN == key->len);
   BSON_ASSERT (out->len >= MONGOCRYPT_HMAC_LEN);

   ctx = _crypto_hmac_new (key, status);
   if (!ctx) {
      goto done;
   }

   /* [MCGREW]:
    * """
    * 4.  The octet string AL is equal to the number of bits in A expressed as a
    * 64-bit unsigned integer in network byte order.
    * 5.  A message authentication tag T is computed by applying HMAC [RFC2104]
    * to the following data, in order:
    *      the associated data A,
    *      the ciphertext S computed in the previous step, and
    *      the octet string AL defined above.
    * """
    */

   /* Add associated data. */
   if (!_crypto_hmac_update (ctx, associated_data, status)) {
      goto done;
   }

   /* Add ciphertext. */
   if (!_crypto_hmac_update (ctx, ciphertext, status)) {
      goto done;
   }

   /* Add associated data length in bits. */
   associated_data_len_be = 8 * associated_data->len;
   associated_data_len_be = BSON_UINT64_TO_BE (associated_data_len_be);
   associated_data_len.data =
      (uint8_t *) &associated_data_len_be; /* TODO: for failures, check this. */
   associated_data_len.len = sizeof (uint64_t);
   if (!_crypto_hmac_update (ctx, &associated_data_len, status)) {
      goto done;
   }

   tag.data = tag_storage;
   tag.len = sizeof (tag_storage);
   if (!_crypto_hmac_finalize (ctx, &tag, &bytes_written, status)) {
      goto done;
   }

   BSON_ASSERT (MONGOCRYPT_HMAC_LEN == bytes_written);

   /* [MCGREW 2.7] "The HMAC-SHA-512 value is truncated to T_LEN=32 octets" */
   memcpy (out->data, tag.data, MONGOCRYPT_HMAC_LEN);

   ret = true;
done:
   _crypto_hmac_destroy (ctx);
   return ret;
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
   bool ret = false;
   _mongocrypt_buffer_t mac_key = {0}, enc_key = {0}, intermediate = {0},
                        intermediate_hmac = {0}, empty_buffer = {0};
   uint32_t intermediate_bytes_written = 0;

   CRYPT_ENTRY;

   BSON_ASSERT (ciphertext->len >=
                _mongocrypt_calculate_ciphertext_len (plaintext->len));

   *bytes_written = 0;
   intermediate.len = ciphertext->len;
   intermediate.data = ciphertext->data;

   /* [MCGREW]: Step 1. "MAC_KEY consists of the initial MAC_KEY_LEN octets of
    * K, in order. ENC_KEY consists of the final ENC_KEY_LEN octets of K, in
    * order." */
   mac_key.data = (uint8_t *) key->data;
   mac_key.len = MONGOCRYPT_MAC_KEY_LEN;
   enc_key.data = (uint8_t *) key->data + (key->len - MONGOCRYPT_ENC_KEY_LEN);
   enc_key.len = MONGOCRYPT_ENC_KEY_LEN;

   /* Prepend the IV. */
   memcpy (intermediate.data, iv->data, iv->len);
   intermediate.data += iv->len;
   intermediate.len -= iv->len;
   *bytes_written += iv->len;

   /* [MCGREW]: Steps 2 & 3. */
   if (!_aes256_cbc_encrypt (iv,
                             &enc_key,
                             plaintext,
                             &intermediate,
                             &intermediate_bytes_written,
                             status)) {
      goto done;
   }

   *bytes_written += intermediate_bytes_written;

   /* Append the HMAC tag. */
   intermediate_hmac.data = ciphertext->data + *bytes_written;
   intermediate_hmac.len = MONGOCRYPT_HMAC_LEN;

   intermediate.data = ciphertext->data;
   intermediate.len = *bytes_written;

   /* [MCGREW]: Steps 4 & 5, compute the HMAC. */
   if (!_hmac_sha512 (&mac_key,
                      associated_data ? associated_data : &empty_buffer,
                      &intermediate,
                      &intermediate_hmac,
                      status)) {
      goto done;
   }

   *bytes_written += MONGOCRYPT_HMAC_LEN;
   ret = true;
done:
   return ret;
}


/* ----------------------------------------------------------------------------
 *
 * _aes256_cbc_decrypt --
 *
 *    Decrypts using AES256 CBC using a secret key and a known IV.
 *
 * Parameters:
 *    @key a 32 byte key.
 *    @ciphertext the ciphertext to decrypt.
 *    @plaintext the resulting plaintext.
 *    @bytes_written a location for the resulting number of bytes written into
 *    plaintext->data.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 * Preconditions:
 *    1. plaintext->data has been pre-allocated with enough space for the
 *    resulting plaintext.
 *
 * Postconditions:
 *    1. bytes_written is set to the length of the written plaintext, excluding
 *    padding. This may be less than
 *    _mongocrypt_calculate_plaintext_len (ciphertext->len).
 *
 * ----------------------------------------------------------------------------
 */
static bool
_aes256_cbc_decrypt (const _mongocrypt_buffer_t *iv,
                     const _mongocrypt_buffer_t *key,
                     const _mongocrypt_buffer_t *ciphertext,
                     _mongocrypt_buffer_t *plaintext,
                     uint32_t *bytes_written,
                     mongocrypt_status_t *status)
{
   void *ctx = NULL;
   bool ret = false;
   uint32_t intermediate_bytes_written;
   _mongocrypt_buffer_t intermediate;

   CRYPT_ENTRY;
   BSON_ASSERT (bytes_written);
   *bytes_written = 0;

   if (ciphertext->len % MONGOCRYPT_BLOCK_SIZE > 0) {
      CLIENT_ERR ("error, ciphertext length is not a multiple of block size");
      goto done;
   }

   ctx = _crypto_decrypt_new (key, iv, status);
   if (!ctx) {
      goto done;
   }

   if (!_crypto_decrypt_update (
          ctx, ciphertext, plaintext, bytes_written, status)) {
      goto done;
   }

   *bytes_written += intermediate_bytes_written;

   intermediate.data = plaintext->data + *bytes_written;
   intermediate.len = plaintext->len - *bytes_written;
   if (!_crypto_decrypt_finalize (
          ctx, &intermediate, &intermediate_bytes_written, status)) {
      goto done;
   }

   BSON_ASSERT (intermediate_bytes_written == 0);
   *bytes_written += intermediate_bytes_written;

   /* Subtract the padding. */
   *bytes_written -= plaintext->data[*bytes_written - 1];
   ret = true;
done:
   _crypto_decrypt_destroy (ctx);
   return ret;
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
   bool ret = false;
   _mongocrypt_buffer_t mac_key = {0}, enc_key = {0}, intermediate = {0},
                        hmac_tag = {0}, iv = {0}, empty_buffer = {0};
   uint8_t hmac_tag_storage[MONGOCRYPT_HMAC_LEN];

   CRYPT_ENTRY;

   BSON_ASSERT (plaintext->len >=
                _mongocrypt_calculate_plaintext_len (ciphertext->len));

   if (ciphertext->len <
       MONGOCRYPT_HMAC_LEN + MONGOCRYPT_IV_LEN + MONGOCRYPT_BLOCK_SIZE) {
      CLIENT_ERR ("corrupt ciphertext - must be > %d bytes",
                  MONGOCRYPT_HMAC_LEN + MONGOCRYPT_IV_LEN +
                     MONGOCRYPT_BLOCK_SIZE);
      goto done;
   }

   plaintext->len = ciphertext->len - (MONGOCRYPT_HMAC_LEN + MONGOCRYPT_IV_LEN);
   plaintext->data = bson_malloc0 (plaintext->len);
   plaintext->owned = true;

   mac_key.data = (uint8_t *) key->data;
   mac_key.len = MONGOCRYPT_MAC_KEY_LEN;
   enc_key.data = (uint8_t *) key->data + (key->len - MONGOCRYPT_ENC_KEY_LEN);
   enc_key.len = MONGOCRYPT_ENC_KEY_LEN;

   iv.data = ciphertext->data;
   iv.len = MONGOCRYPT_IV_LEN;

   intermediate.data = (uint8_t *) ciphertext->data;
   intermediate.len = ciphertext->len - MONGOCRYPT_HMAC_LEN;

   hmac_tag.data = hmac_tag_storage;
   hmac_tag.len = MONGOCRYPT_HMAC_LEN;

   /* [MCGREW 2.2]: Step 3: HMAC check. */
   if (!_hmac_sha512 (&mac_key,
                      associated_data ? associated_data : &empty_buffer,
                      &intermediate,
                      &hmac_tag,
                      status)) {
      goto done;
   }

   /* [MCGREW] "using a comparison routine that takes constant time". */
   /* TODO: CRYPTO_memcmp */
   if (0 != memcmp (hmac_tag.data,
                    ciphertext->data + (ciphertext->len - MONGOCRYPT_HMAC_LEN),
                    MONGOCRYPT_HMAC_LEN)) {
      CLIENT_ERR ("HMAC validation failure");
      goto done;
   }

   /* Decrypt data excluding IV + HMAC. */
   intermediate.data = (uint8_t *) ciphertext->data + MONGOCRYPT_IV_LEN;
   intermediate.len =
      ciphertext->len - (MONGOCRYPT_IV_LEN + MONGOCRYPT_HMAC_LEN);

   if (!_aes256_cbc_decrypt (
          &iv, &enc_key, &intermediate, plaintext, bytes_written, status)) {
      goto done;
   }

   ret = true;
done:
   return ret;
}


/* ----------------------------------------------------------------------------
 *
 * _mongocrypt_random_iv --
 *
 *    Generate a random 16 byte IV.
 *
 * Parameters:
 *    @out an output buffer that has been pre-allocated.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 *  Preconditions:
 *    1. out has been pre-allocated with at least 16 bytes of space.
 *
 * ----------------------------------------------------------------------------
 */
bool
_mongocrypt_random_iv (_mongocrypt_buffer_t *out, mongocrypt_status_t *status)
{
   BSON_ASSERT (out->len >= 16);
   return _crypto_random_iv (out, status);
}
