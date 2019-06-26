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
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"

/*
 * Secure memcmp copied from the C driver.
 */
int
_mongocrypt_memcmp (const void *const b1, const void *const b2, size_t len)
{
   const unsigned char *p1 = b1, *p2 = b2;
   int ret = 0;

   for (; len > 0; len--) {
      ret |= *p1++ ^ *p2++;
   }

   return ret ? 1 : 0;
}

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
 *    @enc_key a 32 byte key.
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
                     const _mongocrypt_buffer_t *enc_key,
                     const _mongocrypt_buffer_t *plaintext,
                     _mongocrypt_buffer_t *ciphertext,
                     uint32_t *bytes_written,
                     mongocrypt_status_t *status)
{
   void *ctx = NULL;
   bool ret = false;
   uint32_t intermediate_bytes_written;
   uint32_t unaligned;
   uint32_t padding_byte;
   _mongocrypt_buffer_t intermediate_in, intermediate_out;
   uint8_t final_block_storage[MONGOCRYPT_BLOCK_SIZE];

   BSON_ASSERT (bytes_written);
   *bytes_written = 0;

   ctx = _crypto_encrypt_new (enc_key, iv, status);
   if (!ctx) {
      goto done;
   }

   /* calculate how many extra bytes there are after a block boundary */
   unaligned = plaintext->len % MONGOCRYPT_BLOCK_SIZE;

   /* Some crypto providers disallow variable length inputs, and require
    * the input to be a multiple of the block size. So add everything up
    * to but excluding the last block if not block aligned, then add
    * the last block with padding. */
   intermediate_in.data = (uint8_t *) plaintext->data;
   intermediate_in.len = plaintext->len - unaligned;
   intermediate_out.data = (uint8_t *) ciphertext->data;
   intermediate_out.len = ciphertext->len;
   if (!_crypto_encrypt_update (ctx,
                                &intermediate_in,
                                &intermediate_out,
                                &intermediate_bytes_written,
                                status)) {
      goto done;
   }

   *bytes_written += intermediate_bytes_written;
   intermediate_out.data = ciphertext->data + *bytes_written;
   intermediate_out.len = ciphertext->len - *bytes_written;

   /* [MCGREW]: "Prior to CBC encryption, the plaintext P is padded by appending
    * a padding string PS to that data, to ensure that len(P || PS) is a
    * multiple of 128". This is also known as PKCS #7 padding. */
   intermediate_in.data = final_block_storage;
   intermediate_in.len = sizeof (final_block_storage);
   if (unaligned) {
      /* Copy the unaligned bytes. */
      memcpy (intermediate_in.data,
              plaintext->data + (plaintext->len - unaligned),
              unaligned);
      /* Fill the rest with the padding byte. */
      padding_byte = MONGOCRYPT_BLOCK_SIZE - unaligned;
      memset (intermediate_in.data + unaligned, padding_byte, padding_byte);
   } else {
      /* Fill the rest with the padding byte. */
      padding_byte = MONGOCRYPT_BLOCK_SIZE;
      memset (intermediate_in.data, padding_byte, padding_byte);
   }

   if (!_crypto_encrypt_update (ctx,
                                &intermediate_in,
                                &intermediate_out,
                                &intermediate_bytes_written,
                                status)) {
      goto done;
   }

   *bytes_written += intermediate_bytes_written;
   intermediate_out.data = ciphertext->data + *bytes_written;
   intermediate_out.len = ciphertext->len - *bytes_written;

   BSON_ASSERT (*bytes_written % MONGOCRYPT_BLOCK_SIZE == 0);

   if (!_crypto_encrypt_finalize (
          ctx, &intermediate_out, &intermediate_bytes_written, status)) {
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
 *    @mac_key a 32 byte key.
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
_hmac_sha512 (const _mongocrypt_buffer_t *mac_key,
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

   BSON_ASSERT (MONGOCRYPT_MAC_KEY_LEN == mac_key->len);
   BSON_ASSERT (out->len >= MONGOCRYPT_HMAC_LEN);

   ctx = _crypto_hmac_new (mac_key, status);
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
   associated_data_len.data = (uint8_t *) &associated_data_len_be;
   associated_data_len.len = sizeof (uint64_t);
   if (!_crypto_hmac_update (ctx, &associated_data_len, status)) {
      goto done;
   }

   tag.data = tag_storage;
   tag.len = sizeof (tag_storage);
   if (!_crypto_hmac_finalize (ctx, &tag, &bytes_written, status)) {
      goto done;
   }

   BSON_ASSERT (MONGOCRYPT_HMAC_SHA512_LEN == bytes_written);

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
 *    @key a 96 byte key.
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

   BSON_ASSERT (iv);
   BSON_ASSERT (key);
   BSON_ASSERT (plaintext);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (ciphertext->len >=
                _mongocrypt_calculate_ciphertext_len (plaintext->len));

   *bytes_written = 0;

   if (iv->len != MONGOCRYPT_IV_LEN) {
      CLIENT_ERR ("invalid iv len");
      return false;
   }
   if (key->len != MONGOCRYPT_KEY_LEN) {
      CLIENT_ERR ("invalid key len");
      return false;
   }

   intermediate.len = ciphertext->len;
   intermediate.data = ciphertext->data;

   /* [MCGREW]: Step 1. "MAC_KEY consists of the initial MAC_KEY_LEN octets of
    * K, in order. ENC_KEY consists of the final ENC_KEY_LEN octets of K, in
    * order." */
   mac_key.data = (uint8_t *) key->data;
   mac_key.len = MONGOCRYPT_MAC_KEY_LEN;
   enc_key.data = (uint8_t *) key->data + MONGOCRYPT_MAC_KEY_LEN;
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
 *    @enc_key a 32 byte key.
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
                     const _mongocrypt_buffer_t *enc_key,
                     const _mongocrypt_buffer_t *ciphertext,
                     _mongocrypt_buffer_t *plaintext,
                     uint32_t *bytes_written,
                     mongocrypt_status_t *status)
{
   void *ctx = NULL;
   bool ret = false;
   uint32_t intermediate_bytes_written;
   _mongocrypt_buffer_t intermediate;
   uint8_t padding_byte;

   BSON_ASSERT (bytes_written);
   *bytes_written = 0;

   if (ciphertext->len % MONGOCRYPT_BLOCK_SIZE > 0) {
      CLIENT_ERR ("error, ciphertext length is not a multiple of block size");
      goto done;
   }

   ctx = _crypto_decrypt_new (enc_key, iv, status);
   if (!ctx) {
      goto done;
   }

   if (!_crypto_decrypt_update (
          ctx, ciphertext, plaintext, &intermediate_bytes_written, status)) {
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
   plaintext->len = *bytes_written;
   padding_byte = plaintext->data[*bytes_written - 1];
   if (padding_byte > 16) {
      CLIENT_ERR ("error, ciphertext malformed padding");
      goto done;
   }
   *bytes_written -= padding_byte;
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
 *    @key a 96 byte key.
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

   BSON_ASSERT (key);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (plaintext);
   BSON_ASSERT (bytes_written);
   BSON_ASSERT (status);
   BSON_ASSERT (plaintext->len >=
                _mongocrypt_calculate_plaintext_len (ciphertext->len));

   if (key->len != MONGOCRYPT_KEY_LEN) {
      CLIENT_ERR ("invalid key len");
      return false;
   }

   if (ciphertext->len <
       MONGOCRYPT_HMAC_LEN + MONGOCRYPT_IV_LEN + MONGOCRYPT_BLOCK_SIZE) {
      CLIENT_ERR ("corrupt ciphertext - must be > %d bytes",
                  MONGOCRYPT_HMAC_LEN + MONGOCRYPT_IV_LEN +
                     MONGOCRYPT_BLOCK_SIZE);
      goto done;
   }

   mac_key.data = (uint8_t *) key->data;
   mac_key.len = MONGOCRYPT_MAC_KEY_LEN;
   enc_key.data = (uint8_t *) key->data + MONGOCRYPT_MAC_KEY_LEN;
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
   if (0 != _mongocrypt_memcmp (hmac_tag.data,
                                ciphertext->data +
                                   (ciphertext->len - MONGOCRYPT_HMAC_LEN),
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
 * _mongocrypt_random --
 *
 *    Generates a string of random bytes.
 *
 * Parameters:
 *    @out an output buffer that has been pre-allocated.
 *    @status set on error.
 *    @count the size of the random string in bytes.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 *  Preconditions:
 *    1. out has been pre-allocated with at least 'count' bytes of space.
 *
 * ----------------------------------------------------------------------------
 */
bool
_mongocrypt_random (_mongocrypt_buffer_t *out,
                    mongocrypt_status_t *status,
                    uint32_t count)
{
   BSON_ASSERT (out);
   BSON_ASSERT (status);
   BSON_ASSERT (out->len >= count);
   return _crypto_random (out, status, count);
}


/* ----------------------------------------------------------------------------
 *
 * _mongocrypt_calculate_deterministic_iv --
 *
 *    Compute the IV for deterministic encryption from the plaintext and IV
 *    key by using HMAC function.
 *
 * Parameters:
 *    @key the 96 byte key. The last 32 represent the IV key.
 *    @plaintext the plaintext to be encrypted.
 *    @associated_data associated data to include in the HMAC.
 *    @out an output buffer that has been pre-allocated.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 *  Preconditions:
 *    1. out has been pre-allocated with at least MONGOCRYPT_IV_LEN bytes.
 *
 * ----------------------------------------------------------------------------
 */
bool
_mongocrypt_calculate_deterministic_iv (
   const _mongocrypt_buffer_t *key,
   const _mongocrypt_buffer_t *plaintext,
   const _mongocrypt_buffer_t *associated_data,
   _mongocrypt_buffer_t *out,
   mongocrypt_status_t *status)
{
   void *ctx = NULL;
   bool ret = false;
   _mongocrypt_buffer_t iv_key;
   uint64_t associated_data_len_be;
   uint32_t bytes_written;
   uint8_t tag_storage[64];
   _mongocrypt_buffer_t tag, associated_data_len;

   BSON_ASSERT (key);
   BSON_ASSERT (plaintext);
   BSON_ASSERT (associated_data);
   BSON_ASSERT (out);
   BSON_ASSERT (status);
   BSON_ASSERT (MONGOCRYPT_KEY_LEN == key->len);
   BSON_ASSERT (out->len >= MONGOCRYPT_IV_LEN);

   _mongocrypt_buffer_init (&iv_key);
   iv_key.data = key->data + MONGOCRYPT_ENC_KEY_LEN + MONGOCRYPT_MAC_KEY_LEN;
   iv_key.len = MONGOCRYPT_IV_KEY_LEN;

   ctx = _crypto_hmac_new (&iv_key, status);
   if (!ctx) {
      goto done;
   }

   /* Add associated data. */
   if (!_crypto_hmac_update (ctx, associated_data, status)) {
      goto done;
   }

   /* Add associated data length in bits. */
   associated_data_len_be = 8 * associated_data->len;
   associated_data_len_be = BSON_UINT64_TO_BE (associated_data_len_be);
   associated_data_len.data = (uint8_t *) &associated_data_len_be;
   associated_data_len.len = sizeof (uint64_t);
   if (!_crypto_hmac_update (ctx, &associated_data_len, status)) {
      goto done;
   }

   /* Add plaintext. */
   if (!_crypto_hmac_update (ctx, plaintext, status)) {
      goto done;
   }

   tag.data = tag_storage;
   tag.len = sizeof (tag_storage);
   if (!_crypto_hmac_finalize (ctx, &tag, &bytes_written, status)) {
      goto done;
   }

   BSON_ASSERT (MONGOCRYPT_HMAC_SHA512_LEN == bytes_written);

   /* Truncate to IV length */
   memcpy (out->data, tag.data, MONGOCRYPT_IV_LEN);

   ret = true;
done:
   _crypto_hmac_destroy (ctx);
   return ret;
   return false;
}