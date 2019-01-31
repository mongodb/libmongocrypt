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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

/* ----------------------------------------------------------------------------
 *
 * _openssl_aes256_cbc_encrypt --
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
_openssl_aes256_cbc_encrypt (const _mongocrypt_buffer_t *iv,
                             const _mongocrypt_buffer_t *key,
                             const _mongocrypt_buffer_t *plaintext,
                             _mongocrypt_buffer_t *ciphertext,
                             uint32_t *bytes_written,
                             mongocrypt_status_t *status)
{
   const EVP_CIPHER *cipher;
   EVP_CIPHER_CTX *ctx;
   bool ret = false;
   int openssl_ret;
   uint32_t intermediate_bytes_written;
   uint8_t padding_byte;
   uint8_t *padding;

   CRYPT_ENTRY;
   BSON_ASSERT (bytes_written);
   *bytes_written = 0;
   ctx = EVP_CIPHER_CTX_new ();
   cipher = EVP_aes_256_cbc ();

   BSON_ASSERT (ctx);
   BSON_ASSERT (cipher);
   BSON_ASSERT (EVP_CIPHER_iv_length (cipher) == iv->len);
   BSON_ASSERT (EVP_CIPHER_key_length (cipher) == key->len);
   BSON_ASSERT (EVP_CIPHER_block_size (cipher) == 16);

   if (!EVP_EncryptInit_ex (
          ctx, cipher, NULL /* engine */, key->data, iv->data)) {
      CLIENT_ERR ("error initializing cipher: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   /* Disable the default OpenSSL padding. */
   EVP_CIPHER_CTX_set_padding (ctx, 0);

   if (!EVP_EncryptUpdate (ctx,
                           ciphertext->data,
                           (int *) &intermediate_bytes_written,
                           plaintext->data,
                           plaintext->len)) {
      CLIENT_ERR ("error encrypting: %s",
                  ERR_error_string (ERR_get_error (), NULL));
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

   padding = bson_malloc (padding_byte);
   memset (padding, padding_byte, padding_byte);

   if (!EVP_EncryptUpdate (ctx,
                           ciphertext->data + *bytes_written,
                           (int *) &intermediate_bytes_written,
                           padding,
                           padding_byte)) {
      CLIENT_ERR ("error encrypting padding: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   bson_free (padding);
   *bytes_written += intermediate_bytes_written;
   BSON_ASSERT (*bytes_written % MONGOCRYPT_BLOCK_SIZE == 0);

   if (!EVP_EncryptFinal_ex (ctx,
                             ciphertext->data + *bytes_written,
                             (int *) &intermediate_bytes_written)) {
      CLIENT_ERR ("error finalizing: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   BSON_ASSERT (intermediate_bytes_written == 0);

   *bytes_written += intermediate_bytes_written;
   ret = true;

done:
   EVP_CIPHER_CTX_free (ctx);
   return ret;
}


/* ----------------------------------------------------------------------------
 *
 * _openssl_aes256_cbc_decrypt --
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
_openssl_aes256_cbc_decrypt (const _mongocrypt_buffer_t *iv,
                             const _mongocrypt_buffer_t *key,
                             const _mongocrypt_buffer_t *ciphertext,
                             _mongocrypt_buffer_t *plaintext,
                             uint32_t *bytes_written,
                             mongocrypt_status_t *status)
{
   const EVP_CIPHER *cipher;
   EVP_CIPHER_CTX *ctx;
   bool ret = false;
   int intermediate_bytes_written;

   CRYPT_ENTRY;
   BSON_ASSERT (bytes_written);
   *bytes_written = 0;
   ctx = EVP_CIPHER_CTX_new ();
   cipher = EVP_aes_256_cbc ();

   BSON_ASSERT (ctx);
   BSON_ASSERT (cipher);
   BSON_ASSERT (EVP_CIPHER_iv_length (cipher) == iv->len);
   BSON_ASSERT (EVP_CIPHER_key_length (cipher) == key->len);
   BSON_ASSERT (EVP_CIPHER_block_size (cipher) == MONGOCRYPT_BLOCK_SIZE);
   /* The IV is the first block of CBC encryption, no need to pass it here. */
   if (!EVP_DecryptInit_ex (
          ctx, cipher, NULL /* engine */, key->data, iv->data)) {
      CLIENT_ERR ("error initializing cipher: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   if (ciphertext->len % MONGOCRYPT_BLOCK_SIZE > 0) {
      CLIENT_ERR ("error, ciphertext length is not a multiple of block size");
      goto done;
   }

   /* Disable padding. */
   EVP_CIPHER_CTX_set_padding (ctx, 0);

   if (!EVP_DecryptUpdate (ctx,
                           plaintext->data,
                           (int *) &intermediate_bytes_written,
                           ciphertext->data,
                           ciphertext->len)) {
      CLIENT_ERR ("error decrypting: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   *bytes_written += intermediate_bytes_written;
   if (!EVP_DecryptFinal_ex (
          ctx, plaintext->data + *bytes_written, &intermediate_bytes_written)) {
      CLIENT_ERR ("error finalizing: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   BSON_ASSERT (intermediate_bytes_written == 0);

   *bytes_written += intermediate_bytes_written;

   /* Subtract the padding. */
   *bytes_written -= plaintext->data[*bytes_written - 1];
   ret = true;
done:
   EVP_CIPHER_CTX_free (ctx);
   return ret;
}


/* ----------------------------------------------------------------------------
 *
 * _openssl_hmac_sha512 --
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
_openssl_hmac_sha512 (const _mongocrypt_buffer_t *key,
                      const _mongocrypt_buffer_t *associated_data,
                      const _mongocrypt_buffer_t *ciphertext,
                      _mongocrypt_buffer_t *out,
                      mongocrypt_status_t *status)
{
   const EVP_MD *algo;
   HMAC_CTX *ctx;
   bool ret = false;
   uint64_t associated_data_len_be;
   uint32_t bytes_written;
   uint8_t tag[64];

   CRYPT_ENTRY;
   ctx = HMAC_CTX_new ();
   algo = EVP_sha512 ();

   BSON_ASSERT (ctx);
   BSON_ASSERT (algo);
   BSON_ASSERT (EVP_MD_block_size (algo) == 128);
   BSON_ASSERT (EVP_MD_size (algo) == 64);
   BSON_ASSERT (MONGOCRYPT_MAC_KEY_LEN == key->len);
   BSON_ASSERT (out->len >= MONGOCRYPT_HMAC_LEN);

   if (!HMAC_Init_ex (ctx, key->data, key->len, algo, NULL /* engine */)) {
      CLIENT_ERR ("error initializing HMAC: %s",
                  ERR_error_string (ERR_get_error (), NULL));
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
   if (!HMAC_Update (ctx, associated_data->data, associated_data->len)) {
      CLIENT_ERR ("error adding associated data to HMAC: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   /* Add ciphertext. */
   if (!HMAC_Update (ctx, ciphertext->data, ciphertext->len)) {
      CLIENT_ERR ("error adding ciphertext to HMAC: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   /* Add associated data length in bits. */
   associated_data_len_be = 8 * associated_data->len;
   associated_data_len_be = BSON_UINT64_TO_BE (associated_data_len_be);
   if (!HMAC_Update (
          ctx, (uint8_t *) &associated_data_len_be, sizeof (uint64_t))) {
      CLIENT_ERR ("error adding associated data length to HMAC: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   if (!HMAC_Final (ctx, tag, &bytes_written)) {
      CLIENT_ERR ("error finalizing: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   BSON_ASSERT (64 == bytes_written);

   /* [MCGREW 2.7] "The HMAC-SHA-512 value is truncated to T_LEN=32 octets" */
   memcpy (out->data, tag, MONGOCRYPT_HMAC_LEN);

   ret = true;
done:
   HMAC_CTX_free (ctx);
   return ret;
}


/* ----------------------------------------------------------------------------
 *
 * _openssl_aes256_cbc_sha512_encrypt --
 *
 *    Encrypt with AES256 and tag with HMAC SHA512 @plaintext and store the
 *    result in @ciphertext.
 *
 * Parameters:
 *    @iv a 16 byte initialization vector (IV).
 *    @associated_data associated data to add into the HMAC. This may be
 *    an empty buffer.
 *    @key a 32 byte key.
 *    @plaintext the plaintext to encrypt.
 *    @ciphertext a location for the resulting ciphertext and HMAC tag.
 *    @bytes_written a location for the resulting bytes written.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 * ----------------------------------------------------------------------------
 */
bool
_openssl_aes256_cbc_sha512_encrypt (const _mongocrypt_buffer_t *iv,
                                    const _mongocrypt_buffer_t *associated_data,
                                    const _mongocrypt_buffer_t *key,
                                    const _mongocrypt_buffer_t *plaintext,
                                    _mongocrypt_buffer_t *ciphertext,
                                    uint32_t *bytes_written,
                                    mongocrypt_status_t *status)
{
   bool ret = false;
   _mongocrypt_buffer_t mac_key = {0}, enc_key = {0}, intermediate = {0},
                        intermediate_hmac = {0};
   uint32_t intermediate_bytes_written = 0;

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
   if (!_openssl_aes256_cbc_encrypt (iv,
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
   if (!_openssl_hmac_sha512 (&mac_key,
                              associated_data,
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
 * _openssl_aes256_cbc_sha512_decrypt --
 *
 *    Decrypt and integrity check @ciphertext and store the result in
 *    @plaintext.
 *
 * Parameters:
 *    @iv a 16 byte IV.
 *    @associated_data associated data to add into the HMAC. This may be
 *    an empty buffer.
 *    @key a 32 byte key.
 *    @ciphertext the ciphertext to decrypt.
 *    @plaintext a location for the resulting plaintext.
 *    @bytes_written a location for the resulting bytes written.
 *    @status set on error.
 *
 * Returns:
 *    True on success. On error, sets @status and returns false.
 *
 * ----------------------------------------------------------------------------
 */
bool
_openssl_aes256_cbc_sha512_decrypt (const _mongocrypt_buffer_t *associated_data,
                                    const _mongocrypt_buffer_t *key,
                                    const _mongocrypt_buffer_t *ciphertext,
                                    _mongocrypt_buffer_t *plaintext,
                                    uint32_t *bytes_written,
                                    mongocrypt_status_t *status)
{
   bool ret = false;
   _mongocrypt_buffer_t mac_key = {0}, enc_key = {0}, intermediate = {0},
                        hmac_tag = {0}, iv = {0};
   uint8_t hmac_tag_storage[MONGOCRYPT_HMAC_LEN];

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
   if (!_openssl_hmac_sha512 (
          &mac_key, associated_data, &intermediate, &hmac_tag, status)) {
      goto done;
   }

   /* [MCGREW] "using a comparison routine that takes constant time". */
   if (0 != CRYPTO_memcmp (hmac_tag.data,
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

   if (!_openssl_aes256_cbc_decrypt (
          &iv, &enc_key, &intermediate, plaintext, bytes_written, status)) {
      goto done;
   }

   ret = true;
done:
   return ret;
}

#endif