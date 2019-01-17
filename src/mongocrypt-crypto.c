/*
 * Copyright 2018-present MongoDB, Inc.
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

#include <mongoc/mongoc.h>
#include "mongocrypt-private.h"

/* TODO: remove - this is for CLion's stupidity */
#ifndef MONGOC_ENABLE_SSL_OPENSSL
#define MONGOC_ENABLE_SSL_OPENSSL
#endif

#ifdef MONGOC_ENABLE_SSL_OPENSSL
#include <openssl/evp.h>

static bool
_openssl_encrypt (const uint8_t *iv,
                  const uint8_t *key,
                  const uint8_t *data,
                  uint32_t data_len,
                  uint8_t **out,
                  uint32_t *out_len,
                  mongocrypt_error_t **error)
{
   const EVP_CIPHER *cipher;
   EVP_CIPHER_CTX ctx;
   bool ret = false;
   int r;
   uint8_t *encrypted = NULL;
   int block_size, bytes_written, encrypted_len = 0;

   CRYPT_ENTRY;
   EVP_CIPHER_CTX_init (&ctx);
   cipher = EVP_aes_256_cbc_hmac_sha256 ();
   block_size = EVP_CIPHER_block_size (cipher);
   BSON_ASSERT (EVP_CIPHER_iv_length (cipher) == 16);
   BSON_ASSERT (block_size == 16);
   BSON_ASSERT (EVP_CIPHER_key_length (cipher) == 32);
   r = EVP_EncryptInit_ex (&ctx, cipher, NULL /* engine */, key, iv);
   if (!r) {
      /* TODO: use ERR_get_error or similar to get OpenSSL error message? */
      CLIENT_ERR ("failed to initialize cipher");
      goto cleanup;
   }

   /* From `man EVP_EncryptInit`: "as a result the amount of data written may be
    * anything from zero bytes to (inl + cipher_block_size - 1)" and for
    * finalize: "should have sufficient space for one block */
   encrypted = bson_malloc0 (data_len + (block_size - 1) + block_size);
   r = EVP_EncryptUpdate (&ctx, encrypted, &bytes_written, data, data_len);
   if (!r) {
      CLIENT_ERR ("failed to encrypt");
      goto cleanup;
   }

   encrypted_len += bytes_written;
   r = EVP_EncryptFinal_ex (&ctx, encrypted + bytes_written, &bytes_written);
   if (!r) {
      CLIENT_ERR ("failed to finalize\n");
      goto cleanup;
   }

   encrypted_len += bytes_written;
   *out = encrypted;
   *out_len = (uint32_t) encrypted_len;
   encrypted = NULL;
   ret = true;
cleanup:
   EVP_CIPHER_CTX_cleanup (&ctx);
   bson_free (encrypted);
   return ret;
}

static bool
_openssl_decrypt (const uint8_t *iv,
                  const uint8_t *key,
                  const uint8_t *data,
                  uint32_t data_len,
                  uint8_t **out,
                  uint32_t *out_len,
                  mongocrypt_error_t **error)
{
   const EVP_CIPHER *cipher;
   EVP_CIPHER_CTX ctx;
   bool ret = false;
   int r;
   uint8_t *decrypted = NULL;
   int block_size, bytes_written, decrypted_len = 0;

   CRYPT_ENTRY;
   EVP_CIPHER_CTX_init (&ctx);
   cipher = EVP_aes_256_cbc_hmac_sha256 ();
   block_size = EVP_CIPHER_block_size (cipher);
   BSON_ASSERT (EVP_CIPHER_iv_length (cipher) == 16);
   BSON_ASSERT (block_size == 16);
   BSON_ASSERT (EVP_CIPHER_key_length (cipher) == 32);
   r = EVP_DecryptInit_ex (&ctx, cipher, NULL /* engine */, key, iv);
   if (!r) {
      /* TODO: use ERR_get_error or similar to get OpenSSL error message? */
      CLIENT_ERR ("failed to initialize cipher");
      goto cleanup;
   }

   /* " EVP_DecryptUpdate() should have sufficient room for (inl +
     * cipher_block_size) bytes" */
   /* decrypted length <= decrypted_len. */
   decrypted = bson_malloc0 (data_len + block_size);
   r = EVP_DecryptUpdate (&ctx, decrypted, &bytes_written, data, data_len);
   if (!r) {
      CLIENT_ERR ("failed to decrypt");
      goto cleanup;
   }

   decrypted_len += bytes_written;
   r = EVP_DecryptFinal_ex (&ctx, decrypted + bytes_written, &bytes_written);
   if (!r) {
      CLIENT_ERR ("failed to finalize\n");
      goto cleanup;
   }

   decrypted_len += bytes_written;
   *out = decrypted;
   *out_len = (uint32_t) decrypted_len;
   decrypted = NULL;
   ret = true;
cleanup:
   EVP_CIPHER_CTX_cleanup (&ctx);
   bson_free (decrypted);
   return ret;
}
#endif

bool
_mongocrypt_do_encryption (const uint8_t *iv,
                           const uint8_t *key,
                           const uint8_t *data,
                           uint32_t data_len,
                           uint8_t **out,
                           uint32_t *out_len,
                           mongocrypt_error_t **error)
{
   CRYPT_ENTRY;

#ifdef MONGOC_ENABLE_SSL_OPENSSL
   return _openssl_encrypt (iv, key, data, data_len, out, out_len, error);
#else
   CLIENT_ERR ("not configured with any supported crypto library");
   return false;
#endif
}

bool
_mongocrypt_do_decryption (const uint8_t *iv,
                           const uint8_t *key,
                           const uint8_t *data,
                           uint32_t data_len,
                           uint8_t **out,
                           uint32_t *out_len,
                           mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
#ifdef MONGOC_ENABLE_SSL_OPENSSL
   return _openssl_decrypt (iv, key, data, data_len, out, out_len, error);
#else
   CLIENT_ERR ("not configured with any supported crypto library");
   return false;
#endif
}