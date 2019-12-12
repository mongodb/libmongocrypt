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

#include "../mongocrypt-crypto-private.h"
#include "../mongocrypt-private.h"
#include "../mongocrypt-log-private.h"

#ifdef MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO

#include <bson/bson.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
   (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
EVP_CIPHER_CTX *
EVP_CIPHER_CTX_new (void)
{
   return bson_malloc0 (sizeof (EVP_CIPHER_CTX));
}

void
EVP_CIPHER_CTX_free (EVP_CIPHER_CTX *ctx)
{
   EVP_CIPHER_CTX_cleanup (ctx);
   bson_free (ctx);
}

HMAC_CTX *
HMAC_CTX_new (void)
{
   return bson_malloc0 (sizeof (HMAC_CTX));
}

void
HMAC_CTX_free (HMAC_CTX *ctx)
{
   HMAC_CTX_cleanup (ctx);
   bson_free (ctx);
}
#endif

bool _native_crypto_initialized = false;

void
_native_crypto_init ()
{
   _native_crypto_initialized = true;
}

bool
_native_crypto_aes_256_cbc_encrypt (const _mongocrypt_buffer_t *key,
                                    const _mongocrypt_buffer_t *iv,
                                    const _mongocrypt_buffer_t *in,
                                    _mongocrypt_buffer_t *out,
                                    uint32_t *bytes_written,
                                    mongocrypt_status_t *status)
{
   const EVP_CIPHER *cipher;
   EVP_CIPHER_CTX *ctx;
   bool ret = false;
   int intermediate_bytes_written;

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

   *bytes_written = 0;
   if (!EVP_EncryptUpdate (
          ctx, out->data, &intermediate_bytes_written, in->data, in->len)) {
      CLIENT_ERR ("error encrypting: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   *bytes_written = (uint32_t) intermediate_bytes_written;

   if (!EVP_EncryptFinal_ex (ctx, out->data, &intermediate_bytes_written)) {
      CLIENT_ERR ("error finalizing: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   *bytes_written += (uint32_t) intermediate_bytes_written;

   ret = true;
done:
   EVP_CIPHER_CTX_free (ctx);
   return ret;
}


bool
_native_crypto_aes_256_cbc_decrypt (const _mongocrypt_buffer_t *key,
                                    const _mongocrypt_buffer_t *iv,
                                    const _mongocrypt_buffer_t *in,
                                    _mongocrypt_buffer_t *out,
                                    uint32_t *bytes_written,
                                    mongocrypt_status_t *status)
{
   const EVP_CIPHER *cipher;
   EVP_CIPHER_CTX *ctx;
   bool ret = false;
   int intermediate_bytes_written;

   ctx = EVP_CIPHER_CTX_new ();
   cipher = EVP_aes_256_cbc ();

   BSON_ASSERT (EVP_CIPHER_iv_length (cipher) == iv->len);
   BSON_ASSERT (EVP_CIPHER_key_length (cipher) == key->len);
   BSON_ASSERT (EVP_CIPHER_block_size (cipher) == MONGOCRYPT_BLOCK_SIZE);

   if (!EVP_DecryptInit_ex (
          ctx, cipher, NULL /* engine */, key->data, iv->data)) {
      CLIENT_ERR ("error initializing cipher: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   /* Disable padding. */
   EVP_CIPHER_CTX_set_padding (ctx, 0);

   *bytes_written = 0;

   if (!EVP_DecryptUpdate (
          ctx, out->data, &intermediate_bytes_written, in->data, in->len)) {
      CLIENT_ERR ("error decrypting: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   *bytes_written = intermediate_bytes_written;

   if (!EVP_DecryptFinal_ex (ctx, out->data, &intermediate_bytes_written)) {
      CLIENT_ERR ("error decrypting: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   *bytes_written += intermediate_bytes_written;

   ret = true;
done:
   EVP_CIPHER_CTX_free (ctx);
   return ret;
}


bool
_native_crypto_hmac_sha_512 (const _mongocrypt_buffer_t *key,
                             const _mongocrypt_buffer_t *in,
                             _mongocrypt_buffer_t *out,
                             mongocrypt_status_t *status)
{
   const EVP_MD *algo;
   HMAC_CTX *ctx;
   bool ret = false;

   ctx = HMAC_CTX_new ();
   algo = EVP_sha512 ();
   BSON_ASSERT (EVP_MD_block_size (algo) == 128);
   BSON_ASSERT (EVP_MD_size (algo) == MONGOCRYPT_HMAC_SHA512_LEN);

   if (out->len != MONGOCRYPT_HMAC_SHA512_LEN) {
      CLIENT_ERR ("out does not contain %d bytes", MONGOCRYPT_HMAC_SHA512_LEN);
      return false;
   }

   if (!HMAC_Init_ex (ctx, key->data, key->len, algo, NULL /* engine */)) {
      CLIENT_ERR ("error initializing HMAC: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   if (!HMAC_Update (ctx, in->data, in->len)) {
      CLIENT_ERR ("error updating HMAC: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   if (!HMAC_Final (ctx, out->data, NULL /* unused out len */)) {
      CLIENT_ERR ("error finalizing: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      goto done;
   }

   ret = true;
done:
   HMAC_CTX_free (ctx);
   return ret;
}


bool
_native_crypto_random (_mongocrypt_buffer_t *out,
                       uint32_t count,
                       mongocrypt_status_t *status)
{
   int ret = RAND_bytes (out->data, count);
   /* From man page: "RAND_bytes() and RAND_priv_bytes() return 1 on success, -1
    * if not supported by the current RAND method, or 0 on other failure. The
    * error code can be obtained by ERR_get_error(3)" */
   if (ret == -1) {
      CLIENT_ERR ("secure random IV not supported: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      return false;
   } else if (ret == 0) {
      CLIENT_ERR ("failed to generate random IV: %s",
                  ERR_error_string (ERR_get_error (), NULL));
      return false;
   }
   return true;
}

#endif /* MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO */
