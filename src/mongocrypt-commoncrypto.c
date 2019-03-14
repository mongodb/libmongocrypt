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

#include "mongocrypt-crypto-private.h"
#include "mongocrypt-private.h"

#ifdef MONGOCRYPT_CRYPTO_COMMONCRYPTO

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <Security/Security.h>
#include <Security/SecRandom.h>

void *
_crypto_encrypt_new (const _mongocrypt_buffer_t *key,
                     const _mongocrypt_buffer_t *iv,
                     mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorRef ctx = NULL;
   CCCryptorStatus cc_status;

   cc_status = CCCryptorCreate (kCCEncrypt,
                                kCCAlgorithmAES,
                                0 /* defaults to CBC w/ no padding */,
                                key->data,
                                kCCKeySizeAES256,
                                iv->data,
                                &ctx);

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error initializing cipher: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return (void *) ctx;
}


bool
_crypto_encrypt_update (void *ctx,
                        const _mongocrypt_buffer_t *in,
                        _mongocrypt_buffer_t *out,
                        uint32_t *bytes_written,
                        mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorUpdate (
      ctx, in->data, in->len, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error encrypting: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


bool
_crypto_encrypt_finalize (void *ctx,
                          _mongocrypt_buffer_t *out,
                          uint32_t *bytes_written,
                          mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorFinal (ctx, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error finalizing: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


void
_crypto_encrypt_destroy (void *ctx)
{
   if (ctx) {
      CCCryptorRelease (ctx);
   }
}


/* Note, the decrypt functions are almost exactly the same as the encrypt
 * functions
 * except for the kCCDecrypt and the error message. */
void *
_crypto_decrypt_new (const _mongocrypt_buffer_t *key,
                     const _mongocrypt_buffer_t *iv,
                     mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorRef ctx = NULL;
   CCCryptorStatus cc_status;

   cc_status = CCCryptorCreate (kCCDecrypt,
                                kCCAlgorithmAES,
                                0 /* defaults to CBC w/ no padding */,
                                key->data,
                                kCCKeySizeAES256,
                                iv->data,
                                &ctx);

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error initializing cipher: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ctx;
}


bool
_crypto_decrypt_update (void *ctx,
                        const _mongocrypt_buffer_t *in,
                        _mongocrypt_buffer_t *out,
                        uint32_t *bytes_written,
                        mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorUpdate (
      ctx, in->data, in->len, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error decrypting: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


bool
_crypto_decrypt_finalize (void *ctx,
                          _mongocrypt_buffer_t *out,
                          uint32_t *bytes_written,
                          mongocrypt_status_t *status)
{
   bool ret = false;
   CCCryptorStatus cc_status;
   size_t bytes_written_size;

   cc_status = CCCryptorFinal (ctx, out->data, out->len, &bytes_written_size);

   *bytes_written = bytes_written_size;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error finalizing: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   if (!ret) {
      return NULL;
   }
   return ret;
}


void
_crypto_decrypt_destroy (void *ctx)
{
   if (ctx) {
      CCCryptorRelease (ctx);
   }
}


/* CCHmac functions don't return errors. */
void *
_crypto_hmac_new (const _mongocrypt_buffer_t *key, mongocrypt_status_t *status)
{
   bool ret;
   CCHmacContext *ctx;

   ctx = bson_malloc0 (sizeof (*ctx));

   CCHmacInit (ctx, kCCHmacAlgSHA512, key->data, key->len);
   return ctx;
}


bool
_crypto_hmac_update (void *ctx,
                     const _mongocrypt_buffer_t *in,
                     mongocrypt_status_t *status)
{
   CCHmacUpdate (ctx, in->data, in->len);
   return true;
}


bool
_crypto_hmac_finalize (void *ctx,
                       _mongocrypt_buffer_t *out,
                       uint32_t *bytes_written,
                       mongocrypt_status_t *status)
{
   BSON_ASSERT (out->len >= 64);
   CCHmacFinal (ctx, out->data);
   *bytes_written = 64; /* have faith! */
   return true;
}


void
_crypto_hmac_destroy (void *ctx)
{
   if (ctx) {
      bson_free (ctx);
   }
}


bool
_crypto_random (_mongocrypt_buffer_t *out,
                mongocrypt_status_t *status,
                uint32_t count)
{
   int ret = SecRandomCopyBytes (kSecRandomDefault, (size_t) count, out->data);
   if (ret != errSecSuccess) {
      CLIENT_ERR ("failed to generate random iv: %d", ret);
      return false;
   }
   return true;
}

#endif