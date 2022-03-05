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

#include "../mongocrypt-crypto-private.h"
#include "../mongocrypt-private.h"

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonRandom.h>

bool _native_crypto_initialized = false;

void
_native_crypto_init ()
{
   _native_crypto_initialized = true;
}


bool
_native_crypto_aes_256_cbc_encrypt (aes_256_args_t args)
{
   bool ret = false;
   CCCryptorRef ctx = NULL;
   CCCryptorStatus cc_status;
   size_t intermediate_bytes_written;
   mongocrypt_status_t *status = args.status;

   cc_status = CCCryptorCreate (kCCEncrypt,
                                kCCAlgorithmAES,
                                0 /* defaults to CBC w/ no padding */,
                                args.key->data,
                                kCCKeySizeAES256,
                                args.iv->data,
                                &ctx);

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error initializing cipher: %d", (int) cc_status);
      goto done;
   }

   *args.bytes_written = 0;

   cc_status = CCCryptorUpdate (ctx,
                                args.in->data,
                                args.in->len,
                                args.out->data,
                                args.out->len,
                                &intermediate_bytes_written);
   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error encrypting: %d", (int) cc_status);
      goto done;
   }
   *args.bytes_written = intermediate_bytes_written;


   cc_status = CCCryptorFinal (ctx,
                               args.out->data + *args.bytes_written,
                               args.out->len - *args.bytes_written,
                               &intermediate_bytes_written);
   *args.bytes_written += intermediate_bytes_written;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error finalizing: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   CCCryptorRelease (ctx);
   return ret;
}


/* Note, the decrypt function is almost exactly the same as the encrypt
 * functions except for the kCCDecrypt and the error message. */
bool
_native_crypto_aes_256_cbc_decrypt (aes_256_args_t args)
{
   bool ret = false;
   CCCryptorRef ctx = NULL;
   CCCryptorStatus cc_status;
   size_t intermediate_bytes_written;
   mongocrypt_status_t *status = args.status;

   cc_status = CCCryptorCreate (kCCDecrypt,
                                kCCAlgorithmAES,
                                0 /* defaults to CBC w/ no padding */,
                                args.key->data,
                                kCCKeySizeAES256,
                                args.iv->data,
                                &ctx);

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error initializing cipher: %d", (int) cc_status);
      goto done;
   }

   *args.bytes_written = 0;
   cc_status = CCCryptorUpdate (ctx,
                                args.in->data,
                                args.in->len,
                                args.out->data,
                                args.out->len,
                                &intermediate_bytes_written);
   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error decrypting: %d", (int) cc_status);
      goto done;
   }
   *args.bytes_written = intermediate_bytes_written;

   cc_status = CCCryptorFinal (ctx,
                               args.out->data + *args.bytes_written,
                               args.out->len - *args.bytes_written,
                               &intermediate_bytes_written);
   *args.bytes_written += intermediate_bytes_written;

   if (cc_status != kCCSuccess) {
      CLIENT_ERR ("error finalizing: %d", (int) cc_status);
      goto done;
   }

   ret = true;
done:
   CCCryptorRelease (ctx);
   return ret;
}


/* CCHmac functions don't return errors. */
bool
_native_crypto_hmac_sha_512 (const _mongocrypt_buffer_t *key,
                             const _mongocrypt_buffer_t *in,
                             _mongocrypt_buffer_t *out,
                             mongocrypt_status_t *status)
{
   CCHmacContext *ctx;

   if (out->len != MONGOCRYPT_HMAC_SHA512_LEN) {
      CLIENT_ERR ("out does not contain %d bytes", MONGOCRYPT_HMAC_SHA512_LEN);
      return false;
   }

   ctx = bson_malloc0 (sizeof (*ctx));
   BSON_ASSERT (ctx);


   CCHmacInit (ctx, kCCHmacAlgSHA512, key->data, key->len);
   CCHmacUpdate (ctx, in->data, in->len);
   CCHmacFinal (ctx, out->data);
   bson_free (ctx);
   return true;
}


bool
_native_crypto_random (_mongocrypt_buffer_t *out,
                       uint32_t count,
                       mongocrypt_status_t *status)
{
   CCRNGStatus ret = CCRandomGenerateBytes (out->data, (size_t) count);
   if (ret != kCCSuccess) {
      CLIENT_ERR ("failed to generate random iv: %d", (int) ret);
      return false;
   }
   return true;
}

bool
_native_crypto_aes_256_ctr_encrypt (aes_256_args_t args)
{
   mongocrypt_status_t *status = args.status;
   CLIENT_ERR (
      "_native_crypto_aes_256_ctr_encrypt not implemented for CommonCrypto");
   return false;
}

bool
_native_crypto_aes_256_ctr_decrypt (aes_256_args_t args)
{
   mongocrypt_status_t *status = args.status;
   CLIENT_ERR (
      "_native_crypto_aes_256_ctr_decrypt not implemented for CommonCrypto");
   return false;
}

bool
_native_crypto_hmac_sha_256 (const _mongocrypt_buffer_t *key,
                             const _mongocrypt_buffer_t *in,
                             _mongocrypt_buffer_t *out,
                             mongocrypt_status_t *status) {
   CCHmacContext *ctx;

   if (out->len != MONGOCRYPT_HMAC_SHA256_LEN) {
      CLIENT_ERR ("out does not contain %d bytes", MONGOCRYPT_HMAC_SHA256_LEN);
      return false;
   }

   ctx = bson_malloc0 (sizeof (*ctx));
   BSON_ASSERT (ctx);


   CCHmacInit (ctx, kCCHmacAlgSHA256, key->data, key->len);
   CCHmacUpdate (ctx, in->data, in->len);
   CCHmacFinal (ctx, out->data);
   bson_free (ctx);
   return true;
}

#endif /* MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO */
