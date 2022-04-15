/*
 * Copyright 2022-present MongoDB, Inc.
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

#include <mongocrypt-buffer-private.h>

#include "test-mongocrypt.h"

bool
_std_hook_native_crypto_aes_256_cbc_encrypt (void *ctx,
                                             mongocrypt_binary_t *key,
                                             mongocrypt_binary_t *iv,
                                             mongocrypt_binary_t *in,
                                             mongocrypt_binary_t *out,
                                             uint32_t *bytes_written,
                                             mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t keybuf, ivbuf, inbuf, outbuf;
   _mongocrypt_buffer_from_binary (&keybuf, key);
   _mongocrypt_buffer_from_binary (&ivbuf, iv);
   _mongocrypt_buffer_from_binary (&inbuf, in);
   _mongocrypt_buffer_from_binary (&outbuf, out);

   aes_256_args_t args = {.key = &keybuf,
                          .iv = &ivbuf,
                          .in = &inbuf,
                          .out = &outbuf,
                          .bytes_written = bytes_written,
                          .status = status};
   return _native_crypto_aes_256_cbc_encrypt (args);
}

bool
_std_hook_native_crypto_aes_256_cbc_decrypt (void *ctx,
                                             mongocrypt_binary_t *key,
                                             mongocrypt_binary_t *iv,
                                             mongocrypt_binary_t *in,
                                             mongocrypt_binary_t *out,
                                             uint32_t *bytes_written,
                                             mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t keybuf, ivbuf, inbuf, outbuf;
   _mongocrypt_buffer_from_binary (&keybuf, key);
   _mongocrypt_buffer_from_binary (&ivbuf, iv);
   _mongocrypt_buffer_from_binary (&inbuf, in);
   _mongocrypt_buffer_from_binary (&outbuf, out);

   aes_256_args_t args = {.key = &keybuf,
                          .iv = &ivbuf,
                          .in = &inbuf,
                          .out = &outbuf,
                          .bytes_written = bytes_written,
                          .status = status};
   return _native_crypto_aes_256_cbc_decrypt (args);
}

bool
_std_hook_native_crypto_random (void *ctx,
                                mongocrypt_binary_t *out,
                                uint32_t count,
                                mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t outbuf;
   _mongocrypt_buffer_from_binary (&outbuf, out);

   return _native_crypto_random (&outbuf, count, status);
}

bool
_std_hook_native_hmac_sha512 (void *ctx,
                              mongocrypt_binary_t *key,
                              mongocrypt_binary_t *in,
                              mongocrypt_binary_t *out,
                              mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t keybuf, inbuf, outbuf;
   _mongocrypt_buffer_from_binary (&keybuf, key);
   _mongocrypt_buffer_from_binary (&inbuf, in);
   _mongocrypt_buffer_from_binary (&outbuf, out);

   return _native_crypto_hmac_sha_512 (&keybuf, &inbuf, &outbuf, status);
}

bool
_std_hook_native_hmac_sha256 (void *ctx,
                              mongocrypt_binary_t *key,
                              mongocrypt_binary_t *in,
                              mongocrypt_binary_t *out,
                              mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t keybuf, inbuf, outbuf;
   _mongocrypt_buffer_from_binary (&keybuf, key);
   _mongocrypt_buffer_from_binary (&inbuf, in);
   _mongocrypt_buffer_from_binary (&outbuf, out);

   return _native_crypto_hmac_sha_256 (&keybuf, &inbuf, &outbuf, status);
}

bool
_error_hook_native_crypto_aes_256_cbc_encrypt (void *ctx,
                                               mongocrypt_binary_t *key,
                                               mongocrypt_binary_t *iv,
                                               mongocrypt_binary_t *in,
                                               mongocrypt_binary_t *out,
                                               uint32_t *bytes_written,
                                               mongocrypt_status_t *status)
{
   CLIENT_ERR ("aes_256_cbc_encrypt not expected to have been called");
   return false;
}

bool
_error_hook_native_crypto_aes_256_cbc_decrypt (void *ctx,
                                               mongocrypt_binary_t *key,
                                               mongocrypt_binary_t *iv,
                                               mongocrypt_binary_t *in,
                                               mongocrypt_binary_t *out,
                                               uint32_t *bytes_written,
                                               mongocrypt_status_t *status)
{
   CLIENT_ERR ("aes_256_cbc_decrypt not expected to have been called");
   return false;
}

bool
_error_hook_native_crypto_random (void *ctx,
                                  mongocrypt_binary_t *out,
                                  uint32_t count,
                                  mongocrypt_status_t *status)
{
   CLIENT_ERR ("crypto_random not expected to have been called");
   return false;
}

bool
_error_hook_native_hmac_sha512 (void *ctx,
                                mongocrypt_binary_t *key,
                                mongocrypt_binary_t *in,
                                mongocrypt_binary_t *out,
                                mongocrypt_status_t *status)
{
   CLIENT_ERR ("hmac_sha512 not expected to have been called");
   return false;
}

bool
_error_hook_native_hmac_sha256 (void *ctx,
                                mongocrypt_binary_t *key,
                                mongocrypt_binary_t *in,
                                mongocrypt_binary_t *out,
                                mongocrypt_status_t *status)
{
   CLIENT_ERR ("hmac_sha256 not expected to have been called");
   return false;
}

bool
_error_hook_native_sha256 (void *ctx,
                           mongocrypt_binary_t *in,
                           mongocrypt_binary_t *out,
                           mongocrypt_status_t *status)
{
   CLIENT_ERR ("sha256 not expected to have been called");
   return false;
}
