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

/* Forwarding proxies for base crypto functions.
 * Each std hook wraps binary_t inputs into buffer_t
 * and calls the native crypto implementation.
 *
 * ctx is ignored.
 */
bool _std_hook_native_crypto_aes_256_cbc_encrypt(void *ctx,
                                                 mongocrypt_binary_t *key,
                                                 mongocrypt_binary_t *iv,
                                                 mongocrypt_binary_t *in,
                                                 mongocrypt_binary_t *out,
                                                 uint32_t *bytes_written,
                                                 mongocrypt_status_t *status);

bool _std_hook_native_crypto_aes_256_cbc_decrypt(void *ctx,
                                                 mongocrypt_binary_t *key,
                                                 mongocrypt_binary_t *iv,
                                                 mongocrypt_binary_t *in,
                                                 mongocrypt_binary_t *out,
                                                 uint32_t *bytes_written,
                                                 mongocrypt_status_t *status);

bool _std_hook_native_crypto_random(void *ctx, mongocrypt_binary_t *out, uint32_t count, mongocrypt_status_t *status);

bool _std_hook_native_hmac_sha512(void *ctx,
                                  mongocrypt_binary_t *key,
                                  mongocrypt_binary_t *in,
                                  mongocrypt_binary_t *out,
                                  mongocrypt_status_t *status);

bool _std_hook_native_hmac_sha256(void *ctx,
                                  mongocrypt_binary_t *key,
                                  mongocrypt_binary_t *in,
                                  mongocrypt_binary_t *out,
                                  mongocrypt_status_t *status);

/* Hooks which fail and set an error indicating that the named
 * function was not expected to have been called.
 */
bool _error_hook_native_crypto_aes_256_cbc_encrypt(void *ctx,
                                                   mongocrypt_binary_t *key,
                                                   mongocrypt_binary_t *iv,
                                                   mongocrypt_binary_t *in,
                                                   mongocrypt_binary_t *out,
                                                   uint32_t *bytes_written,
                                                   mongocrypt_status_t *status);

bool _error_hook_native_crypto_aes_256_cbc_decrypt(void *ctx,
                                                   mongocrypt_binary_t *key,
                                                   mongocrypt_binary_t *iv,
                                                   mongocrypt_binary_t *in,
                                                   mongocrypt_binary_t *out,
                                                   uint32_t *bytes_written,
                                                   mongocrypt_status_t *status);

bool _error_hook_native_crypto_random(void *ctx, mongocrypt_binary_t *out, uint32_t count, mongocrypt_status_t *status);

bool _error_hook_native_hmac_sha512(void *ctx,
                                    mongocrypt_binary_t *key,
                                    mongocrypt_binary_t *in,
                                    mongocrypt_binary_t *out,
                                    mongocrypt_status_t *status);

bool _error_hook_native_hmac_sha256(void *ctx,
                                    mongocrypt_binary_t *key,
                                    mongocrypt_binary_t *in,
                                    mongocrypt_binary_t *out,
                                    mongocrypt_status_t *status);

bool _error_hook_native_sha256(void *ctx,
                               mongocrypt_binary_t *in,
                               mongocrypt_binary_t *out,
                               mongocrypt_status_t *status);
