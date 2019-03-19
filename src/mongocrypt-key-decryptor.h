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

#ifndef MONGOCRYPT_KEY_DECRYPTOR_H
#define MONGOCRYPT_KEY_DECRYPTOR_H

#include "mongocrypt-binary.h"
#include "mongocrypt-export.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-status.h"

/* Represents a request/response parser for the decryption of a key material. */
typedef struct _mongocrypt_key_decryptor_t mongocrypt_key_decryptor_t;

/* Return the HTTP message to send. TODO: should this indicate the URI endpoint?
 */
MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_key_decryptor_msg (mongocrypt_key_decryptor_t *kd);

/* Does this key decryptor need more bytes from the response? If it does need
 * bytes, cap it to max_bytes. */
MONGOCRYPT_EXPORT
int
mongocrypt_key_decryptor_bytes_needed (mongocrypt_key_decryptor_t *kd,
                                       uint32_t max_bytes);

/* Add bytes received in the response. */
MONGOCRYPT_EXPORT
bool
mongocrypt_key_decryptor_feed (mongocrypt_key_decryptor_t *kd,
                               mongocrypt_binary_t *bytes);

MONGOCRYPT_EXPORT
mongocrypt_status_t *
mongocrypt_key_decryptor_status (mongocrypt_key_decryptor_t *kb);

#endif /* MONGOCRYPT_KEY_DECRYPTOR_H */
