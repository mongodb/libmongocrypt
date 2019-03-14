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

#ifndef MONGOCRYPT_KEY_BROKER_H
#define MONGOCRYPT_KEY_BROKER_H

#include "mongocrypt-binary.h"
#include "mongocrypt-key-decryptor.h"

typedef struct _mongocrypt_key_broker_t mongocrypt_key_broker_t;

/* Create a filter for all keys which must be fetched from the key vault. */
const mongocrypt_binary_t *
mongocrypt_key_broker_get_key_filter (mongocrypt_key_broker_t *kb);


bool
mongocrypt_key_broker_add_key (mongocrypt_key_broker_t *kb,
                               const mongocrypt_binary_t *key);


bool
mongocrypt_key_broker_done_adding_keys (mongocrypt_key_broker_t *kb);


mongocrypt_key_decryptor_t *
mongocrypt_key_broker_next_decryptor (mongocrypt_key_broker_t *kb);


bool
mongocrypt_key_broker_add_decrypted_key (
   mongocrypt_key_broker_t *kb,
   mongocrypt_key_decryptor_t *key_decryptor);


mongocrypt_status_t *
mongocrypt_key_broker_status (mongocrypt_key_broker_t *kb);


#endif /* MONGOCRYPT_KEY_BROKER_H */
