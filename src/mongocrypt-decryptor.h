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

#ifndef MONGOCRYPT_DECRYPTOR_H
#define MONGOCRYPT_DECRYPTOR_H


#include "mongocrypt-binary.h"
#include "mongocrypt-key-decryptor.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-status.h"

typedef struct _mongocrypt_decryptor_t mongocrypt_decryptor_t;

typedef enum {
   MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC = 0,
   MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS,
   MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS_DECRYPTED,
   MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION,
   MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED,
   MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED,
   MONGOCRYPT_DECRYPTOR_STATE_ERROR
} mongocrypt_decryptor_state_t;


mongocrypt_decryptor_t *
mongocrypt_decryptor_new (mongocrypt_t *crypt, const mongocrypt_opts_t *opts);


mongocrypt_decryptor_state_t
mongocrypt_decryptor_add_doc (mongocrypt_decryptor_t *decryptor,
                              mongocrypt_binary_t *encrypted_doc,
                              const mongocrypt_opts_t *opts);


const mongocrypt_binary_t *
mongocrypt_decryptor_get_key_filter (mongocrypt_decryptor_t *decryptor,
                                     const mongocrypt_opts_t *opts);


bool
mongocrypt_decryptor_add_key (mongocrypt_decryptor_t *decryptor,
                              const mongocrypt_opts_t *opts,
                              const mongocrypt_binary_t *key,
                              mongocrypt_status_t *status);


mongocrypt_decryptor_state_t
mongocrypt_decryptor_done_adding_keys (mongocrypt_decryptor_t *decryptor);


mongocrypt_key_decryptor_t *
mongocrypt_decryptor_next_key_decryptor (mongocrypt_decryptor_t *decryptor);


mongocrypt_decryptor_state_t
mongocrypt_decryptor_add_decrypted_key (
   mongocrypt_decryptor_t *decryptor,
   mongocrypt_key_decryptor_t *key_decryptor);


mongocrypt_decryptor_state_t
mongocrypt_decryptor_done_decrypting_keys (mongocrypt_decryptor_t *decryptor);


mongocrypt_decryptor_state_t
mongocrypt_decryptor_decrypt (mongocrypt_decryptor_t *decryptor);


mongocrypt_decryptor_state_t
mongocrypt_decryptor_state (mongocrypt_decryptor_t *decryptor);


mongocrypt_binary_t *
mongocrypt_decryptor_decrypted_cmd (mongocrypt_decryptor_t *decryptor);


mongocrypt_status_t *
mongocrypt_decryptor_status (mongocrypt_decryptor_t *decryptor);


void
mongocrypt_decryptor_destroy (mongocrypt_decryptor_t *decryptor);


#endif /* MONGOCRYPT_DECRYPTOR_H */
