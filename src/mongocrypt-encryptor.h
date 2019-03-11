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

#ifndef MONGOCRYPT_ENCRYPTOR_H
#define MONGOCRYPT_ENCRYPTOR_H


#include "mongocrypt-binary.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-status.h"


typedef struct _mongocrypt_encryptor_t mongocrypt_encryptor_t;

typedef enum {
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS = 0,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS_DECRYPTED,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION,
   MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED,
   MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED,
   MONGOCRYPT_ENCRYPTOR_STATE_ERROR
} mongocrypt_encryptor_state_t;


mongocrypt_encryptor_t *
mongocrypt_encryptor_new (mongocrypt_t *crypt, const mongocrypt_opts_t *opts);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_ns (mongocrypt_encryptor_t *encryptor,
                             const char *ns,
                             const mongocrypt_opts_t *opts);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_collection_info (
   mongocrypt_encryptor_t *encryptor,
   const mongocrypt_binary_t *list_collections_reply,
   const mongocrypt_opts_t *opts);


const mongocrypt_binary_t *
mongocrypt_encryptor_get_schema (mongocrypt_encryptor_t *encryptor,
                                 const mongocrypt_opts_t *opts);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_markings (mongocrypt_encryptor_t *encryptor,
                                   mongocrypt_binary_t *marked_reply,
                                   const mongocrypt_opts_t *opts);


const mongocrypt_binary_t *
mongocrypt_encryptor_get_key_filter (mongocrypt_encryptor_t *encryptor,
                                     const mongocrypt_opts_t *opts);


bool
mongocrypt_encryptor_add_key (mongocrypt_encryptor_t *encryptor,
                              const mongocrypt_opts_t *opts,
                              mongocrypt_binary_t *key,
                              mongocrypt_status_t *status);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_done_adding_keys (mongocrypt_encryptor_t *encryptor);


mongocrypt_key_decryptor_t *
mongocrypt_encryptor_next_key_decryptor (mongocrypt_encryptor_t *encryptor);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_decrypted_key (
   mongocrypt_encryptor_t *encryptor,
   mongocrypt_key_decryptor_t *key_decryptor);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_done_decrypting_keys (mongocrypt_encryptor_t *encryptor);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_encrypt (mongocrypt_encryptor_t *encryptor);


mongocrypt_encryptor_state_t
mongocrypt_encryptor_state (mongocrypt_encryptor_t *encryptor);


mongocrypt_binary_t *
mongocrypt_encryptor_encrypted_cmd (mongocrypt_encryptor_t *encryptor);


mongocrypt_status_t *
mongocrypt_encryptor_status (mongocrypt_encryptor_t *encryptor);


void
mongocrypt_encryptor_destroy (mongocrypt_encryptor_t *encryptor);


#endif /* MONGOCRYPT_ENCRYPTOR_H */
