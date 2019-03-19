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
#include "mongocrypt-export.h"
#include "mongocrypt-key-broker.h"
#include "mongocrypt-status.h"


typedef struct _mongocrypt_encryptor_t mongocrypt_encryptor_t;

typedef enum {
   MONGOCRYPT_ENCRYPTOR_STATE_ERROR = 0,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS = 1,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA = 2,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS = 3,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS = 4,
   MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION = 5,
   MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED = 6,
   MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED = 7
} mongocrypt_encryptor_state_t;

MONGOCRYPT_EXPORT
mongocrypt_encryptor_t *
mongocrypt_encryptor_new (mongocrypt_t *crypt);


MONGOCRYPT_EXPORT
mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_ns (mongocrypt_encryptor_t *encryptor, const char *ns);


MONGOCRYPT_EXPORT
mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_collection_info (
   mongocrypt_encryptor_t *encryptor,
   const mongocrypt_binary_t *collection_info);


MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_encryptor_get_schema (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_markings (mongocrypt_encryptor_t *encryptor,
                                   mongocrypt_binary_t *marked_reply);

MONGOCRYPT_EXPORT
mongocrypt_key_broker_t *
mongocrypt_encryptor_get_key_broker (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
mongocrypt_encryptor_state_t
mongocrypt_encryptor_key_broker_done (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
mongocrypt_encryptor_state_t
mongocrypt_encryptor_encrypt (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
mongocrypt_encryptor_state_t
mongocrypt_encryptor_state (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_encryptor_encrypted_cmd (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
mongocrypt_status_t *
mongocrypt_encryptor_status (mongocrypt_encryptor_t *encryptor);


MONGOCRYPT_EXPORT
void
mongocrypt_encryptor_destroy (mongocrypt_encryptor_t *encryptor);


#endif /* MONGOCRYPT_ENCRYPTOR_H */
