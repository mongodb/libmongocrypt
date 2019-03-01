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

#ifndef MONGOCRYPT_ENCRYPTOR_PRIVATE_H
#define MONGOCRYPT_ENCRYPTOR_PRIVATE_H

#include "mongocrypt-private.h"
#include "mongocrypt-encryptor.h"
#include "mongocrypt-key-broker-private.h"

struct _mongocrypt_encryptor_t {
   mongocrypt_t *crypt;
   mongocrypt_encryptor_state_t state;
   mongocrypt_binary_t *schema;
   bson_t *marked;
   mongocrypt_binary_t *filter;
   mongocrypt_binary_t *encrypted_cmd;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_t kb;
   /* used to iterate over keys to decrypt. */
   _mongocrypt_key_broker_entry_t *kb_item;
   const char *ns;
};


#endif /* MONGOCRYPT_ENCRYPTOR_PRIVATE_H */
