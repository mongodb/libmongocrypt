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

#ifndef MONGOCRYPT_DECRYPTOR_PRIVATE_H
#define MONGOCRYPT_DECRYPTOR_PRIVATE_H

#include "mongocrypt-private.h"
#include "mongocrypt-decryptor.h"

struct _mongocrypt_decryptor_t {
   mongocrypt_t *crypt;
   mongocrypt_decryptor_state_t state;
   mongocrypt_binary_t *encrypted_doc;
   mongocrypt_binary_t *decrypted_doc;
   mongocrypt_status_t *status;
};


#endif /* MONGOCRYPT_DECRYPTOR_PRIVATE_H */
