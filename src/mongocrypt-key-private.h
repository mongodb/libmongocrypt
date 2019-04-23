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

#ifndef MONGOCRYPT_KEY_PRIVATE_H
#define MONGOCRYPT_KEY_PRIVATE_H

#define MONGOCRYPT_KEYMATERIAL_LEN 64

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-opts-private.h"

typedef struct {
   _mongocrypt_buffer_t id;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_kms_provider_t masterkey_provider;
   char *masterkey_region;
   char *masterkey_cmk;
} _mongocrypt_key_doc_t;

bool
_mongocrypt_key_parse_owned (const bson_t *bson,
                             _mongocrypt_key_doc_t *out,
                             mongocrypt_status_t *status);

void
_mongocrypt_key_doc_copy_to (_mongocrypt_key_doc_t *src,
                             _mongocrypt_key_doc_t *dst);


void
_mongocrypt_key_cleanup (_mongocrypt_key_doc_t *key);


#endif /* MONGOCRYPT_KEY_PRIVATE_H */
