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

#ifndef MONGOCRYPT_CACHE_KEY_PRIVATE_H
#define MONGOCRYPT_CACHE_KEY_PRIVATE_H

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-cache-private.h"
#include "mongocrypt-key-private.h"
#include "mongocrypt-mutex-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-status-private.h"

typedef struct {
   _mongocrypt_key_doc_t *key_doc;
   _mongocrypt_buffer_t decrypted_key_material;
} _mongocrypt_cache_key_value_t;

void
_mongocrypt_cache_key_init (_mongocrypt_cache_t *cache);

_mongocrypt_cache_key_value_t *
_mongocrypt_cache_key_value_new (_mongocrypt_key_doc_t *key_doc,
                                 _mongocrypt_buffer_t *decrypted_key_material);

void
_mongocrypt_cache_key_value_destroy (void *value);


#endif /* MONGOCRYPT_CACHE_KEY_PRIVATE_H */
