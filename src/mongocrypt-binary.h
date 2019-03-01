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

#ifndef MONGOCRYPT_BINARY_H
#define MONGOCRYPT_BINARY_H

#include <stdint.h>

/* TODO CDRIVER-2990: we have three ways of representing binary/BSON
 * mongocrypt_binary_t - public
 * _mongocrypt_buffer_t - private, has conveniences
 * bson_t - for working with bson
 * TODO: consider having _mongocrypt_buffer_t contain a bson member.
 * TODO: consider having _mongocrypt_buffer_t data inherit mongocrypt_binary_t
 * so we can return them from functions.
 * TODO: be consistent about when to pass pointers, and const-ness.
 * TODO: return only const pointers to mongocrypt_binary_t?
 */
typedef struct {
   uint8_t *data;
   uint32_t len;
} mongocrypt_binary_t; /* TODO: likely rename to BSON */


mongocrypt_binary_t *
mongocrypt_binary_new (void);

void
mongocrypt_binary_destroy (mongocrypt_binary_t *binary);


#endif /* MONGOCRYPT_BINARY_H */
