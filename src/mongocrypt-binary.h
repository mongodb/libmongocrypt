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

#include "mongocrypt-export.h"

/**
 * A non-owning view of a byte buffer.
 *
 * Functions returning a mongocrypt_binary_t* expect it to be destroyed with
 * mongocrypt_binary_destroy.
 *
 * Functions taking a mongocrypt_binary_t* argument may either copy or keep a
 * pointer to the data. See individual function documentation.
*/
typedef struct _mongocrypt_binary_t mongocrypt_binary_t;

/**
 * Create a new non-owning view of a buffer (data + length). Free the view with
 * mongocrypt_binary_destroy.
 *
 * @param data A pointer to an array of bytes. This is not copied. @data must
 * outlive the binary object.
 * @param len The length of the @data array.
 *
 * @returns A new mongocrypt_binary_t that must later be destroyed with
 * mongocrypt_binary_destroy.
 */
MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_binary_new (uint8_t *data, uint32_t len);


/**
 * Get a pointer to the referenced data.
 *
 * @param binary The mongocrypt_binary_t from which to retrieve the data.
 *
 * @returns A pointer to the referenced data.
 */
MONGOCRYPT_EXPORT
const uint8_t *
mongocrypt_binary_data (const mongocrypt_binary_t *binary);


/**
 * Get the length of the referenced data.
 *
 * @param binary The mongocrypt_binary_t from which to retrieve the length.
 *
 * @returns The length of the referenced data.
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_binary_len (const mongocrypt_binary_t *binary);


/**
 * Free the mongocrypt_binary_t. Does not free the referenced data.
 *
 * @param binary The mongocrypt_binary_t destroy.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_binary_destroy (mongocrypt_binary_t *binary);


#endif /* MONGOCRYPT_BINARY_H */
