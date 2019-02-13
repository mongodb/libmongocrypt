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

#ifndef MONGOCRYPT_KEY_QUERY_H
#define MONGOCRYPT_KEY_QUERY_H

/* The typedef for mongocrypt_binary_t is in here */
#include "mongocrypt-binary.h"

typedef struct _mongocrypt_key_query_t mongocrypt_key_query_t;


const mongocrypt_binary_t *
mongocrypt_key_query_filter (const mongocrypt_key_query_t *key_query);


const char *
mongocrypt_key_query_keyvault_name (const mongocrypt_key_query_t *key_query);


#endif /* MONGOCRYPT_KEY_QUERY_H */
