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

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-opts-private.h"

typedef struct {
   _mongocrypt_buffer_t id;
   bson_value_t key_alt_names;
   bool has_alt_names;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_kms_provider_t masterkey_provider;
   char *masterkey_region;
   char *masterkey_cmk;
   char *endpoint;
   uint64_t creation_date;
   uint64_t update_date;
} _mongocrypt_key_doc_t;

/* A linked list of key alt names */
typedef struct __mongocrypt_key_alt_name_t {
   struct __mongocrypt_key_alt_name_t *next;
   bson_value_t value;
} _mongocrypt_key_alt_name_t;

_mongocrypt_key_alt_name_t *
_mongocrypt_key_alt_name_copy_all (_mongocrypt_key_alt_name_t *list);
void
_mongocrypt_key_alt_name_destroy_all (_mongocrypt_key_alt_name_t *list);
bool
_mongocrypt_key_alt_name_intersects (_mongocrypt_key_alt_name_t *list_a,
                                     _mongocrypt_key_alt_name_t *list_b);

bool
_mongocrypt_key_parse_owned (const bson_t *bson,
                             _mongocrypt_key_doc_t *out,
                             mongocrypt_status_t *status);

_mongocrypt_key_doc_t *
_mongocrypt_key_new ();

bool
_mongocrypt_key_equal (const _mongocrypt_key_doc_t *a,
                       const _mongocrypt_key_doc_t *b);

void
_mongocrypt_key_doc_copy_to (_mongocrypt_key_doc_t *src,
                             _mongocrypt_key_doc_t *dst);

void
_mongocrypt_key_destroy (_mongocrypt_key_doc_t *key);


#endif /* MONGOCRYPT_KEY_PRIVATE_H */
