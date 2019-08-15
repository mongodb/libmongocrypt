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

#ifndef MONGOCRYPT_MARKING_PRIVATE_H
#define MONGOCRYPT_MARKING_PRIVATE_H

#include "mongocrypt-private.h"
#include "mongocrypt-ciphertext-private.h"

typedef struct {
   mongocrypt_encryption_algorithm_t algorithm;
   bson_iter_t v_iter;
   /* one of the following is zeroed, and the other is set. */
   _mongocrypt_buffer_t key_id;
   bson_value_t key_alt_name;
   bool has_alt_name;
} _mongocrypt_marking_t;


void
_mongocrypt_marking_init (_mongocrypt_marking_t *marking);

void
_mongocrypt_marking_cleanup (_mongocrypt_marking_t *marking);

bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status)
   MONGOCRYPT_WARN_UNUSED_RESULT;

bool
_mongocrypt_marking_to_ciphertext (void *ctx,
                                   _mongocrypt_marking_t *marking,
                                   _mongocrypt_ciphertext_t *ciphertext,
                                   mongocrypt_status_t *status)
   MONGOCRYPT_WARN_UNUSED_RESULT;


#endif /* MONGOCRYPT_MARKING_PRIVATE_H */
