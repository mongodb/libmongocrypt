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

#ifndef MONGOCRYPT_BUFFER_H
#define MONGOCRYPT_BUFFER_H

#include <bson/bson.h>

struct _mongocrypt_binary_t;

/* An internal struct to make working with binary values more convenient.
 * - a non-owning buffer can be constructed from a bson_iter_t.
 * - a non-owning buffer can become an owned buffer by copying.
 * - a buffer can be appended as a BSON binary in a bson_t.
 */
typedef struct __mongocrypt_buffer_t {
   uint8_t *data;
   uint32_t len;
   bool owned;
   bson_subtype_t subtype;
} _mongocrypt_buffer_t;


void
_mongocrypt_buffer_init (_mongocrypt_buffer_t *buf);


/* @iter is iterated to a BSON binary value. */
void
_mongocrypt_buffer_copy_from_iter (_mongocrypt_buffer_t *buf,
                                   bson_iter_t *iter);


/* @iter is iterated to a BSON binary value. */
void
_mongocrypt_buffer_from_iter (_mongocrypt_buffer_t *buf, bson_iter_t *iter);


/* @iter is iterated to a BSON document value. */
void
_mongocrypt_buffer_from_document_iter (_mongocrypt_buffer_t *buf,
                                       bson_iter_t *iter);


/* @iter is iterated to a BSON document value. */
void
_mongocrypt_buffer_copy_from_document_iter (_mongocrypt_buffer_t *buf,
                                            bson_iter_t *iter);


void
_mongocrypt_buffer_steal_from_bson (_mongocrypt_buffer_t *buf, bson_t *bson);


void
_mongocrypt_buffer_from_bson (_mongocrypt_buffer_t *buf, const bson_t *bson);


void
_mongocrypt_buffer_to_bson (const _mongocrypt_buffer_t *buf, bson_t *bson);


void
_mongocrypt_buffer_append (const _mongocrypt_buffer_t *buf,
                           bson_t *bson,
                           const char *key,
                           uint32_t key_len);


void
_mongocrypt_buffer_from_binary (_mongocrypt_buffer_t *buf,
                                const struct _mongocrypt_binary_t *binary);

void
_mongocrypt_buffer_copy_from_binary (_mongocrypt_buffer_t *buf,
                                     const struct _mongocrypt_binary_t *binary);


void
_mongocrypt_buffer_to_binary (_mongocrypt_buffer_t *buf, struct _mongocrypt_binary_t * binary);


void
_mongocrypt_buffer_copy_to (const _mongocrypt_buffer_t *src,
                            _mongocrypt_buffer_t *dst);


int
_mongocrypt_buffer_cmp (const _mongocrypt_buffer_t *a,
                        const _mongocrypt_buffer_t *b);


void
_mongocrypt_buffer_cleanup (_mongocrypt_buffer_t *buf);


bool
_mongocrypt_buffer_empty (_mongocrypt_buffer_t *buf);

#endif /* MONGOCRYPT_BUFFER_H */
