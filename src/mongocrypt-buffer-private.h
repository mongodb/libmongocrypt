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

/* This is an internal struct to make working with binary values more
 * convenient.
 * - a non-owning buffer can be constructed from a bson_iter_t.
 * - a non-owning buffer can become an owned buffer by copying.
 * - a buffer can be appended as a BSON binary in a bson_t.
 */
typedef struct {
   uint8_t *data;
   uint32_t len;
   bool owned;
   bson_subtype_t subtype;
} _mongocrypt_buffer_t;

void
_mongocrypt_owned_buffer_from_iter (bson_iter_t *iter,
                                    _mongocrypt_buffer_t *out);

void
_mongocrypt_unowned_buffer_from_iter (bson_iter_t *iter,
                                      _mongocrypt_buffer_t *out);

void
_mongocrypt_buffer_cleanup (_mongocrypt_buffer_t *binary);

void
_mongocrypt_bson_append_buffer (bson_t *bson,
                                const char *key,
                                uint32_t key_len,
                                _mongocrypt_buffer_t *in);

#endif /* MONGOCRYPT_BUFFER_H */
