/*
 * Copyright 2021-present MongoDB, Inc.
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

#ifndef TEST_MONGOCRYPT_UTIL_H
#define TEST_MONGOCRYPT_UTIL_H

#include "mongocrypt.h"

#include <bson/bson.h>

#include <stdint.h>
#include <stdio.h>

const char *mongocrypt_ctx_state_to_string(mongocrypt_ctx_state_t state);

char *data_to_hex(const uint8_t *data, size_t len);

/* bson_iter_bson iterates a document or array into a bson_t. */
void bson_iter_bson(bson_iter_t *iter, bson_t *bson);

// `kms_ctx_feed_all` repeatedly calls `mongocrypt_kms_ctx_feed`.
// Returns false on a failed call to `mongocrypt_kms_ctx_feed`.
// Useful for KMIP. The KMIP response parser expects two calls: (length, then data).
bool kms_ctx_feed_all(mongocrypt_kms_ctx_t *kms_ctx, const uint8_t *data, uint32_t datalen);

#endif /* TEST_MONGOCRYPT_UTIL_H */
