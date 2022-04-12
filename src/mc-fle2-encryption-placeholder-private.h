/*
 * Copyright 2022-present MongoDB, Inc.
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

#ifndef MC_FLE2_ENCRYPTION_PLACEHOLDER_PRIVATE_H
#define MC_FLE2_ENCRYPTION_PLACEHOLDER_PRIVATE_H

#include <bson.h>

#include "mongocrypt.h"
#include "mongocrypt-private.h"

typedef struct {
   mongocrypt_fle2_placeholder_type_t type;
   mongocrypt_fle2_encryption_algorithm_t algorithm;
   bson_iter_t v_iter;
   _mongocrypt_buffer_t index_key_id;
   _mongocrypt_buffer_t user_key_id;
   int64_t maxContentionCounter;
} mc_FLE2EncryptionPlaceholder_t;

void
mc_FLE2EncryptionPlaceholder_init (
   mc_FLE2EncryptionPlaceholder_t *placeholder);

bool
mc_FLE2EncryptionPlaceholder_parse (mc_FLE2EncryptionPlaceholder_t *out,
                                      const bson_t *in,
                                      mongocrypt_status_t *status);

void
mc_FLE2EncryptionPlaceholder_cleanup (
   mc_FLE2EncryptionPlaceholder_t *placeholder);

#endif /* MC_FLE2_ENCRYPTION_PLACEHOLDER_PRIVATE_H */
