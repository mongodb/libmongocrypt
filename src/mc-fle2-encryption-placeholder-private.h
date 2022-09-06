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

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-private.h"

/** FLE2RangeSpec represents the range find specification that is encoded inside
 * of a FLE2EncryptionPlaceholder. See
 * https://github.com/mongodb/mongo/blob/d870dda33fb75983f628636ff8f849c7f1c90b09/src/mongo/crypto/fle_field_schema.idl#L346
 * for the representation in the MongoDB server. */
typedef struct {
   // min is the minimum value for an encrypted range query.
   bson_iter_t min;
   // minIncluded indicates if the lower bound should be included in the range.
   bool minIncluded;
   // max is the maximum value for an encrypted range query.
   bson_iter_t max;
   // maxIncluded indicates if the upper bound should be included in the range.
   bool maxIncluded;
} mc_FLE2RangeSpec_t;

bool
mc_FLE2RangeSpec_parse (mc_FLE2RangeSpec_t *out,
                        const bson_iter_t *in,
                        mongocrypt_status_t *status);

/** mc_FLE2RangeInsertSpec_t represents the range insert specification that is
 * encoded inside of a FLE2EncryptionPlaceholder. See
 * https://github.com/mongodb/mongo/blob/d870dda33fb75983f628636ff8f849c7f1c90b09/src/mongo/crypto/fle_field_schema.idl#L364
 * for the representation in the MongoDB server. */
typedef struct {
   // v is the value to encrypt.
   bson_iter_t v;
   // lb is the Queryable Encryption lower bound for range.
   bson_iter_t lb;
   // ub is the Queryable Encryption upper bound for range.
   bson_iter_t ub;
} mc_FLE2RangeInsertSpec_t;

bool
mc_FLE2RangeInsertSpec_parse (mc_FLE2RangeInsertSpec_t *out,
                              const bson_iter_t *in,
                              mongocrypt_status_t *status);

/** FLE2EncryptionPlaceholder implements Encryption BinData (subtype 6)
 * sub-subtype 0, the intent-to-encrypt mapping. Contains a value to encrypt and
 * a description of how it should be encrypted.
 *
 * For automatic encryption, FLE2EncryptionPlaceholder is created by query
 * analysis (mongocryptd or mongo_crypt shared library). For explicit
 * encryption, FLE2EncryptionPlaceholder is created by libmongocrypt.
 *
 * FLE2EncryptionPlaceholder is processed by libmongocrypt into a payload
 * suitable to send to the MongoDB server (mongod/mongos).
 *
 * See
 * https://github.com/mongodb/mongo/blob/d870dda33fb75983f628636ff8f849c7f1c90b09/src/mongo/crypto/fle_field_schema.idl#L133
 * for the representation in the MongoDB server.
 */

typedef struct {
   mongocrypt_fle2_placeholder_type_t type;
   mongocrypt_fle2_encryption_algorithm_t algorithm;
   bson_iter_t v_iter;
   _mongocrypt_buffer_t index_key_id;
   _mongocrypt_buffer_t user_key_id;
   int64_t maxContentionCounter;
   // sparsity is the Queryable Encryption range hypergraph sparsity factor
   int32_t sparsity;
} mc_FLE2EncryptionPlaceholder_t;

void
mc_FLE2EncryptionPlaceholder_init (mc_FLE2EncryptionPlaceholder_t *placeholder);

bool
mc_FLE2EncryptionPlaceholder_parse (mc_FLE2EncryptionPlaceholder_t *out,
                                    const bson_t *in,
                                    mongocrypt_status_t *status);

void
mc_FLE2EncryptionPlaceholder_cleanup (
   mc_FLE2EncryptionPlaceholder_t *placeholder);

/* mc_validate_contention is used to check that contention is a valid
 * value. contention may come from the 'cm' field in FLE2EncryptionPlaceholder
 * or from mongocrypt_ctx_setopt_contention_factor. */
bool
mc_validate_contention (int64_t contention, mongocrypt_status_t *status);

/* mc_validate_sparsity is used to check that sparsity is a valid
 * value. */
bool
mc_validate_sparsity (int32_t sparsity, mongocrypt_status_t *status);

#endif /* MC_FLE2_ENCRYPTION_PLACEHOLDER_PRIVATE_H */
