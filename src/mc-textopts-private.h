/*
 * Copyright 2025-present MongoDB, Inc.
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

#ifndef MC_TEXTOPTS_PRIVATE_H
#define MC_TEXTOPTS_PRIVATE_H

#include <bson/bson.h>

#include "mongocrypt-private.h"

typedef enum {
    MONGOCRYPT_TEXT_SEARCH_PREFIX = 0,
    MONGOCRYPT_TEXT_SEARCH_SUFFIX = 1,
    MONGOCRYPT_TEXT_SEARCH_SUBSTRING = 2,
} mongocrypt_text_search_type_t;

typedef struct {
    bson_t *bson;

    mongocrypt_text_search_type_t type;
    int32_t strMaxLength;
    int32_t strMinQueryLength;
    int32_t strMaxQueryLength;
    bool caseSensitive;
    bool diacriticSensitive;
} mc_TextOpts_t;

// `mc_RangeOpts_t` inherits extended alignment from libbson. To dynamically allocate, use
// aligned allocation (e.g. BSON_ALIGNED_ALLOC)
// BSON_STATIC_ASSERT2(alignof_mc_TextOpts_t,
//                     BSON_ALIGNOF(mc_TextOpts_t) >= BSON_MAX(BSON_ALIGNOF(bson_t), BSON_ALIGNOF(bson_iter_t)));

/* mc_TextOpts_parse parses a BSON document into mc_TextOpts_t.
 * The document is expected to have the form:
 * {
 *    "min": BSON value,
 *    "max": BSON value,
 *    "sparsity": Optional<Int64>,
 *    "precision": Optional<Int32>,
 *    "trimFactor": Optional<Int32>,
 * }
 */
bool mc_TextOpts_parse(mc_TextOpts_t *txo, const bson_t *in, mongocrypt_status_t *status);

/*
 * mc_RangeOpts_to_FLE2RangeInsertSpec creates a placeholder value to be
 * encrypted. It is only expected to be called when query_type is unset. The
 * output FLE2RangeInsertSpec is a BSON document of the form:
 * {
 *    "v": BSON value to encrypt,
 *    "min": BSON value,
 *    "max": BSON value,
 *    "precision": Optional<Int32>
 * }
 *
 * v is expect to be a BSON document of the form:
 * { "v": BSON value to encrypt }.
 *
 * Preconditions: out must be initialized by caller.
 */
// bool mc_RangeOpts_to_FLE2RangeInsertSpec(const mc_RangeOpts_t *ro,
//                                          const bson_t *v,
//                                          bson_t *out,
//                                          mongocrypt_status_t *status);

bool mc_TextOpts_to_FLE2TextSearchInsertSpec(const mc_TextOpts_t *txo,
                                         mongocrypt_index_type_t index_type,
                                         const bson_t *v,
                                         bson_t *out,
                                         mongocrypt_status_t *status);


// void mc_RangeOpts_cleanup(mc_RangeOpts_t *ro);

#endif // MC_TEXTOPTS_PRIVATE_H
