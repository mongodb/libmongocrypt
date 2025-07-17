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

#include "mc-textopts-private.h"

#include "mongocrypt-private.h"
#include "mongocrypt-util-private.h" // mc_bson_type_to_string

// Common logic for testing field name, tracking duplication, and presence.
#define IF_FIELD(Name)                                                                                                 \
    if (0 == strcmp(field, #Name)) {                                                                                   \
        if (has_##Name) {                                                                                              \
            CLIENT_ERR(ERROR_PREFIX "Unexpected duplicate field '" #Name "'");                                         \
            return false;                                                                                              \
        }                                                                                                              \
        has_##Name = true;                                                                                             \
    ((void)0)

#define END_IF_FIELD                                                                                                   \
    continue;                                                                                                          \
    }                                                                                                                  \
    else((void)0)

#define ERROR_PREFIX "Error parsing TextOpts: "

bool mc_TextOpts_parse(mc_TextOpts_t *txo, const bson_t *in, mongocrypt_status_t *status) {
    bson_iter_t iter = {0};
    bool has_min = false, has_max = false, has_sparsity = false, has_precision = false, has_trimFactor = false;
    bool has_caseSensitive = false, has_diacriticSensitive = false, has_strMaxLength = false, has_strMinQueryLength = false, has_strMaxQueryLength = false;
    BSON_ASSERT_PARAM(txo);
    BSON_ASSERT_PARAM(in);
    BSON_ASSERT(status || true);

    *txo = (mc_TextOpts_t){0};
    txo->bson = bson_copy(in);

    if (!bson_iter_init(&iter, txo->bson)) {
        CLIENT_ERR(ERROR_PREFIX "Invalid BSON");
        return false;
    }

    while (bson_iter_next(&iter)) {
        const char *field = bson_iter_key(&iter);
        BSON_ASSERT(field);

        IF_FIELD(caseSensitive);
        {
            if (!BSON_ITER_HOLDS_BOOL(&iter)) {
                CLIENT_ERR(ERROR_PREFIX "Expected bool for caseSensitive, got: %s",
                           mc_bson_type_to_string(bson_iter_type(&iter)));
                return false;
            }
            txo->caseSensitive = bson_iter_bool(&iter);
        }
        END_IF_FIELD;

        IF_FIELD(diacriticSensitive);
        {
            if (!BSON_ITER_HOLDS_BOOL(&iter)) {
                CLIENT_ERR(ERROR_PREFIX "Expected bool for diacriticSensitive, got: %s",
                           mc_bson_type_to_string(bson_iter_type(&iter)));
                return false;
            }
            txo->diacriticSensitive = bson_iter_bool(&iter);
        }
        END_IF_FIELD;

        IF_FIELD(strMaxLength);
        {
            if (!BSON_ITER_HOLDS_INT32(&iter)) {
                CLIENT_ERR(ERROR_PREFIX "'strMaxLength' must be an int32");
                return false;
            }
            const int32_t val = bson_iter_int32(&iter);
            if (val <= 0) {
                CLIENT_ERR(ERROR_PREFIX "'strMaxLength' must be greater than zero");
                return false;
            }
            txo->strMaxLength = val;
        }
        END_IF_FIELD;

        IF_FIELD(strMinQueryLength);
        {
            if (!BSON_ITER_HOLDS_INT32(&iter)) {
                CLIENT_ERR(ERROR_PREFIX "'strMinQueryLength' must be an int32");
                return false;
            }
            const int32_t val = bson_iter_int32(&iter);
            if (val <= 0) {
                CLIENT_ERR(ERROR_PREFIX "'strMinQueryLength' must be greater than zero");
                return false;
            }
            txo->strMinQueryLength = val;
        }
        END_IF_FIELD;

        IF_FIELD(strMaxQueryLength);
        {
            if (!BSON_ITER_HOLDS_INT32(&iter)) {
                CLIENT_ERR(ERROR_PREFIX "'strMaxQueryLength' must be an int32");
                return false;
            }
            const int32_t val = bson_iter_int32(&iter);
            if (val <= 0) {
                CLIENT_ERR(ERROR_PREFIX "'strMaxQueryLength' must be greater than zero");
                return false;
            }
            txo->strMaxQueryLength = val;
        }
        END_IF_FIELD;

        CLIENT_ERR(ERROR_PREFIX "Unrecognized field: '%s'", field);
        return false;
    }

    return true;
}

#undef ERROR_PREFIX
#define ERROR_PREFIX "Error making FLE2RangeInsertSpec: "

bool mc_TextOpts_to_FLE2TextSearchInsertSpec(const mc_TextOpts_t *txo,
                                        mongocrypt_index_type_t index_type,
                                         const bson_t *v,
                                         bson_t *out,
                                         mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(txo);
    BSON_ASSERT_PARAM(v);
    BSON_ASSERT_PARAM(out);
    BSON_ASSERT(status || true);

    bson_iter_t v_iter;
    if (!bson_iter_init_find(&v_iter, v, "v")) {
        CLIENT_ERR(ERROR_PREFIX "Unable to find 'v' in input");
        return false;
    }

    bson_t child;
    if (!BSON_APPEND_DOCUMENT_BEGIN(out, "v", &child)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }
    if (!bson_append_iter(&child, "v", 1, &v_iter)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }
    if (!bson_append_bool(&child, "casef", -1, txo->caseSensitive)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    if (!bson_append_bool(&child, "diacf", -1, txo->diacriticSensitive)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    bson_t insert_spec;
    const char *type_key;
    switch (txo->type) {
        case MONGOCRYPT_TEXT_SEARCH_PREFIX:
            type_key = "prefix";
            break;
        case MONGOCRYPT_TEXT_SEARCH_SUFFIX:
            type_key = "suffix";
            break;
        case MONGOCRYPT_TEXT_SEARCH_SUBSTRING:
            type_key = "substr";
            break;
        default:
            abort();
    }
    if (!BSON_APPEND_DOCUMENT_BEGIN(&child, type_key, &insert_spec)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    // TODO optional strMaxLength
    if (!bson_append_int32(&insert_spec, "ub", -1, txo->strMaxQueryLength)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    if (!bson_append_int32(&insert_spec, "lb", -1, txo->strMinQueryLength)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    if (!bson_append_document_end(&child, &insert_spec)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    if (!bson_append_document_end(out, &child)) {
        CLIENT_ERR(ERROR_PREFIX "Error appending to BSON");
        return false;
    }

    return true;
}

#undef ERROR_PREFIX
