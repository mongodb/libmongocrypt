/*
 * Copyright 2024-present MongoDB, Inc.
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

#ifndef MONGOCRYPT_TEXT_SEARCH_STR_ENCODE_PRIVATE_H
#define MONGOCRYPT_TEXT_SEARCH_STR_ENCODE_PRIVATE_H

#include "mc-fle2-encryption-placeholder-private.h"
#include "mc-str-encode-string-sets-private.h"
#include "mongocrypt-status-private.h"
#include "mongocrypt.h"

// Result of a StrEncode. Contains the computed prefix, suffix, and substring trees, or NULL if empty, as well as the
// exact string.
typedef struct {
    // Base string which the substring sets point to.
    mc_utf8_string_with_bad_char_t *base_string;
    // Set of encoded suffixes.
    mc_affix_set_t *suffix_set;
    // Set of encoded prefixes.
    mc_affix_set_t *prefix_set;
    // Set of encoded substrings.
    mc_substring_set_t *substring_set;
    // Encoded exact string.
    _mongocrypt_buffer_t exact;
} mc_str_encode_sets_t;

// Run StrEncode with the given spec.
mc_str_encode_sets_t *mc_text_search_str_encode(const mc_FLE2TextSearchInsertSpec_t *spec, mongocrypt_status_t *status);

// TODO MONGOCRYPT-759 This helper only exists to test folded_len != unfolded_len; make the test actually use folding
mc_str_encode_sets_t *mc_text_search_str_encode_helper(const mc_FLE2TextSearchInsertSpec_t *spec,
                                                       uint32_t unfolded_len,
                                                       mongocrypt_status_t *status);

void mc_str_encode_sets_destroy(mc_str_encode_sets_t *sets);

#endif /* MONGOCRYPT_TEXT_SEARCH_STR_ENCODE_PRIVATE_H */