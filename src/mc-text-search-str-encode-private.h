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
#include "mongocrypt-status-private.h"
#include "mongocrypt.h"

// Represents a validate unicode string with the bad character 0xFF appended to the end. This is our base string which
// we build substring trees on. Stores all the valid code points in the string, plus one code point for 0xFF.
typedef struct {
    char *data;
    uint32_t len;
    uint32_t *codepoint_offsets;
    uint32_t codepoint_len;
} mc_utf8_string_with_bad_char_t;

// Set of substrings of a shared base string.
typedef struct _mc_substring_set_t mc_substring_set_t;

// Iterator on substring_set.
typedef struct {
    mc_substring_set_t *set;
    uint32_t cur_idx;
} mc_substring_set_iter_t;

// Point the iterator to the first substring of the given set.
void mc_substring_set_iter_init(mc_substring_set_iter_t *it, mc_substring_set_t *set);

// Get the next substring, its length, and its count. Returns false if the set does not have a next element, true
// otherwise.
bool mc_substring_set_iter_next(mc_substring_set_iter_t *it, const char **str, uint32_t *len, uint32_t *count);

// Result of a StrEncode. Contains the computed prefix, suffix, and substring trees, or NULL if empty, as well as the
// exact string.
typedef struct {
    // Base string which the substring sets point to.
    mc_utf8_string_with_bad_char_t *base_string;
    // Set of encoded suffixes.
    mc_substring_set_t *suffix_set;
    // Set of encoded prefixes.
    mc_substring_set_t *prefix_set;
    // Set of encoded substrings.
    mc_substring_set_t *substring_set;
    // Encoded exact string.
    char *exact;
    size_t exact_len;
} mc_str_encode_sets_t;

// Run StrEncode with the given spec.
mc_str_encode_sets_t *mc_text_search_str_encode(const mc_FLE2TextSearchInsertSpec_t *spec, mongocrypt_status_t *status);

// TODO MONGOCRYPT-759 This helper only exists to test folded_len != unfolded_len; make the test actually use folding
mc_str_encode_sets_t *mc_text_search_str_encode_helper(const mc_FLE2TextSearchInsertSpec_t *spec,
                                                       uint32_t unfolded_len,
                                                       mongocrypt_status_t *status);

void mc_str_encode_sets_destroy(mc_str_encode_sets_t *sets);

#endif /* MONGOCRYPT_TEXT_SEARCH_STR_ENCODE_PRIVATE_H */