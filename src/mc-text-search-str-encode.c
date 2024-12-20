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

#include "mc-text-search-str-encode-private.h"
#include <bson/bson.h>

struct _mc_substring_set_t {
    // base_string is not owned
    const char *base_string;
    uint32_t base_string_len;
    uint32_t *start_indices;
    uint32_t *end_indices;
    uint32_t *substring_counts;
    uint32_t n_indices;
};

mc_substring_set_t *mc_substring_set_new(const char *base_string, uint32_t base_len, uint32_t n_indices) {
    mc_substring_set_t *set = (mc_substring_set_t *)bson_malloc0(sizeof(mc_substring_set_t));
    set->base_string = base_string;
    set->base_string_len = base_len;
    set->start_indices = (uint32_t *)bson_malloc0(sizeof(uint32_t) * n_indices);
    set->end_indices = (uint32_t *)bson_malloc0(sizeof(uint32_t) * n_indices);
    set->substring_counts = (uint32_t *)bson_malloc0(sizeof(uint32_t) * n_indices);
    set->n_indices = n_indices;
    return set;
}

void mc_substring_set_destroy(mc_substring_set_t *set) {
    if (set == NULL) {
        return;
    }
    bson_free(set->start_indices);
    bson_free(set->end_indices);
    bson_free(set->substring_counts);
    bson_free(set);
}

bool mc_substring_set_insert(mc_substring_set_t *set,
                             uint32_t base_start_idx,
                             uint32_t base_end_idx,
                             uint32_t idx,
                             uint32_t count) {
    if (base_start_idx > base_end_idx || base_end_idx > set->base_string_len || idx >= set->n_indices || count == 0) {
        return false;
    }
    set->start_indices[idx] = base_start_idx;
    set->end_indices[idx] = base_end_idx;
    set->substring_counts[idx] = count;
    return true;
}

void mc_substring_set_iter_init(mc_substring_set_iter_t *it, mc_substring_set_t *set) {
    it->set = set;
    it->curIdx = 0;
}

bool mc_substring_set_iter_next(mc_substring_set_iter_t *it, const char **str, uint32_t *len, uint32_t *count) {
    if (it->curIdx >= it->set->n_indices) {
        return false;
    }
    uint32_t start_idx = it->set->start_indices[it->curIdx];
    uint32_t end_idx = it->set->end_indices[it->curIdx];
    *str = &it->set->base_string[start_idx];
    *len = end_idx - start_idx;
    *count = it->set->substring_counts[it->curIdx];
    it->curIdx++;
    return true;
}

// Note -- these are pre-defined only on POSIX systems.
#undef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define BAD_CHAR ((char)0xFF)

mc_substring_set_t *generate_prefix_or_suffix_tree(const char *base_str,
                                                   uint32_t folded_len,
                                                   uint32_t unfolded_len,
                                                   uint32_t lb,
                                                   uint32_t ub,
                                                   bool is_prefix) {
    // 16 * ceil(unfolded len / 16)
    uint32_t cbclen = 16 * (uint32_t)((unfolded_len + 15) / 16);
    if (cbclen < lb) {
        // Empty tree
        return NULL;
    }
    // lb = 2 ub = 14 cbclen = 16 flen = 9
    // 14 - 2 + 1 = 13
    uint32_t msize = MIN(cbclen, ub) - lb + 1;
    // 9
    uint32_t real_max_len = MIN(folded_len, ub);
    // 9-2+1 = 8
    uint32_t real_substrings = real_max_len >= lb ? real_max_len - lb + 1 : 0;
    // If real_substrings and msize are different, we add one to the length for the padding inserts.
    // len 9
    mc_substring_set_t *set = mc_substring_set_new(base_str,
                                                   folded_len + 1,
                                                   real_substrings == msize ? real_substrings : real_substrings + 1);
    // 8 strs
    uint32_t idx = 0;
    for (uint32_t i = lb; i < real_max_len + 1; i++) {
        if (is_prefix) {
            BSON_ASSERT(mc_substring_set_insert(set, 0, i, idx++, 1));
        } else {
            BSON_ASSERT(mc_substring_set_insert(set, folded_len - i, folded_len, idx++, 1));
        }
    }
    if (msize != real_substrings) {
        mc_substring_set_insert(set, 0, folded_len + 1, idx++, msize - real_substrings);
    }
    BSON_ASSERT(idx == set->n_indices);
    return set;
}

mc_substring_set_t *generate_suffix_tree(const char *base_str,
                                         uint32_t folded_len,
                                         uint32_t unfolded_len,
                                         const mc_FLE2SuffixInsertSpec_t *spec) {
    return generate_prefix_or_suffix_tree(base_str, folded_len, unfolded_len, spec->lb, spec->ub, false);
}

mc_substring_set_t *generate_prefix_tree(const char *base_str,
                                         uint32_t folded_len,
                                         uint32_t unfolded_len,
                                         const mc_FLE2PrefixInsertSpec_t *spec) {
    return generate_prefix_or_suffix_tree(base_str, folded_len, unfolded_len, spec->lb, spec->ub, true);
}

uint32_t calc_number_of_substrings(uint32_t strlen, uint32_t lb, uint32_t ub) {
    // There are len - i + 1 substrings of length i in a length len string.
    // Therefore, the total number of substrings with length between lb and ub
    // is the sum of the integers between A = len - ub + 1 and B = len - lb + 1,
    // A <= B. This has a closed form: (A + B)(B - A + 1)/2.
    if (lb > strlen) {
        return 0;
    }
    uint32_t largest_substr = MIN(strlen, ub);
    uint32_t largest_substr_count = strlen - largest_substr + 1;
    uint32_t smallest_substr_count = strlen - lb + 1;
    return (largest_substr_count + smallest_substr_count) * (smallest_substr_count - largest_substr_count + 1) / 2;
}

mc_substring_set_t *generate_substring_tree(const char *base_str,
                                            uint32_t folded_len,
                                            uint32_t unfolded_len,
                                            const mc_FLE2SubstringInsertSpec_t *spec) {
    // 16 * ceil(unfolded len / 16)
    uint32_t cbclen = 16 * (uint32_t)((unfolded_len + 15) / 16);
    if (unfolded_len > spec->mlen || cbclen < spec->lb) {
        // Empty tree
        return NULL;
    }
    uint32_t padded_len = MIN(spec->mlen, cbclen);
    uint32_t msize = calc_number_of_substrings(padded_len, spec->lb, spec->ub);
    uint32_t n_real_substrings = calc_number_of_substrings(folded_len, spec->lb, spec->ub);
    mc_substring_set_t *set =
        mc_substring_set_new(base_str,
                             folded_len + 1,
                             n_real_substrings == msize ? n_real_substrings : n_real_substrings + 1);
    uint32_t idx = 0;
    if (folded_len >= spec->lb) {
        for (uint32_t i = 0; i < folded_len - spec->lb + 1; i++) {
            for (uint32_t j = i + spec->lb; j < MIN(folded_len, i + spec->ub) + 1; j++) {
                mc_substring_set_insert(set, i, j, idx++, 1);
            }
        }
    }
    // Ensure our precalculated value was correct
    if (msize != n_real_substrings) {
        mc_substring_set_insert(set, 0, folded_len + 1, idx++, msize - n_real_substrings);
    }
    BSON_ASSERT(idx == set->n_indices);
    return set;
}

char *make_base_string_for_str_encode(const char *folded_str, uint32_t folded_len) {
    char *ret = (char *)bson_malloc0(folded_len + 1);
    memcpy(ret, folded_str, folded_len);
    ret[folded_len] = BAD_CHAR;
    return ret;
}

// TODO MONGOCRYPT-759 This helper only exists to test folded_len != unfolded_len; make the test actually use folding
mc_str_encode_sets_t mc_text_search_str_encode_helper(const mc_FLE2TextSearchInsertSpec_t *spec,
                                                      uint32_t unfolded_len) {
    const char *folded_str = spec->v;
    uint32_t folded_len = spec->len;

    mc_str_encode_sets_t sets;
    sets.suffix_set = NULL;
    sets.prefix_set = NULL;
    sets.substring_set = NULL;
    // Base string is the folded string plus the 0xFF character
    sets.base_string = make_base_string_for_str_encode(folded_str, folded_len);
    sets.base_len = spec->len + 1;
    if (spec->suffix.set) {
        sets.suffix_set = generate_suffix_tree(sets.base_string, folded_len, unfolded_len, &spec->suffix.value);
    }
    if (spec->prefix.set) {
        sets.prefix_set = generate_prefix_tree(sets.base_string, folded_len, unfolded_len, &spec->prefix.value);
    }
    if (spec->substr.set) {
        sets.substring_set = generate_substring_tree(sets.base_string, folded_len, unfolded_len, &spec->substr.value);
    }
    // Exact string is always the first len characters of the base string
    sets.exact = sets.base_string;
    sets.exact_len = spec->len;
    return sets;
}

mc_str_encode_sets_t mc_text_search_str_encode(const mc_FLE2TextSearchInsertSpec_t *spec) {
    // TODO MONGOCRYPT-759 Implement and use CFold
    uint32_t unfolded_len = spec->len;
    return mc_text_search_str_encode_helper(spec, unfolded_len);
}

void mc_str_encode_sets_destroy(mc_str_encode_sets_t *sets) {
    if (sets == NULL) {
        return;
    }
    bson_free(sets->base_string);
    mc_substring_set_destroy(sets->suffix_set);
    mc_substring_set_destroy(sets->prefix_set);
    mc_substring_set_destroy(sets->substring_set);
}