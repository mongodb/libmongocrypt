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

#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#include "mc-fle2-encryption-placeholder-private.h"
#include "mc-str-encode-string-sets-private.h"
#include "mc-text-search-str-encode-private.h"
#include <stdint.h>
#include <string.h>

#undef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

uint32_t get_utf8_codepoint_length(const char *buf, uint32_t len) {
    const char *cur = buf;
    const char *end = buf + len;
    uint32_t codepoint_len = 0;
    while (cur < end) {
        cur = bson_utf8_next_char(cur);
        codepoint_len++;
    }
    return codepoint_len;
}

// TODO MONGOCRYPT-759 Modify these tests not to take unfolded_codepoint_len, but to instead take strings with
// diacritics and fold them
static void test_nofold_suffix_prefix_case(_mongocrypt_tester_t *tester,
                                           const char *str,
                                           uint32_t lb,
                                           uint32_t ub,
                                           uint32_t unfolded_codepoint_len) {
    fprintf(stderr,
            "Testing nofold suffix/prefix case: str=\"%s\", lb=%u, ub=%u, unfolded_codepoint_len=%u\n",
            str,
            lb,
            ub,
            unfolded_codepoint_len);
    uint32_t byte_len = (uint32_t)strlen(str);
    uint32_t codepoint_len = get_utf8_codepoint_length(str, byte_len);
    uint32_t max_padded_len = 16 * (uint32_t)((unfolded_codepoint_len + 15) / 16);
    uint32_t max_affix_len = MIN(ub, codepoint_len);
    uint32_t n_real_affixes = max_affix_len >= lb ? max_affix_len - lb + 1 : 0;
    uint32_t n_affixes = MIN(ub, max_padded_len) - lb + 1;
    uint32_t n_padding = n_affixes - n_real_affixes;

    mc_str_encode_sets_t *sets;
    mongocrypt_status_t *status = mongocrypt_status_new();
    for (int suffix = 0; suffix <= 1; suffix++) {
        if (suffix) {
            mc_FLE2TextSearchInsertSpec_t spec =
                {str, byte_len, {{0, 0, 0}, false}, {{lb, ub}, true}, {{0, 0}, false}, false, false};
            sets = mc_text_search_str_encode_helper(&spec, unfolded_codepoint_len, status);
        } else {
            mc_FLE2TextSearchInsertSpec_t spec =
                {str, byte_len, {{0, 0, 0}, false}, {{0, 0}, false}, {{lb, ub}, true}, false, false};
            sets = mc_text_search_str_encode_helper(&spec, unfolded_codepoint_len, status);
        }
        ASSERT_OR_PRINT(sets, status);
        ASSERT(sets->base_string->buf.len == byte_len + 1);
        ASSERT(sets->base_string->codepoint_len == codepoint_len + 1);
        ASSERT(0 == memcmp(sets->base_string->buf.data, str, byte_len));
        ASSERT(sets->base_string->buf.data[byte_len] == (uint8_t)0xFF);
        ASSERT(sets->substring_set == NULL);
        ASSERT(sets->exact.len == byte_len);
        ASSERT(0 == memcmp(sets->exact.data, str, byte_len));

        if (lb > max_padded_len) {
            ASSERT(sets->suffix_set == NULL);
            ASSERT(sets->prefix_set == NULL);
            goto CONTINUE;
        }

        fprintf(stderr,
                "Expecting: n_real_affixes: %u, n_affixes: %u, n_padding: %u\n",
                n_real_affixes,
                n_affixes,
                n_padding);

        mc_affix_set_t *set;
        if (suffix) {
            ASSERT(sets->prefix_set == NULL);
            set = sets->suffix_set;
        } else {
            ASSERT(sets->suffix_set == NULL);
            set = sets->prefix_set;
        }
        ASSERT(set != NULL);

        mc_affix_set_iter_t it;
        mc_affix_set_iter_init(&it, set);
        const char *affix;

        uint32_t idx = 0;
        uint32_t affix_len = 0;
        uint32_t affix_count = 0;
        uint32_t total_real_affix_count = 0;
        while (mc_affix_set_iter_next(&it, &affix, &affix_len, &affix_count)) {
            // Since all substrings are just views on the base string, we can use pointer math to find our start and
            // indices.
            fprintf(stderr,
                    "Affix starting %lld, ending %lld, count %u\n",
                    (long long)((uint8_t *)affix - sets->base_string->buf.data),
                    (long long)((uint8_t *)affix - sets->base_string->buf.data + affix_len),
                    affix_count);
            if (affix_len == byte_len + 1) {
                // This is padding, so there should be no more entries due to how we ordered them
                ASSERT(!mc_affix_set_iter_next(&it, NULL, NULL, NULL));
                break;
            }

            ASSERT(affix_len <= byte_len);
            ASSERT(0 < affix_len);

            // We happen to always order from smallest to largest in the suffix/prefix algorithm, which makes our life
            // slightly easier when testing.
            if (suffix) {
                uint32_t start_offset = sets->base_string->codepoint_offsets[codepoint_len - (lb + idx)];
                ASSERT((uint8_t *)affix == sets->base_string->buf.data + start_offset);
                ASSERT(affix_len == sets->base_string->codepoint_offsets[codepoint_len] - start_offset)
            } else {
                uint32_t end_offset = sets->base_string->codepoint_offsets[lb + idx];
                ASSERT((uint8_t *)affix == sets->base_string->buf.data);
                ASSERT(affix_len == end_offset);
            }
            // The count should always be 1, except for padding.
            ASSERT(1 == affix_count);
            total_real_affix_count++;
            idx++;
        }
        ASSERT(total_real_affix_count == n_real_affixes);
        if (affix_len == byte_len + 1) {
            // Padding
            ASSERT((uint8_t *)affix == sets->base_string->buf.data);
            ASSERT(affix_count == n_padding);
        } else {
            // No padding found
            ASSERT(n_padding == 0);
        }
    CONTINUE:
        mc_str_encode_sets_destroy(sets);
    }
    mongocrypt_status_destroy(status);
}

static uint32_t calc_number_of_substrings(uint32_t len, uint32_t lb, uint32_t ub) {
    uint32_t ret = 0;
    // Calculate the long way to make sure our math in calc_number_of_substrings is correct
    for (uint32_t i = 0; i < len; i++) {
        uint32_t max_sublen = MIN(ub, len - i);
        uint32_t n_substrings = max_sublen < lb ? 0 : max_sublen - lb + 1;
        ret += n_substrings;
    }
    return ret;
}

static uint32_t calc_unique_substrings(const mc_utf8_string_with_bad_char_t *str, uint32_t lb, uint32_t ub) {
    uint32_t len = str->codepoint_len - 1; // eliminate last 0xff CP
    if (len < lb) {
        return 0;
    }
    // Bruteforce to make sure our hashset is working as expected.
    uint8_t *idx_is_dupe = bson_malloc0(len);
    uint32_t dupes = 0;
    for (uint32_t ss_len = lb; ss_len <= BSON_MIN(len, ub); ss_len++) {
        for (uint32_t i = 0; i < len - ss_len; i++) {
            // Already checked
            if (idx_is_dupe[i]) {
                continue;
            }
            for (uint32_t j = i + 1; j <= len - ss_len; j++) {
                // Already counted
                if (idx_is_dupe[j]) {
                    continue;
                }
                uint32_t i_start_byte = str->codepoint_offsets[i];
                uint32_t i_end_byte = str->codepoint_offsets[i + ss_len];
                uint32_t j_start_byte = str->codepoint_offsets[j];
                uint32_t j_end_byte = str->codepoint_offsets[j + ss_len];
                if (i_end_byte - i_start_byte == j_end_byte - j_start_byte
                    && memcmp(&str->buf.data[i_start_byte], &str->buf.data[j_start_byte], i_end_byte - i_start_byte)
                           == 0) {
                    idx_is_dupe[j] = 1;
                    dupes++;
                }
            }
        }
        memset(idx_is_dupe, 0, len);
    }
    bson_free(idx_is_dupe);
    return calc_number_of_substrings(len, lb, ub) - dupes;
}

static void test_nofold_substring_case(_mongocrypt_tester_t *tester,
                                       const char *str,
                                       uint32_t lb,
                                       uint32_t ub,
                                       uint32_t mlen,
                                       uint32_t unfolded_codepoint_len) {
    fprintf(stderr,
            "Testing nofold substring case: str=\"%s\", lb=%u, ub=%u, mlen=%u, unfolded_codepoint_len=%u\n",
            str,
            lb,
            ub,
            mlen,
            unfolded_codepoint_len);
    uint32_t byte_len = (uint32_t)strlen(str);
    uint32_t codepoint_len = get_utf8_codepoint_length(str, byte_len);
    uint32_t max_padded_len = 16 * (uint32_t)((unfolded_codepoint_len + 15) / 16);
    uint32_t n_substrings = calc_number_of_substrings(MIN(max_padded_len, mlen), lb, ub);

    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_str_encode_sets_t *sets;
    mc_FLE2TextSearchInsertSpec_t spec =
        {str, byte_len, {{mlen, lb, ub}, true}, {{0, 0}, false}, {{0, 0}, false}, false, false};
    sets = mc_text_search_str_encode_helper(&spec, unfolded_codepoint_len, status);
    if (unfolded_codepoint_len > mlen) {
        ASSERT_FAILS_STATUS(sets, status, "longer than the maximum length");
        mongocrypt_status_destroy(status);
        return;
    }
    ASSERT_OR_PRINT(sets, status);
    mongocrypt_status_destroy(status);
    ASSERT(sets->base_string->buf.len == byte_len + 1);
    ASSERT(sets->base_string->codepoint_len == codepoint_len + 1);
    ASSERT(0 == memcmp(sets->base_string->buf.data, str, byte_len));
    ASSERT(sets->base_string->buf.data[byte_len] == (uint8_t)0xFF);
    ASSERT(sets->suffix_set == NULL)
    ASSERT(sets->prefix_set == NULL);
    ASSERT(sets->exact.len == byte_len);
    ASSERT(0 == memcmp(sets->exact.data, str, byte_len));

    if (unfolded_codepoint_len > mlen || lb > max_padded_len) {
        ASSERT(sets->substring_set == NULL);
        goto cleanup;
    } else {
        ASSERT(sets->substring_set != NULL);
    }

    uint32_t n_real_substrings = calc_unique_substrings(sets->base_string, lb, ub);
    uint32_t n_padding = n_substrings - n_real_substrings;

    fprintf(stderr,
            "Expecting: n_real_substrings: %u, n_substrings: %u, n_padding: %u\n",
            n_real_substrings,
            n_substrings,
            n_padding);

    mc_substring_set_t *set = sets->substring_set;
    mc_substring_set_iter_t it;
    mc_substring_set_iter_init(&it, set);
    const char *substring;

    uint32_t substring_len = 0;
    uint32_t substring_count = 0;
    uint32_t total_real_substring_count = 0;
    while (mc_substring_set_iter_next(&it, &substring, &substring_len, &substring_count)) {
        fprintf(stderr,
                "Substring starting %lld, ending %lld, count %u: \"%.*s\"\n",
                (long long)((uint8_t *)substring - sets->base_string->buf.data),
                (long long)((uint8_t *)substring - sets->base_string->buf.data + substring_len),
                substring_count,
                substring_len,
                substring);
        if (substring_len == byte_len + 1) {
            // This is padding, so there should be no more entries due to how we ordered them
            ASSERT(!mc_substring_set_iter_next(&it, NULL, NULL, NULL));
            break;
        }

        ASSERT((uint8_t *)substring + substring_len <= sets->base_string->buf.data + byte_len);
        ASSERT(substring_len <= byte_len);
        ASSERT(0 < substring_len);
        ASSERT(1 == substring_count);
        total_real_substring_count++;
    }
    ASSERT(total_real_substring_count == n_real_substrings);
    if (substring_len == byte_len + 1) {
        // Padding
        ASSERT((uint8_t *)substring == sets->base_string->buf.data);
        ASSERT(substring_count == n_padding);
    } else {
        // No padding found
        ASSERT(n_padding == 0);
    }
cleanup:
    mc_str_encode_sets_destroy(sets);
}

static void test_nofold_substring_case_multiple_mlen(_mongocrypt_tester_t *tester,
                                                     const char *str,
                                                     uint32_t lb,
                                                     uint32_t ub,
                                                     uint32_t unfolded_codepoint_len) {
    // mlen < unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len - 1, unfolded_codepoint_len);
    // mlen = unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len, unfolded_codepoint_len);
    // mlen > unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len + 1, unfolded_codepoint_len);
    // mlen >> unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len + 64, unfolded_codepoint_len);
    // mlen = cbclen
    uint32_t max_padded_len = 16 * (uint32_t)((unfolded_codepoint_len + 15) / 16);
    test_nofold_substring_case(tester, str, lb, ub, max_padded_len, unfolded_codepoint_len);
}

const uint32_t UNFOLDED_CASES[] = {0, 1, 3, 16};
const char short_string[] = "123456789";
const char medium_string[] = "0123456789abcdef";
const char long_string[] = "123456789123456789123458980";
// The unicode test strings are a mix of 1, 2, and 3-byte unicode characters.
const char short_unicode_string[] = "1二𓀀4五六❼8𓀯";
const char medium_unicode_string[] = "⓪1二𓀀4五六❼8𓀯あいうえおf";
const char long_unicode_string[] = "1二𓀀4五六❼8𓀯1二𓀀4五六𓀯1二𓀀4❼8𓀯❼8五六";
const uint32_t SHORT_LEN = sizeof(short_string) - 1;
const uint32_t MEDIUM_LEN = sizeof(medium_string) - 1;
const uint32_t LONG_LEN = sizeof(long_string) - 1;

static void test_text_search_str_encode_suffix_prefix(_mongocrypt_tester_t *tester,
                                                      const char *short_s,
                                                      const char *medium_s,
                                                      const char *long_s) {
    for (uint32_t i = 0; i < sizeof(UNFOLDED_CASES) / sizeof(UNFOLDED_CASES[0]); i++) {
        uint32_t short_unfolded_codepoint_len = SHORT_LEN + UNFOLDED_CASES[i];
        uint32_t medium_unfolded_codepoint_len = MEDIUM_LEN + UNFOLDED_CASES[i];
        uint32_t long_unfolded_codepoint_len = LONG_LEN + UNFOLDED_CASES[i];
        // LB > 16
        test_nofold_suffix_prefix_case(tester, short_s, 17, 19, short_unfolded_codepoint_len);
        // Simple cases
        test_nofold_suffix_prefix_case(tester, short_s, 2, 4, short_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, short_s, 3, 6, short_unfolded_codepoint_len);
        // LB = UB
        test_nofold_suffix_prefix_case(tester, short_s, 2, 2, short_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, short_s, 9, 9, short_unfolded_codepoint_len);
        // UB = len
        test_nofold_suffix_prefix_case(tester, short_s, 2, 9, short_unfolded_codepoint_len);
        // 16 > UB > len
        test_nofold_suffix_prefix_case(tester, short_s, 2, 14, short_unfolded_codepoint_len);
        // UB = 16
        test_nofold_suffix_prefix_case(tester, short_s, 2, 16, short_unfolded_codepoint_len);
        // UB > 16
        test_nofold_suffix_prefix_case(tester, short_s, 2, 19, short_unfolded_codepoint_len);
        // UB > 32
        test_nofold_suffix_prefix_case(tester, short_s, 2, 35, short_unfolded_codepoint_len);
        // 16 >= LB > len
        test_nofold_suffix_prefix_case(tester, short_s, 12, 19, short_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, short_s, 12, 16, short_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, short_s, 16, 19, short_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, short_s, 12, 35, short_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, short_s, 16, 35, short_unfolded_codepoint_len);

        // len = 16 cases
        // LB > 16
        test_nofold_suffix_prefix_case(tester, medium_s, 17, 19, medium_unfolded_codepoint_len);
        // Simple cases
        test_nofold_suffix_prefix_case(tester, medium_s, 2, 4, medium_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, medium_s, 3, 6, medium_unfolded_codepoint_len);
        // LB = UB
        test_nofold_suffix_prefix_case(tester, medium_s, 2, 2, medium_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, medium_s, 16, 16, medium_unfolded_codepoint_len);
        // UB = len
        test_nofold_suffix_prefix_case(tester, medium_s, 2, 16, medium_unfolded_codepoint_len);
        // UB > len
        test_nofold_suffix_prefix_case(tester, medium_s, 2, 19, medium_unfolded_codepoint_len);
        // UB = 32
        test_nofold_suffix_prefix_case(tester, medium_s, 2, 32, medium_unfolded_codepoint_len);
        // UB > 32
        test_nofold_suffix_prefix_case(tester, medium_s, 2, 35, medium_unfolded_codepoint_len);
        // LB = len
        test_nofold_suffix_prefix_case(tester, medium_s, 16, 19, medium_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, medium_s, 16, 35, medium_unfolded_codepoint_len);

        // len > 16 cases
        // LB > 32
        test_nofold_suffix_prefix_case(tester, long_s, 33, 38, long_unfolded_codepoint_len);
        // Simple cases
        test_nofold_suffix_prefix_case(tester, long_s, 2, 4, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 3, 6, long_unfolded_codepoint_len);
        // LB < 16 <= UB <= len
        test_nofold_suffix_prefix_case(tester, long_s, 3, 18, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 3, 16, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 3, 27, long_unfolded_codepoint_len);
        // 16 <= LB < UB <= len
        test_nofold_suffix_prefix_case(tester, long_s, 18, 24, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 16, 24, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 18, 27, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 16, 27, long_unfolded_codepoint_len);
        // LB = UB
        test_nofold_suffix_prefix_case(tester, long_s, 3, 3, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 16, 16, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 27, 27, long_unfolded_codepoint_len);
        // 32 > UB > len
        test_nofold_suffix_prefix_case(tester, long_s, 3, 29, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 18, 29, long_unfolded_codepoint_len);
        // UB = 32
        test_nofold_suffix_prefix_case(tester, long_s, 3, 32, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 18, 32, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 27, 32, long_unfolded_codepoint_len);
        // UB > 32
        test_nofold_suffix_prefix_case(tester, long_s, 3, 35, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 18, 35, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 27, 32, long_unfolded_codepoint_len);
        // UB > 48
        test_nofold_suffix_prefix_case(tester, long_s, 3, 49, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 18, 49, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 27, 32, long_unfolded_codepoint_len);
        // 32 >= LB > len
        test_nofold_suffix_prefix_case(tester, long_s, 28, 30, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 28, 28, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 28, 32, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 28, 34, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 28, 49, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 32, 32, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 32, 34, long_unfolded_codepoint_len);
        test_nofold_suffix_prefix_case(tester, long_s, 32, 49, long_unfolded_codepoint_len);
    }
}

static void test_text_search_str_encode_substring(_mongocrypt_tester_t *tester,
                                                  const char *short_s,
                                                  const char *medium_s,
                                                  const char *long_s) {
    for (uint32_t i = 0; i < sizeof(UNFOLDED_CASES) / sizeof(UNFOLDED_CASES[0]); i++) {
        uint32_t short_unfolded_codepoint_len = SHORT_LEN + UNFOLDED_CASES[i];
        uint32_t medium_unfolded_codepoint_len = MEDIUM_LEN + UNFOLDED_CASES[i];
        uint32_t long_unfolded_codepoint_len = LONG_LEN + UNFOLDED_CASES[i];
        // LB > 16
        test_nofold_substring_case_multiple_mlen(tester, short_s, 17, 19, short_unfolded_codepoint_len);
        // Simple cases
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 4, short_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, short_s, 3, 6, short_unfolded_codepoint_len);
        // LB = UB
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 2, short_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, short_s, 9, 9, short_unfolded_codepoint_len);
        // UB = len
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 9, short_unfolded_codepoint_len);
        // 16 > UB > len
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 14, short_unfolded_codepoint_len);
        // UB = 16
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 16, short_unfolded_codepoint_len);
        // UB > 16
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 19, short_unfolded_codepoint_len);
        // UB > 32
        test_nofold_substring_case_multiple_mlen(tester, short_s, 2, 35, short_unfolded_codepoint_len);
        // 16 >= LB > len
        test_nofold_substring_case_multiple_mlen(tester, short_s, 12, 19, short_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, short_s, 12, 16, short_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, short_s, 16, 19, short_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, short_s, 12, 35, short_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, short_s, 16, 35, short_unfolded_codepoint_len);

        // len = 16 cases
        // LB > 16
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 17, 19, medium_unfolded_codepoint_len);
        // Simple cases
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 2, 4, medium_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 3, 6, medium_unfolded_codepoint_len);
        // LB = UB
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 2, 2, medium_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 16, 16, medium_unfolded_codepoint_len);
        // UB = len
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 2, 16, medium_unfolded_codepoint_len);
        // UB > len
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 2, 19, medium_unfolded_codepoint_len);
        // UB = 32
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 2, 32, medium_unfolded_codepoint_len);
        // UB > 32
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 2, 35, medium_unfolded_codepoint_len);
        // LB = len
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 16, 19, medium_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, medium_s, 16, 35, medium_unfolded_codepoint_len);

        // len > 16 cases
        // LB > 32
        test_nofold_substring_case_multiple_mlen(tester, long_s, 33, 38, long_unfolded_codepoint_len);
        // Simple cases
        test_nofold_substring_case_multiple_mlen(tester, long_s, 2, 4, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 6, long_unfolded_codepoint_len);
        // LB < 16 <= UB <= len
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 18, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 16, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 27, long_unfolded_codepoint_len);
        // 16 <= LB < UB <= len
        test_nofold_substring_case_multiple_mlen(tester, long_s, 18, 24, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 16, 24, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 18, 27, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 16, 27, long_unfolded_codepoint_len);
        // LB = UB
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 3, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 16, 16, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 27, 27, long_unfolded_codepoint_len);
        // 32 > UB > len
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 29, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 18, 29, long_unfolded_codepoint_len);
        // UB = 32
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 32, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 18, 32, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 27, 32, long_unfolded_codepoint_len);
        // UB > 32
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 35, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 18, 35, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 27, 32, long_unfolded_codepoint_len);
        // UB > 48
        test_nofold_substring_case_multiple_mlen(tester, long_s, 3, 49, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 18, 49, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 27, 32, long_unfolded_codepoint_len);
        // 32 >= LB > len
        test_nofold_substring_case_multiple_mlen(tester, long_s, 28, 30, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 28, 28, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 28, 32, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 28, 34, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 28, 49, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 32, 32, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 32, 34, long_unfolded_codepoint_len);
        test_nofold_substring_case_multiple_mlen(tester, long_s, 32, 49, long_unfolded_codepoint_len);
    }
}

static void _test_text_search_str_encode_suffix_prefix_ascii(_mongocrypt_tester_t *tester) {
    test_text_search_str_encode_suffix_prefix(tester, short_string, medium_string, long_string);
}

static void _test_text_search_str_encode_suffix_prefix_utf8(_mongocrypt_tester_t *tester) {
    test_text_search_str_encode_suffix_prefix(tester, short_unicode_string, medium_unicode_string, long_unicode_string);
}

static void _test_text_search_str_encode_substring_ascii(_mongocrypt_tester_t *tester) {
    test_text_search_str_encode_substring(tester, short_string, medium_string, long_string);
}

static void _test_text_search_str_encode_substring_utf8(_mongocrypt_tester_t *tester) {
    test_text_search_str_encode_substring(tester, short_unicode_string, medium_unicode_string, long_unicode_string);
}

static void _test_text_search_str_encode_multiple(_mongocrypt_tester_t *tester) {
    mc_FLE2TextSearchInsertSpec_t spec =
        {"123456789", 9, {{20, 9, 9}, true}, {{1, 5}, true}, {{6, 8}, true}, false, false};
    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_str_encode_sets_t *sets = mc_text_search_str_encode(&spec, status);
    // Ensure that we ran tree generation for suffix, prefix, and substring successfully by checking the first entry of
    // each.
    const char *str;
    uint32_t len, count;

    ASSERT_OR_PRINT(sets, status);
    mongocrypt_status_destroy(status);
    ASSERT(sets->suffix_set != NULL);
    mc_affix_set_iter_t it;
    mc_affix_set_iter_init(&it, sets->suffix_set);
    ASSERT(mc_affix_set_iter_next(&it, &str, &len, &count));
    ASSERT(len == 1);
    ASSERT(*str == '9');
    ASSERT(count == 1);

    ASSERT(sets->prefix_set != NULL);
    mc_affix_set_iter_init(&it, sets->prefix_set);
    ASSERT(mc_affix_set_iter_next(&it, &str, &len, &count));
    ASSERT(len == 6);
    ASSERT(0 == memcmp("123456", str, 6));
    ASSERT(count == 1);

    ASSERT(sets->substring_set != NULL);
    mc_substring_set_iter_t ss_it;
    mc_substring_set_iter_init(&ss_it, sets->substring_set);
    ASSERT(mc_substring_set_iter_next(&ss_it, &str, &len, &count));
    ASSERT(len == 9);
    ASSERT(0 == memcmp("123456789", str, 9));
    ASSERT(count == 1);

    ASSERT(sets->exact.len == 9);
    ASSERT(0 == memcmp(sets->exact.data, str, 9));

    mc_str_encode_sets_destroy(sets);
}

static void _test_text_search_str_encode_bad_string(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_FLE2TextSearchInsertSpec_t spec =
        {"\xff\xff\xff\xff\xff\xff\xff\xff\xff", 9, {{20, 4, 7}, true}, {{1, 5}, true}, {{6, 8}, true}, false, false};
    mc_str_encode_sets_t *sets = mc_text_search_str_encode(&spec, status);
    ASSERT_FAILS_STATUS(sets, status, "not valid UTF-8");
    mc_str_encode_sets_destroy(sets);
    mongocrypt_status_destroy(status);
}

static void _test_text_search_str_encode_empty_string(_mongocrypt_tester_t *tester) {
    test_nofold_suffix_prefix_case(tester, "", 1, 1, 1);
    test_nofold_suffix_prefix_case(tester, "", 1, 2, 1);
    test_nofold_suffix_prefix_case(tester, "", 2, 3, 1);
    test_nofold_suffix_prefix_case(tester, "", 1, 16, 1);
    test_nofold_suffix_prefix_case(tester, "", 1, 17, 1);
    test_nofold_suffix_prefix_case(tester, "", 2, 16, 1);
    test_nofold_suffix_prefix_case(tester, "", 2, 17, 1);

    test_nofold_substring_case_multiple_mlen(tester, "", 1, 1, 1);
    test_nofold_substring_case_multiple_mlen(tester, "", 1, 2, 1);
    test_nofold_substring_case_multiple_mlen(tester, "", 2, 3, 1);
    test_nofold_substring_case_multiple_mlen(tester, "", 1, 16, 1);
    test_nofold_substring_case_multiple_mlen(tester, "", 1, 17, 1);
    test_nofold_substring_case_multiple_mlen(tester, "", 2, 16, 1);
    test_nofold_substring_case_multiple_mlen(tester, "", 2, 17, 1);
}

void _mongocrypt_tester_install_text_search_str_encode(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_text_search_str_encode_suffix_prefix_ascii);
    INSTALL_TEST(_test_text_search_str_encode_suffix_prefix_utf8);
    INSTALL_TEST(_test_text_search_str_encode_substring_ascii);
    INSTALL_TEST(_test_text_search_str_encode_substring_utf8);
    INSTALL_TEST(_test_text_search_str_encode_multiple);
    INSTALL_TEST(_test_text_search_str_encode_bad_string);
    INSTALL_TEST(_test_text_search_str_encode_empty_string);
}
