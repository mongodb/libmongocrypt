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
#include "mc-text-search-str-encode-private.h"
#include <stdint.h>
#include <string.h>

#undef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// TODO MONGOCRYPT-759 Modify these tests not to take unfolded_len, but to instead take strings with diacritics and fold
// them
static void test_nofold_suffix_prefix_case(_mongocrypt_tester_t *tester,
                                           const char *str,
                                           uint32_t lb,
                                           uint32_t ub,
                                           uint32_t unfolded_len) {
    fprintf(stderr,
            "Testing nofold suffix/prefix case: str=\"%s\", lb=%u, ub=%u, unfolded_len=%u\n",
            str,
            lb,
            ub,
            unfolded_len);
    uint32_t len = strlen(str);
    uint32_t max_padded_len = 16 * (uint32_t)((unfolded_len + 15) / 16);
    uint32_t max_affix_len = MIN(ub, len);
    uint32_t n_real_affixes = max_affix_len >= lb ? max_affix_len - lb + 1 : 0;
    uint32_t n_affixes = MIN(ub, max_padded_len) - lb + 1;
    uint32_t n_padding = n_affixes - n_real_affixes;

    mc_str_encode_sets_t sets;
    for (int suffix = 0; suffix <= 1; suffix++) {
        if (suffix) {
            mc_FLE2TextSearchInsertSpec_t spec =
                {str, len, {{0, 0, 0}, false}, {{lb, ub}, true}, {{0, 0}, false}, false, false};
            sets = mc_text_search_str_encode_helper(&spec, unfolded_len);
        } else {
            mc_FLE2TextSearchInsertSpec_t spec =
                {str, len, {{0, 0, 0}, false}, {{0, 0}, false}, {{lb, ub}, true}, false, false};
            sets = mc_text_search_str_encode_helper(&spec, unfolded_len);
        }
        ASSERT(sets.base_len == len + 1);
        ASSERT(0 == memcmp(sets.base_string, str, len));
        ASSERT(sets.base_string[len] == (char)0xFF);
        ASSERT(sets.substring_set == NULL);
        ASSERT(sets.exact_len == len);
        ASSERT(0 == memcmp(sets.exact, str, len));

        if (lb > max_padded_len) {
            ASSERT(sets.suffix_set == NULL);
            ASSERT(sets.prefix_set == NULL);
            goto CONTINUE;
        }

        fprintf(stderr,
                "Expecting: n_real_affixes: %u, n_affixes: %u, n_padding: %u\n",
                n_real_affixes,
                n_affixes,
                n_padding);

        mc_substring_set_t *set;
        if (suffix) {
            ASSERT(sets.prefix_set == NULL);
            set = sets.suffix_set;
        } else {
            ASSERT(sets.suffix_set == NULL);
            set = sets.prefix_set;
        }
        ASSERT(set != NULL);

        mc_substring_set_iter_t it;
        mc_substring_set_iter_init(&it, set);
        const char *affix;

        uint32_t lastlen = lb - 1;
        uint32_t affix_len = 0;
        uint32_t affix_count = 0;
        uint32_t total_real_affix_count = 0;
        while (mc_substring_set_iter_next(&it, &affix, &affix_len, &affix_count)) {
            // Since all substrings are just views on the base string, we can use pointer math to find our start and
            // indices.
            fprintf(stderr,
                    "Affix starting %lu, ending %lu, count %u\n",
                    affix - sets.base_string,
                    affix - sets.base_string + affix_len,
                    affix_count);
            if (affix_len == len + 1) {
                // This is padding, so there should be no more entries due to how we ordered them
                ASSERT(!mc_substring_set_iter_next(&it, NULL, NULL, NULL));
                break;
            }

            ASSERT(affix_len <= MIN(len, ub));
            ASSERT(lb <= affix_len);
            // We happen to always order from smallest to largest in the suffix/prefix algorithm, which makes our life
            // slightly easier when testing.
            ASSERT(affix_len == lastlen + 1);
            lastlen = affix_len;
            if (suffix) {
                ASSERT(0 == memcmp(affix, str + len - affix_len, affix_len));
            } else {
                ASSERT(0 == memcmp(affix, str, affix_len));
            }
            // The count should always be 1, except for padding.
            ASSERT(1 == affix_count);
            total_real_affix_count++;
        }
        ASSERT(total_real_affix_count == n_real_affixes);
        if (affix_len == len + 1) {
            // Padding
            ASSERT(affix == sets.base_string);
            ASSERT(affix_count == n_padding);
        } else {
            // No padding found
            ASSERT(n_padding == 0)
        }
    CONTINUE:
        mc_str_encode_sets_destroy(&sets);
    }
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

static void test_nofold_substring_case(_mongocrypt_tester_t *tester,
                                       const char *str,
                                       uint32_t lb,
                                       uint32_t ub,
                                       uint32_t mlen,
                                       uint32_t unfolded_len) {
    fprintf(stderr,
            "Testing nofold substring case: str=\"%s\", lb=%u, ub=%u, mlen=%u, unfolded_len=%u\n",
            str,
            lb,
            ub,
            mlen,
            unfolded_len);
    uint32_t len = strlen(str);
    uint32_t max_padded_len = 16 * (uint32_t)((unfolded_len + 15) / 16);
    uint32_t n_real_substrings = calc_number_of_substrings(len, lb, ub);
    uint32_t n_substrings = calc_number_of_substrings(MIN(max_padded_len, mlen), lb, ub);
    uint32_t n_padding = n_substrings - n_real_substrings;

    mc_str_encode_sets_t sets;
    mc_FLE2TextSearchInsertSpec_t spec =
        {str, len, {{mlen, lb, ub}, true}, {{0, 0}, false}, {{0, 0}, false}, false, false};
    sets = mc_text_search_str_encode_helper(&spec, unfolded_len);

    ASSERT(sets.base_len == len + 1);
    ASSERT(0 == memcmp(sets.base_string, str, len));
    ASSERT(sets.base_string[len] == (char)0xFF);
    ASSERT(sets.suffix_set == NULL)
    ASSERT(sets.prefix_set == NULL);
    ASSERT(sets.exact_len == len);
    ASSERT(0 == memcmp(sets.exact, str, len));

    if (unfolded_len > mlen || lb > max_padded_len) {
        ASSERT(sets.substring_set == NULL);
        return;
    } else {
        ASSERT(sets.substring_set != NULL);
    }

    fprintf(stderr,
            "Expecting: n_real_substrings: %u, n_substrings: %u, n_padding: %u\n",
            n_real_substrings,
            n_substrings,
            n_padding);

    mc_substring_set_t *set = sets.substring_set;
    mc_substring_set_iter_t it;
    mc_substring_set_iter_init(&it, set);
    const char *substring;
    // 2D array: counts[i + j*len] is the number of substrings returned which started at index i
    // of the base string and were of length (j + lb).
    uint32_t *counts = calloc(len * (ub - lb + 1), sizeof(uint32_t));

    uint32_t substring_len = 0;
    uint32_t substring_count = 0;
    uint32_t total_real_substring_count = 0;
    while (mc_substring_set_iter_next(&it, &substring, &substring_len, &substring_count)) {
        fprintf(stderr,
                "Substring starting %lu, ending %lu, count %u\n",
                substring - sets.base_string,
                substring - sets.base_string + substring_len,
                substring_count);
        if (substring_len == len + 1) {
            // This is padding, so there should be no more entries due to how we ordered them
            ASSERT(!mc_substring_set_iter_next(&it, NULL, NULL, NULL));
            break;
        }

        ASSERT(substring + substring_len <= sets.base_string + len);
        ASSERT(substring_len <= MIN(len, ub));
        ASSERT(lb <= substring_len);
        ASSERT(1 == substring_count);
        total_real_substring_count++;

        counts[substring - sets.base_string + (substring_len - lb) * len]++;
    }
    ASSERT(total_real_substring_count == n_real_substrings);
    if (substring_len == len + 1) {
        // Padding
        ASSERT(substring == sets.base_string);
        ASSERT(substring_count == n_padding);
    } else {
        // No padding found
        ASSERT(n_padding == 0)
    }
    for (uint32_t i = 0; i < len; i++) {
        for (uint32_t j = 0; j < ub - lb + 1; j++) {
            // We expect to find one substring if the end index, i + (j + lb),
            // would be within range of the folded string, otherwise 0.
            uint32_t expected_count = i + j + lb <= len ? 1 : 0;
            ASSERT(counts[i + j * len] == expected_count);
        }
    }
    free(counts);
    mc_str_encode_sets_destroy(&sets);
}

static void test_nofold_substring_case_multiple_mlen(_mongocrypt_tester_t *tester,
                                                     const char *str,
                                                     uint32_t lb,
                                                     uint32_t ub,
                                                     uint32_t unfolded_len) {
    // mlen < unfolded_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_len - 1, unfolded_len);
    // mlen = unfolded_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_len, unfolded_len);
    // mlen > unfolded_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_len + 1, unfolded_len);
    // mlen >> unfolded_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_len + 64, unfolded_len);
    // mlen = cbclen
    uint32_t max_padded_len = 16 * (uint32_t)((unfolded_len + 15) / 16);
    test_nofold_substring_case(tester, str, lb, ub, max_padded_len, unfolded_len);
}

const uint32_t UNFOLDED_CASES[] = {0, 1, 3, 16};
const char TEST_STRING_SHORT[] = "123456789";
const char TEST_STRING_MEDIUM[] = "0123456789abcdef";
const char TEST_STRING_LONG[] = "123456789123456789123456789";

static void _test_text_search_str_encode_suffix_prefix(_mongocrypt_tester_t *tester) {
    for (uint32_t i = 0; i < sizeof(UNFOLDED_CASES) / sizeof(UNFOLDED_CASES[0]); i++) {
        uint32_t short_unfolded_len = sizeof(TEST_STRING_SHORT) - 1 + UNFOLDED_CASES[i];
        uint32_t medium_unfolded_len = sizeof(TEST_STRING_MEDIUM) - 1 + UNFOLDED_CASES[i];
        uint32_t long_unfolded_len = sizeof(TEST_STRING_LONG) - 1 + UNFOLDED_CASES[i];
        // LB > 16
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 17, 19, short_unfolded_len);
        // Simple cases
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 4, short_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 3, 6, short_unfolded_len);
        // LB = UB
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 2, short_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 9, 9, short_unfolded_len);
        // UB = len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 9, short_unfolded_len);
        // 16 > UB > len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 14, short_unfolded_len);
        // UB = 16
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 16, short_unfolded_len);
        // UB > 16
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 19, short_unfolded_len);
        // UB > 32
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 2, 35, short_unfolded_len);
        // 16 >= LB > len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 12, 19, short_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 12, 16, short_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 16, 19, short_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 12, 35, short_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_SHORT, 16, 35, short_unfolded_len);

        // len = 16 cases
        // LB > 16
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 17, 19, medium_unfolded_len);
        // Simple cases
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 2, 4, medium_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 3, 6, medium_unfolded_len);
        // LB = UB
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 2, 2, medium_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 16, 16, medium_unfolded_len);
        // UB = len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 2, 16, medium_unfolded_len);
        // UB > len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 2, 19, medium_unfolded_len);
        // UB = 32
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 2, 32, medium_unfolded_len);
        // UB > 32
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 2, 35, medium_unfolded_len);
        // LB = len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 16, 19, medium_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_MEDIUM, 16, 35, medium_unfolded_len);

        // len > 16 cases
        // LB > 32
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 33, 38, long_unfolded_len);
        // Simple cases
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 2, 4, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 6, long_unfolded_len);
        // LB < 16 <= UB <= len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 18, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 16, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 27, long_unfolded_len);
        // 16 <= LB < UB <= len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 18, 24, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 16, 24, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 18, 27, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 16, 27, long_unfolded_len);
        // LB = UB
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 3, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 16, 16, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 27, 27, long_unfolded_len);
        // 32 > UB > len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 29, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 18, 29, long_unfolded_len);
        // UB = 32
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 32, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 18, 32, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 27, 32, long_unfolded_len);
        // UB > 32
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 35, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 18, 35, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 27, 32, long_unfolded_len);
        // UB > 48
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 3, 49, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 18, 49, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 27, 32, long_unfolded_len);
        // 32 >= LB > len
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 28, 30, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 28, 28, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 28, 32, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 28, 34, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 28, 49, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 32, 32, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 32, 34, long_unfolded_len);
        test_nofold_suffix_prefix_case(tester, TEST_STRING_LONG, 32, 49, long_unfolded_len);
    }
}

static void _test_text_search_str_encode_substring(_mongocrypt_tester_t *tester) {
    for (uint32_t i = 0; i < sizeof(UNFOLDED_CASES) / sizeof(UNFOLDED_CASES[0]); i++) {
        uint32_t short_unfolded_len = sizeof(TEST_STRING_SHORT) - 1 + UNFOLDED_CASES[i];
        uint32_t medium_unfolded_len = sizeof(TEST_STRING_MEDIUM) - 1 + UNFOLDED_CASES[i];
        uint32_t long_unfolded_len = sizeof(TEST_STRING_LONG) - 1 + UNFOLDED_CASES[i];
        // LB > 16
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 17, 19, short_unfolded_len);
        // Simple cases
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 4, short_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 3, 6, short_unfolded_len);
        // LB = UB
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 2, short_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 9, 9, short_unfolded_len);
        // UB = len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 9, short_unfolded_len);
        // 16 > UB > len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 14, short_unfolded_len);
        // UB = 16
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 16, short_unfolded_len);
        // UB > 16
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 19, short_unfolded_len);
        // UB > 32
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 2, 35, short_unfolded_len);
        // 16 >= LB > len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 12, 19, short_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 12, 16, short_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 16, 19, short_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 12, 35, short_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_SHORT, 16, 35, short_unfolded_len);

        // len = 16 cases
        // LB > 16
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 17, 19, medium_unfolded_len);
        // Simple cases
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 2, 4, medium_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 3, 6, medium_unfolded_len);
        // LB = UB
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 2, 2, medium_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 16, 16, medium_unfolded_len);
        // UB = len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 2, 16, medium_unfolded_len);
        // UB > len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 2, 19, medium_unfolded_len);
        // UB = 32
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 2, 32, medium_unfolded_len);
        // UB > 32
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 2, 35, medium_unfolded_len);
        // LB = len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 16, 19, medium_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_MEDIUM, 16, 35, medium_unfolded_len);

        // len > 16 cases
        // LB > 32
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 33, 38, long_unfolded_len);
        // Simple cases
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 2, 4, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 6, long_unfolded_len);
        // LB < 16 <= UB <= len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 18, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 16, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 27, long_unfolded_len);
        // 16 <= LB < UB <= len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 18, 24, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 16, 24, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 18, 27, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 16, 27, long_unfolded_len);
        // LB = UB
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 3, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 16, 16, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 27, 27, long_unfolded_len);
        // 32 > UB > len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 29, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 18, 29, long_unfolded_len);
        // UB = 32
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 32, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 18, 32, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 27, 32, long_unfolded_len);
        // UB > 32
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 35, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 18, 35, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 27, 32, long_unfolded_len);
        // UB > 48
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 3, 49, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 18, 49, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 27, 32, long_unfolded_len);
        // 32 >= LB > len
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 28, 30, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 28, 28, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 28, 32, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 28, 34, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 28, 49, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 32, 32, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 32, 34, long_unfolded_len);
        test_nofold_substring_case_multiple_mlen(tester, TEST_STRING_LONG, 32, 49, long_unfolded_len);
    }
}

void _test_text_search_str_encode_multiple(_mongocrypt_tester_t *tester) {
    mc_FLE2TextSearchInsertSpec_t spec =
        {"123456789", 9, {{20, 4, 7}, true}, {{1, 5}, true}, {{6, 8}, true}, false, false};
    mc_str_encode_sets_t sets = mc_text_search_str_encode(&spec);
    // Ensure that we ran tree generation for suffix, prefix, and substring successfully by checking the first entry of
    // each.
    const char *str;
    uint32_t len, count;

    ASSERT(sets.suffix_set != NULL);
    mc_substring_set_iter_t it;
    mc_substring_set_iter_init(&it, sets.suffix_set);
    ASSERT(mc_substring_set_iter_next(&it, &str, &len, &count));
    ASSERT(len == 1);
    ASSERT(*str == '9');
    ASSERT(count == 1);

    ASSERT(sets.prefix_set != NULL);
    mc_substring_set_iter_init(&it, sets.prefix_set);
    ASSERT(mc_substring_set_iter_next(&it, &str, &len, &count));
    ASSERT(len == 6);
    ASSERT(0 == memcmp("123456", str, 6));
    ASSERT(count == 1);

    ASSERT(sets.substring_set != NULL);
    mc_substring_set_iter_init(&it, sets.substring_set);
    ASSERT(mc_substring_set_iter_next(&it, &str, &len, &count));
    ASSERT(len == 4);
    ASSERT(0 == memcmp("1234", str, 4));
    ASSERT(count == 1);

    ASSERT(sets.exact_len == 9);
    ASSERT(0 == memcmp(sets.exact, str, 9));

    mc_str_encode_sets_destroy(&sets);
}

void _mongocrypt_tester_install_text_search_str_encode(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_text_search_str_encode_suffix_prefix);
    INSTALL_TEST(_test_text_search_str_encode_substring);
    INSTALL_TEST(_test_text_search_str_encode_multiple);
}
