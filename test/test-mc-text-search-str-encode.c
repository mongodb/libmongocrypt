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
#include "unicode/fold.h"
#include <stdint.h>
#include <string.h>

static uint32_t get_utf8_codepoint_length(const char *buf, uint32_t len) {
    const char *cur = buf;
    const char *end = buf + len;
    uint32_t codepoint_len = 0;
    while (cur < end) {
        cur = bson_utf8_next_char(cur);
        codepoint_len++;
    }
    return codepoint_len;
}

static void test_nofold_suffix_prefix_case(_mongocrypt_tester_t *tester,
                                           const char *str,
                                           uint32_t lb,
                                           uint32_t ub,
                                           bool casef,
                                           bool diacf,
                                           int foldable_codepoints) {
    TEST_PRINTF("Testing nofold suffix/prefix case: str=\"%s\", lb=%u, ub=%u, casef=%d, diacf=%d\n",
                str,
                lb,
                ub,
                casef,
                diacf);
    uint32_t byte_len = (uint32_t)strlen(str);
    uint32_t unfolded_codepoint_len = byte_len == 0 ? 1 : get_utf8_codepoint_length(str, byte_len);
    uint32_t folded_codepoint_len = byte_len == 0 ? 0 : unfolded_codepoint_len - foldable_codepoints;
    uint32_t padded_len = 16 * (uint32_t)((byte_len + 5 + 15) / 16) - 5;
    uint32_t max_affix_len = BSON_MIN(ub, folded_codepoint_len);
    uint32_t n_real_affixes = max_affix_len >= lb ? max_affix_len - lb + 1 : 0;
    uint32_t n_affixes = BSON_MIN(ub, padded_len) - lb + 1;
    uint32_t n_padding = n_affixes - n_real_affixes;

    mc_str_encode_sets_t *sets;
    mongocrypt_status_t *status = mongocrypt_status_new();
    for (int suffix = 0; suffix <= 1; suffix++) {
        if (suffix) {
            mc_FLE2TextSearchInsertSpec_t spec = {.v = str,
                                                  .len = byte_len,
                                                  .suffix = {{lb, ub}, true},
                                                  .casef = casef,
                                                  .diacf = diacf};
            sets = mc_text_search_str_encode(&spec, status);
        } else {
            mc_FLE2TextSearchInsertSpec_t spec = {.v = str,
                                                  .len = byte_len,
                                                  .prefix = {{lb, ub}, true},
                                                  .casef = casef,
                                                  .diacf = diacf};
            sets = mc_text_search_str_encode(&spec, status);
        }
        ASSERT_OR_PRINT(sets, status);
        ASSERT_CMPUINT32(sets->base_string->codepoint_len, ==, folded_codepoint_len + 1);
        if (!casef && !diacf) {
            ASSERT_CMPUINT32(sets->base_string->buf.len, ==, byte_len + 1);
            ASSERT_CMPINT(0, ==, memcmp(sets->base_string->buf.data, str, byte_len));
        }
        ASSERT_CMPUINT8(sets->base_string->buf.data[sets->base_string->buf.len - 1], ==, (uint8_t)0xFF);
        ASSERT(sets->substring_set == NULL);
        ASSERT_CMPUINT32(sets->exact.len, ==, sets->base_string->buf.len - 1);
        ASSERT_CMPINT(0, ==, memcmp(sets->exact.data, sets->base_string->buf.data, sets->exact.len));

        if (lb > padded_len) {
            ASSERT(sets->suffix_set == NULL);
            ASSERT(sets->prefix_set == NULL);
            goto CONTINUE;
        }

        TEST_PRINTF("Expecting: n_real_affixes: %u, n_affixes: %u, n_padding: %u\n",
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
            // end indices.
            TEST_PRINTF("Affix starting %lld, ending %lld, count %u\n",
                        (long long)((uint8_t *)affix - sets->base_string->buf.data),
                        (long long)((uint8_t *)affix - sets->base_string->buf.data + affix_len),
                        affix_count);
            if (affix_len == sets->base_string->buf.len) {
                // This is padding, so there should be no more entries due to how we ordered them
                ASSERT(!mc_affix_set_iter_next(&it, NULL, NULL, NULL));
                break;
            }

            ASSERT_CMPUINT32(affix_len, <=, sets->base_string->buf.len - 1);
            ASSERT_CMPUINT32(0, <, affix_len);

            // We happen to always order from smallest to largest in the suffix/prefix algorithm, which makes our
            // life slightly easier when testing.
            if (suffix) {
                uint32_t start_offset = sets->base_string->codepoint_offsets[folded_codepoint_len - (lb + idx)];
                ASSERT_CMPPTR((uint8_t *)affix, ==, sets->base_string->buf.data + start_offset);
                ASSERT_CMPUINT32(affix_len,
                                 ==,
                                 sets->base_string->codepoint_offsets[folded_codepoint_len] - start_offset)
            } else {
                uint32_t end_offset = sets->base_string->codepoint_offsets[lb + idx];
                ASSERT_CMPPTR((uint8_t *)affix, ==, sets->base_string->buf.data);
                ASSERT_CMPUINT32(affix_len, ==, end_offset);
            }
            // The count should always be 1, except for padding.
            ASSERT_CMPUINT32(1, ==, affix_count);
            total_real_affix_count++;
            idx++;
        }
        ASSERT_CMPUINT32(total_real_affix_count, ==, n_real_affixes);
        if (affix_len == sets->base_string->buf.len) {
            // Padding
            ASSERT_CMPPTR((uint8_t *)affix, ==, sets->base_string->buf.data);
            ASSERT_CMPUINT32(affix_count, ==, n_padding);
        } else {
            // No padding found
            ASSERT_CMPUINT32(n_padding, ==, 0);
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
        uint32_t max_sublen = BSON_MIN(ub, len - i);
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
                                       bool casef,
                                       bool diacf,
                                       int foldable_codepoints) {
    TEST_PRINTF("Testing nofold substring case: str=\"%s\", lb=%u, ub=%u, mlen=%u, casef=%d, diacf=%d\n",
                str,
                lb,
                ub,
                mlen,
                casef,
                diacf);
    uint32_t byte_len = (uint32_t)strlen(str);
    uint32_t unfolded_codepoint_len = byte_len == 0 ? 1 : get_utf8_codepoint_length(str, byte_len);
    uint32_t folded_codepoint_len = byte_len == 0 ? 0 : unfolded_codepoint_len - foldable_codepoints;
    uint32_t padded_len = 16 * (uint32_t)((byte_len + 5 + 15) / 16) - 5;
    uint32_t n_substrings = calc_number_of_substrings(BSON_MIN(padded_len, mlen), lb, ub);

    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_str_encode_sets_t *sets;
    mc_FLE2TextSearchInsertSpec_t spec = {.v = str,
                                          .len = byte_len,
                                          .substr = {{mlen, lb, ub}, true},
                                          .casef = casef,
                                          .diacf = diacf};
    sets = mc_text_search_str_encode(&spec, status);
    if (unfolded_codepoint_len > mlen) {
        ASSERT_FAILS_STATUS(sets, status, "longer than the maximum length");
        mongocrypt_status_destroy(status);
        return;
    }
    ASSERT_OR_PRINT(sets, status);
    mongocrypt_status_destroy(status);
    ASSERT_CMPUINT32(sets->base_string->codepoint_len, ==, folded_codepoint_len + 1);
    if (!casef && !diacf) {
        ASSERT_CMPUINT32(sets->base_string->buf.len, ==, byte_len + 1);
        ASSERT_CMPINT(0, ==, memcmp(sets->base_string->buf.data, str, byte_len));
    }

    ASSERT_CMPUINT8(sets->base_string->buf.data[sets->base_string->buf.len - 1], ==, (uint8_t)0xFF);
    ASSERT(sets->suffix_set == NULL);
    ASSERT(sets->prefix_set == NULL);
    ASSERT_CMPUINT32(sets->exact.len, ==, sets->base_string->buf.len - 1);
    ASSERT_CMPINT(0, ==, memcmp(sets->exact.data, sets->base_string->buf.data, sets->base_string->buf.len - 1));

    if (lb > padded_len) {
        ASSERT(sets->substring_set == NULL);
        goto cleanup;
    } else {
        ASSERT(sets->substring_set != NULL);
    }

    uint32_t n_real_substrings = calc_unique_substrings(sets->base_string, lb, ub);
    uint32_t n_padding = n_substrings - n_real_substrings;

    TEST_PRINTF("Expecting: n_real_substrings: %u, n_substrings: %u, n_padding: %u\n",
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
        TEST_PRINTF("Substring starting %lld, ending %lld, count %u: \"%.*s\"\n",
                    (long long)((uint8_t *)substring - sets->base_string->buf.data),
                    (long long)((uint8_t *)substring - sets->base_string->buf.data + substring_len),
                    substring_count,
                    substring_len,
                    substring);
        if (substring_len == sets->base_string->buf.len) {
            // This is padding, so there should be no more entries due to how we ordered them
            ASSERT(!mc_substring_set_iter_next(&it, NULL, NULL, NULL));
            break;
        }

        ASSERT_CMPPTR((uint8_t *)substring + substring_len,
                      <=,
                      sets->base_string->buf.data + sets->base_string->buf.len);
        ASSERT_CMPUINT32(substring_len, <=, sets->base_string->buf.len - 1);
        ASSERT_CMPUINT32(0, <, substring_len);
        ASSERT_CMPUINT32(1, ==, substring_count);
        total_real_substring_count++;
    }
    ASSERT_CMPUINT32(total_real_substring_count, ==, n_real_substrings);
    if (substring_len == sets->base_string->buf.len) {
        // Padding
        ASSERT_CMPPTR((uint8_t *)substring, ==, sets->base_string->buf.data);
        ASSERT_CMPUINT32(substring_count, ==, n_padding);
    } else {
        // No padding found
        ASSERT_CMPUINT32(n_padding, ==, 0);
    }
cleanup:
    mc_str_encode_sets_destroy(sets);
}

static void test_nofold_substring_case_multiple_mlen(_mongocrypt_tester_t *tester,
                                                     const char *str,
                                                     uint32_t lb,
                                                     uint32_t ub,
                                                     uint32_t unfolded_codepoint_len,
                                                     bool casef,
                                                     bool diacf,
                                                     int foldable_codepoints) {
    if (unfolded_codepoint_len > 1) {
        // mlen < unfolded_codepoint_len
        test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len - 1, casef, diacf, foldable_codepoints);
    }
    // mlen = unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len, casef, diacf, foldable_codepoints);
    // mlen > unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len + 1, casef, diacf, foldable_codepoints);
    // mlen >> unfolded_codepoint_len
    test_nofold_substring_case(tester, str, lb, ub, unfolded_codepoint_len + 64, casef, diacf, foldable_codepoints);

    uint32_t byte_len = (uint32_t)strlen(str);
    if (byte_len > 1) {
        // mlen < byte_len
        test_nofold_substring_case(tester, str, lb, ub, byte_len - 1, casef, diacf, foldable_codepoints);
    }
    if (byte_len > 0) {
        // mlen = byte_len
        test_nofold_substring_case(tester, str, lb, ub, byte_len, casef, diacf, foldable_codepoints);
    }
    // mlen > byte_len
    test_nofold_substring_case(tester, str, lb, ub, byte_len + 1, casef, diacf, foldable_codepoints);
    // mlen = padded_len
    test_nofold_substring_case(tester,
                               str,
                               lb,
                               ub,
                               16 * (uint32_t)((byte_len + 5 + 15) / 16) - 5,
                               casef,
                               diacf,
                               foldable_codepoints);
    // mlen >> byte_len
    test_nofold_substring_case(tester, str, lb, ub, byte_len + 64, casef, diacf, foldable_codepoints);
}

const char *normal_ascii_strings[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
                                      "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
                                      "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
                                      "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};
const char *ascii_diacritics[] = {"^", "`"};
const char *normal_unicode_strings[] = {"ぁ", "あ", "ぃ", "い", "ぅ", "う", "ぇ", "え", "ぉ", "お", "か", "が",
                                        "き", "ぎ", "く", "け", "Ѐ",  "Ё",  "Ђ",  "Ѓ",  "Є",  "Ѕ",  "І",  "Ї",
                                        "Ј",  "Љ",  "Њ",  "Ћ",  "Ќ",  "Ѝ",  "Ў",  "Џ",  "𓀀",  "𓀁",  "𓀂",  "𓀃",
                                        "𓀄",  "𓀅",  "𓀆",  "𓀇",  "𓀈",  "𓀉",  "𓀊",  "𓀋",  "𓀌",  "𓀍",  "𓀎",  "𓀏"};
const char *unicode_diacritics[] = {"̀", "́", "̂", "̃", "̄", "̅",  "̆",  "̇",  "̈",  "̉",  "̊",  "̋",  "̌",  "̍", "̎",
                                    "̏", "᷄", "᷅", "᷆", "᷇", "᷈",  "᷉",  "᷊",  "᷋",  "᷌",  "᷍",  "᷎",  "᷏",  "︠", "︡",
                                    "︢", "︣", "︤", "︥", "︦", "︧", "︨", "︩", "︪", "︫", "︬", "︭", "︮", "︯"};

// Build a random string which has unfolded_len codepoints, but folds to folded_len codepoints after diacritic folding.
char *build_random_string_to_fold(uint32_t folded_len, uint32_t unfolded_len) {
    // 1/3 to generate all unicode, 1/3 to be half and half, 1/3 to be all ascii.
    int ascii_ratio = rand() % 3;
    ASSERT_CMPUINT32(unfolded_len, >=, folded_len);
    // Max size in bytes is # unicode characters * 4 bytes for each character + 1 null terminator.
    char *str = malloc(unfolded_len * 4 + 1);
    char *ptr = str;
    uint32_t folded_size = 0;
    uint32_t diacritics = unfolded_len - folded_len;
    int dia_prob = (diacritics * 1000) / unfolded_len;
    for (uint32_t n_codepoints = 0; n_codepoints < unfolded_len; n_codepoints++) {
        const char *src_ptr;
        bool must_add_diacritic = folded_size == folded_len;
        bool must_add_normal = n_codepoints - folded_size == diacritics;
        if (must_add_diacritic || (!must_add_normal && (rand() % 1000 < dia_prob))) {
            // Add diacritic.
            if (rand() % 2 < ascii_ratio) {
                int i = rand() % (sizeof(ascii_diacritics) / sizeof(char *));
                src_ptr = ascii_diacritics[i];
            } else {
                int i = rand() % (sizeof(unicode_diacritics) / sizeof(char *));
                src_ptr = unicode_diacritics[i];
            }
        } else {
            // Add normal character.
            if (rand() % 2 < ascii_ratio) {
                int i = rand() % (sizeof(normal_ascii_strings) / sizeof(char *));
                src_ptr = normal_ascii_strings[i];
            } else {
                int i = rand() % (sizeof(normal_unicode_strings) / sizeof(char *));
                src_ptr = normal_unicode_strings[i];
            }
            folded_size++;
        }
        strcpy(ptr, src_ptr);
        ptr += strlen(src_ptr);
    }

    uint32_t len = (uint32_t)(ptr - str);
    // ptr points to the final null character, include that in the final string.
    str = realloc(str, len + 1);

    // Make sure we did everything right.
    ASSERT_CMPUINT32(unfolded_len, ==, get_utf8_codepoint_length(str, len));
    mongocrypt_status_t *status = mongocrypt_status_new();
    char *out_str;
    size_t out_len;
    ASSERT_OK_STATUS(unicode_fold(str, len, kUnicodeFoldRemoveDiacritics, &out_str, &out_len, status), status);
    ASSERT_CMPUINT32(folded_len, ==, get_utf8_codepoint_length(out_str, (uint32_t)out_len));
    bson_free(out_str);
    mongocrypt_status_destroy(status);
    return str;
}

static void suffix_prefix_run_folding_case(_mongocrypt_tester_t *tester,
                                           const char *short_s,
                                           const char *medium_s,
                                           const char *long_s,
                                           bool casef,
                                           bool diacf,
                                           int foldable_codepoints) {
    // LB > 16
    test_nofold_suffix_prefix_case(tester, short_s, 17, 19, casef, diacf, foldable_codepoints);
    // Simple cases
    test_nofold_suffix_prefix_case(tester, short_s, 2, 4, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, short_s, 3, 6, casef, diacf, foldable_codepoints);
    // LB = UB
    test_nofold_suffix_prefix_case(tester, short_s, 2, 2, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, short_s, 9, 9, casef, diacf, foldable_codepoints);
    // UB = len
    test_nofold_suffix_prefix_case(tester, short_s, 2, 9, casef, diacf, foldable_codepoints);
    // 16 > UB > len
    test_nofold_suffix_prefix_case(tester, short_s, 2, 14, casef, diacf, foldable_codepoints);
    // UB = 16
    test_nofold_suffix_prefix_case(tester, short_s, 2, 16, casef, diacf, foldable_codepoints);
    // UB > 16
    test_nofold_suffix_prefix_case(tester, short_s, 2, 19, casef, diacf, foldable_codepoints);
    // UB > 32
    test_nofold_suffix_prefix_case(tester, short_s, 2, 35, casef, diacf, foldable_codepoints);
    // 16 >= LB > len
    test_nofold_suffix_prefix_case(tester, short_s, 12, 19, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, short_s, 12, 16, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, short_s, 16, 19, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, short_s, 12, 35, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, short_s, 16, 35, casef, diacf, foldable_codepoints);

    // len = 16 cases
    // LB > 16
    test_nofold_suffix_prefix_case(tester, medium_s, 17, 19, casef, diacf, foldable_codepoints);
    // Simple cases
    test_nofold_suffix_prefix_case(tester, medium_s, 2, 4, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, medium_s, 3, 6, casef, diacf, foldable_codepoints);
    // LB = UB
    test_nofold_suffix_prefix_case(tester, medium_s, 2, 2, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, medium_s, 16, 16, casef, diacf, foldable_codepoints);
    // UB = len
    test_nofold_suffix_prefix_case(tester, medium_s, 2, 16, casef, diacf, foldable_codepoints);
    // UB > len
    test_nofold_suffix_prefix_case(tester, medium_s, 2, 19, casef, diacf, foldable_codepoints);
    // UB = 32
    test_nofold_suffix_prefix_case(tester, medium_s, 2, 32, casef, diacf, foldable_codepoints);
    // UB > 32
    test_nofold_suffix_prefix_case(tester, medium_s, 2, 35, casef, diacf, foldable_codepoints);
    // LB = len
    test_nofold_suffix_prefix_case(tester, medium_s, 16, 19, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, medium_s, 16, 35, casef, diacf, foldable_codepoints);

    // len > 16 cases
    // LB > 32
    test_nofold_suffix_prefix_case(tester, long_s, 33, 38, casef, diacf, foldable_codepoints);
    // Simple cases
    test_nofold_suffix_prefix_case(tester, long_s, 2, 4, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 3, 6, casef, diacf, foldable_codepoints);
    // LB < 16 <= UB <= len
    test_nofold_suffix_prefix_case(tester, long_s, 3, 18, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 3, 16, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 3, 27, casef, diacf, foldable_codepoints);
    // 16 <= LB < UB <= len
    test_nofold_suffix_prefix_case(tester, long_s, 18, 24, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 16, 24, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 18, 27, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 16, 27, casef, diacf, foldable_codepoints);
    // LB = UB
    test_nofold_suffix_prefix_case(tester, long_s, 3, 3, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 16, 16, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 27, 27, casef, diacf, foldable_codepoints);
    // 32 > UB > len
    test_nofold_suffix_prefix_case(tester, long_s, 3, 29, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 18, 29, casef, diacf, foldable_codepoints);
    // UB = 32
    test_nofold_suffix_prefix_case(tester, long_s, 3, 32, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 18, 32, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 27, 32, casef, diacf, foldable_codepoints);
    // UB > 32
    test_nofold_suffix_prefix_case(tester, long_s, 3, 35, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 18, 35, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 27, 32, casef, diacf, foldable_codepoints);
    // UB > 48
    test_nofold_suffix_prefix_case(tester, long_s, 3, 49, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 18, 49, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 27, 32, casef, diacf, foldable_codepoints);
    // 32 >= LB > len
    test_nofold_suffix_prefix_case(tester, long_s, 28, 30, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 28, 28, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 28, 32, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 28, 34, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 28, 49, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 32, 32, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 32, 34, casef, diacf, foldable_codepoints);
    test_nofold_suffix_prefix_case(tester, long_s, 32, 49, casef, diacf, foldable_codepoints);
}

const uint32_t UNFOLDED_CASES[] = {0, 1, 3, 16};
// Predefined lengths to test a variety of cases
const uint32_t SHORT_LEN = 9;
const uint32_t MEDIUM_LEN = 16;
const uint32_t LONG_LEN = 27;

static void _test_text_search_str_encode_suffix_prefix(_mongocrypt_tester_t *tester) {
    unsigned int seed = (unsigned int)time(0);
    TEST_PRINTF("Testing with seed: %u", seed);
    srand(seed);
    // Run diacritic folding and case+diacritic folding for a variety of folded/unfolded sizes.
    for (uint32_t i = 0; i < sizeof(UNFOLDED_CASES) / sizeof(UNFOLDED_CASES[0]); i++) {
        char *short_s = build_random_string_to_fold(SHORT_LEN, SHORT_LEN + UNFOLDED_CASES[i]);
        char *medium_s = build_random_string_to_fold(MEDIUM_LEN, MEDIUM_LEN + UNFOLDED_CASES[i]);
        char *long_s = build_random_string_to_fold(LONG_LEN, LONG_LEN + UNFOLDED_CASES[i]);
        for (int casef = 0; casef <= 1; casef++) {
            suffix_prefix_run_folding_case(tester,
                                           short_s,
                                           medium_s,
                                           long_s,
                                           casef,
                                           true /* diacf */,
                                           UNFOLDED_CASES[i]);
        }
        bson_free(short_s);
        bson_free(medium_s);
        bson_free(long_s);
    }
    // Run case folding and no folding for different sizes. Only unfolded size matters.
    char *short_s = build_random_string_to_fold(SHORT_LEN, SHORT_LEN);
    char *medium_s = build_random_string_to_fold(MEDIUM_LEN, MEDIUM_LEN);
    char *long_s = build_random_string_to_fold(LONG_LEN, LONG_LEN);
    for (int casef = 0; casef <= 1; casef++) {
        suffix_prefix_run_folding_case(tester, short_s, medium_s, long_s, casef, false /* diacf*/, 0);
    }
    bson_free(short_s);
    bson_free(medium_s);
    bson_free(long_s);
}

static void substring_run_folding_case(_mongocrypt_tester_t *tester,
                                       const char *short_s,
                                       uint32_t short_unfolded_codepoint_len,
                                       const char *medium_s,
                                       uint32_t medium_unfolded_codepoint_len,
                                       const char *long_s,
                                       uint32_t long_unfolded_codepoint_len,
                                       bool casef,
                                       bool diacf,
                                       int foldable_codepoints) {
    // LB > 16
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             17,
                                             19,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // Simple cases
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             4,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             3,
                                             6,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // LB = UB
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             2,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             9,
                                             9,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB = len
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             9,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // 16 > UB > len
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             14,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB = 16
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             16,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB > 16
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             19,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB > 32
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             2,
                                             35,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // 16 >= LB > len
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             12,
                                             19,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             12,
                                             16,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             16,
                                             19,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             12,
                                             35,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             short_s,
                                             16,
                                             35,
                                             short_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);

    // len = 16 cases
    // LB > 16
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             17,
                                             19,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // Simple cases
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             2,
                                             4,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             3,
                                             6,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // LB = UB
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             2,
                                             2,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             16,
                                             16,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB = len
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             2,
                                             16,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB > len
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             2,
                                             19,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB = 32
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             2,
                                             32,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB > 32
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             2,
                                             35,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // LB = len
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             16,
                                             19,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             medium_s,
                                             16,
                                             35,
                                             medium_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);

    // len > 16 cases
    // LB > 32
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             33,
                                             38,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // Simple cases
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             2,
                                             4,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             6,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // LB < 16 <= UB <= len
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             18,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             16,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             27,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // 16 <= LB < UB <= len
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             18,
                                             24,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             16,
                                             24,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             18,
                                             27,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             16,
                                             27,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // LB = UB
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             3,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             16,
                                             16,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             27,
                                             27,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // 32 > UB > len
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             29,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             18,
                                             29,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB = 32
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             18,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             27,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB > 32
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             35,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             18,
                                             35,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             27,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // UB > 48
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             3,
                                             49,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             18,
                                             49,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             27,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    // 32 >= LB > len
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             28,
                                             30,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             28,
                                             28,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             28,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             28,
                                             34,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             28,
                                             49,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             32,
                                             32,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             32,
                                             34,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
    test_nofold_substring_case_multiple_mlen(tester,
                                             long_s,
                                             32,
                                             49,
                                             long_unfolded_codepoint_len,
                                             casef,
                                             diacf,
                                             foldable_codepoints);
}

static void _test_text_search_str_encode_substring(_mongocrypt_tester_t *tester) {
    unsigned int seed = (unsigned int)time(0);
    TEST_PRINTF("Testing with seed: %u", seed);
    srand(seed);
    // Run diacritic folding and case+diacritic folding for a variety of folded/unfolded sizes.
    for (uint32_t i = 0; i < sizeof(UNFOLDED_CASES) / sizeof(UNFOLDED_CASES[0]); i++) {
        char *short_s = build_random_string_to_fold(SHORT_LEN, SHORT_LEN + UNFOLDED_CASES[i]);
        char *medium_s = build_random_string_to_fold(MEDIUM_LEN, MEDIUM_LEN + UNFOLDED_CASES[i]);
        char *long_s = build_random_string_to_fold(LONG_LEN, LONG_LEN + UNFOLDED_CASES[i]);
        for (int casef = 0; casef <= 1; casef++) {
            substring_run_folding_case(tester,
                                       short_s,
                                       SHORT_LEN + UNFOLDED_CASES[i],
                                       medium_s,
                                       MEDIUM_LEN + UNFOLDED_CASES[i],
                                       long_s,
                                       LONG_LEN + UNFOLDED_CASES[i],
                                       casef,
                                       true /* diacf */,
                                       UNFOLDED_CASES[i]);
        }
        bson_free(short_s);
        bson_free(medium_s);
        bson_free(long_s);
    }
    // Run case folding and no folding for different sizes. Only unfolded size matters.
    char *short_s = build_random_string_to_fold(SHORT_LEN, SHORT_LEN);
    char *medium_s = build_random_string_to_fold(MEDIUM_LEN, MEDIUM_LEN);
    char *long_s = build_random_string_to_fold(LONG_LEN, LONG_LEN);
    for (int casef = 0; casef <= 1; casef++) {
        substring_run_folding_case(tester,
                                   short_s,
                                   SHORT_LEN,
                                   medium_s,
                                   MEDIUM_LEN,
                                   long_s,
                                   LONG_LEN,
                                   casef,
                                   false /* diacf */,
                                   0);
    }
    bson_free(short_s);
    bson_free(medium_s);
    bson_free(long_s);
}

static void _test_text_search_str_encode_multiple(_mongocrypt_tester_t *tester) {
    mc_FLE2TextSearchInsertSpec_t spec = {.v = "123456789",
                                          .len = 9,
                                          .substr = {{20, 9, 9}, true},
                                          .suffix = {{1, 5}, true},
                                          .prefix = {{6, 8}, true}};
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
    ASSERT_CMPUINT32(len, ==, 1);
    ASSERT_CMPUINT8((uint8_t)*str, ==, (uint8_t)'9');
    ASSERT_CMPUINT32(count, ==, 1);

    ASSERT(sets->prefix_set != NULL);
    mc_affix_set_iter_init(&it, sets->prefix_set);
    ASSERT(mc_affix_set_iter_next(&it, &str, &len, &count));
    ASSERT_CMPUINT32(len, ==, 6);
    ASSERT_CMPINT(0, ==, memcmp("123456", str, 6));
    ASSERT_CMPUINT32(count, ==, 1);

    ASSERT(sets->substring_set != NULL);
    mc_substring_set_iter_t ss_it;
    mc_substring_set_iter_init(&ss_it, sets->substring_set);
    ASSERT(mc_substring_set_iter_next(&ss_it, &str, &len, &count));
    ASSERT_CMPUINT32(len, ==, 9);
    ASSERT_CMPINT(0, ==, memcmp("123456789", str, 9));
    ASSERT_CMPUINT32(count, ==, 1);

    ASSERT_CMPUINT32(sets->exact.len, ==, 9);
    ASSERT_CMPINT(0, ==, memcmp(sets->exact.data, str, 9));

    mc_str_encode_sets_destroy(sets);
}

static void _test_text_search_str_encode_bad_string(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_FLE2TextSearchInsertSpec_t spec = {.v = "\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                                          .len = 9,
                                          .substr = {{20, 4, 7}, true},
                                          .suffix = {{1, 5}, true},
                                          .prefix = {{6, 8}, true}};
    mc_str_encode_sets_t *sets = mc_text_search_str_encode(&spec, status);
    ASSERT_FAILS_STATUS(sets, status, "not valid UTF-8");
    mc_str_encode_sets_destroy(sets);
    mongocrypt_status_destroy(status);
}

static void _test_text_search_str_encode_empty_string(_mongocrypt_tester_t *tester) {
    for (int casef = 0; casef <= 1; casef++) {
        for (int diacf = 0; diacf <= 1; diacf++) {
            test_nofold_suffix_prefix_case(tester, "", 1, 1, casef, diacf, 0);
            test_nofold_suffix_prefix_case(tester, "", 1, 2, casef, diacf, 0);
            test_nofold_suffix_prefix_case(tester, "", 2, 3, casef, diacf, 0);
            test_nofold_suffix_prefix_case(tester, "", 1, 16, casef, diacf, 0);
            test_nofold_suffix_prefix_case(tester, "", 1, 17, casef, diacf, 0);
            test_nofold_suffix_prefix_case(tester, "", 2, 16, casef, diacf, 0);
            test_nofold_suffix_prefix_case(tester, "", 2, 17, casef, diacf, 0);

            test_nofold_substring_case_multiple_mlen(tester, "", 1, 1, 1, casef, diacf, 0);
            test_nofold_substring_case_multiple_mlen(tester, "", 1, 2, 1, casef, diacf, 0);
            test_nofold_substring_case_multiple_mlen(tester, "", 2, 3, 1, casef, diacf, 0);
            test_nofold_substring_case_multiple_mlen(tester, "", 1, 16, 1, casef, diacf, 0);
            test_nofold_substring_case_multiple_mlen(tester, "", 1, 17, 1, casef, diacf, 0);
            test_nofold_substring_case_multiple_mlen(tester, "", 2, 16, 1, casef, diacf, 0);
            test_nofold_substring_case_multiple_mlen(tester, "", 2, 17, 1, casef, diacf, 0);
        }
    }
}

void _mongocrypt_tester_install_text_search_str_encode(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_text_search_str_encode_suffix_prefix);
    INSTALL_TEST(_test_text_search_str_encode_substring);
    INSTALL_TEST(_test_text_search_str_encode_multiple);
    INSTALL_TEST(_test_text_search_str_encode_bad_string);
    INSTALL_TEST(_test_text_search_str_encode_empty_string);
}
