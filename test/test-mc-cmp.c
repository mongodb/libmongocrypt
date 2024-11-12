/*
 * Copyright 2018-present MongoDB, Inc.
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

// `test-mc-cmp.h` is a modified copy of `test-bson-cmp.c` from libbson 1.28.0.

#include "test-mongocrypt.h"

#include "mc-cmp-private.h"

static void test_mc_cmp_equal(_mongocrypt_tester_t *tester) {
    (void)tester;

    ASSERT(mc_cmp_equal_ss(0, 0));
    ASSERT(!mc_cmp_equal_ss(0, -1));
    ASSERT(!mc_cmp_equal_ss(0, 1));
    ASSERT(!mc_cmp_equal_ss(-1, 0));
    ASSERT(mc_cmp_equal_ss(-1, -1));
    ASSERT(!mc_cmp_equal_ss(-1, 1));
    ASSERT(!mc_cmp_equal_ss(1, 0));
    ASSERT(!mc_cmp_equal_ss(1, -1));
    ASSERT(mc_cmp_equal_ss(1, 1));

    ASSERT(mc_cmp_equal_uu(0u, 0u));
    ASSERT(!mc_cmp_equal_uu(0u, 1u));
    ASSERT(!mc_cmp_equal_uu(1u, 0u));
    ASSERT(mc_cmp_equal_uu(1u, 1u));

    ASSERT(mc_cmp_equal_su(0, 0u));
    ASSERT(!mc_cmp_equal_su(0, 1u));
    ASSERT(!mc_cmp_equal_su(-1, 0u));
    ASSERT(!mc_cmp_equal_su(-1, 1u));
    ASSERT(!mc_cmp_equal_su(1, 0u));
    ASSERT(mc_cmp_equal_su(1, 1u));

    ASSERT(mc_cmp_equal_us(0u, 0));
    ASSERT(!mc_cmp_equal_us(0u, -1));
    ASSERT(!mc_cmp_equal_us(0u, 1));
    ASSERT(!mc_cmp_equal_us(1u, 0));
    ASSERT(!mc_cmp_equal_us(1u, -1));
    ASSERT(mc_cmp_equal_us(1u, 1));
}

static void test_mc_cmp_not_equal(_mongocrypt_tester_t *tester) {
    (void)tester;

    ASSERT(!mc_cmp_not_equal_ss(0, 0));
    ASSERT(mc_cmp_not_equal_ss(0, -1));
    ASSERT(mc_cmp_not_equal_ss(0, 1));
    ASSERT(mc_cmp_not_equal_ss(-1, 0));
    ASSERT(!mc_cmp_not_equal_ss(-1, -1));
    ASSERT(mc_cmp_not_equal_ss(-1, 1));
    ASSERT(mc_cmp_not_equal_ss(1, 0));
    ASSERT(mc_cmp_not_equal_ss(1, -1));
    ASSERT(!mc_cmp_not_equal_ss(1, 1));

    ASSERT(!mc_cmp_not_equal_uu(0u, 0u));
    ASSERT(mc_cmp_not_equal_uu(0u, 1u));
    ASSERT(mc_cmp_not_equal_uu(1u, 0u));
    ASSERT(!mc_cmp_not_equal_uu(1u, 1u));

    ASSERT(!mc_cmp_not_equal_su(0, 0u));
    ASSERT(mc_cmp_not_equal_su(0, 1u));
    ASSERT(mc_cmp_not_equal_su(-1, 0u));
    ASSERT(mc_cmp_not_equal_su(-1, 1u));
    ASSERT(mc_cmp_not_equal_su(1, 0u));
    ASSERT(!mc_cmp_not_equal_su(1, 1u));

    ASSERT(!mc_cmp_not_equal_us(0u, 0));
    ASSERT(mc_cmp_not_equal_us(0u, -1));
    ASSERT(mc_cmp_not_equal_us(0u, 1));
    ASSERT(mc_cmp_not_equal_us(1u, 0));
    ASSERT(mc_cmp_not_equal_us(1u, -1));
    ASSERT(!mc_cmp_not_equal_us(1u, 1));
}

static void test_mc_cmp_less(_mongocrypt_tester_t *tester) {
    (void)tester;

    ASSERT(!mc_cmp_less_ss(0, 0));
    ASSERT(!mc_cmp_less_ss(0, -1));
    ASSERT(mc_cmp_less_ss(0, 1));
    ASSERT(mc_cmp_less_ss(-1, 0));
    ASSERT(!mc_cmp_less_ss(-1, -1));
    ASSERT(mc_cmp_less_ss(-1, 1));
    ASSERT(!mc_cmp_less_ss(1, 0));
    ASSERT(!mc_cmp_less_ss(1, -1));
    ASSERT(!mc_cmp_less_ss(1, 1));

    ASSERT(!mc_cmp_less_uu(0u, 0u));
    ASSERT(mc_cmp_less_uu(0u, 1u));
    ASSERT(!mc_cmp_less_uu(1u, 0u));
    ASSERT(!mc_cmp_less_uu(1u, 1u));

    ASSERT(!mc_cmp_less_su(0, 0u));
    ASSERT(mc_cmp_less_su(0, 1u));
    ASSERT(mc_cmp_less_su(-1, 0u));
    ASSERT(mc_cmp_less_su(-1, 1u));
    ASSERT(!mc_cmp_less_su(1, 0u));
    ASSERT(!mc_cmp_less_su(1, 1u));

    ASSERT(!mc_cmp_less_us(0u, 0));
    ASSERT(!mc_cmp_less_us(0u, -1));
    ASSERT(mc_cmp_less_us(0u, 1));
    ASSERT(!mc_cmp_less_us(1u, 0));
    ASSERT(!mc_cmp_less_us(1u, -1));
    ASSERT(!mc_cmp_less_us(1u, 1));
}

static void test_mc_cmp_greater(_mongocrypt_tester_t *tester) {
    (void)tester;

    ASSERT(!mc_cmp_greater_ss(0, 0));
    ASSERT(mc_cmp_greater_ss(0, -1));
    ASSERT(!mc_cmp_greater_ss(0, 1));
    ASSERT(!mc_cmp_greater_ss(-1, 0));
    ASSERT(!mc_cmp_greater_ss(-1, -1));
    ASSERT(!mc_cmp_greater_ss(-1, 1));
    ASSERT(mc_cmp_greater_ss(1, 0));
    ASSERT(mc_cmp_greater_ss(1, -1));
    ASSERT(!mc_cmp_greater_ss(1, 1));

    ASSERT(!mc_cmp_greater_uu(0u, 0u));
    ASSERT(!mc_cmp_greater_uu(0u, 1u));
    ASSERT(mc_cmp_greater_uu(1u, 0u));
    ASSERT(!mc_cmp_greater_uu(1u, 1u));

    ASSERT(!mc_cmp_greater_su(0, 0u));
    ASSERT(!mc_cmp_greater_su(0, 1u));
    ASSERT(!mc_cmp_greater_su(-1, 0u));
    ASSERT(!mc_cmp_greater_su(-1, 1u));
    ASSERT(mc_cmp_greater_su(1, 0u));
    ASSERT(!mc_cmp_greater_su(1, 1u));

    ASSERT(!mc_cmp_greater_us(0u, 0));
    ASSERT(mc_cmp_greater_us(0u, -1));
    ASSERT(!mc_cmp_greater_us(0u, 1));
    ASSERT(mc_cmp_greater_us(1u, 0));
    ASSERT(mc_cmp_greater_us(1u, -1));
    ASSERT(!mc_cmp_greater_us(1u, 1));
}

static void test_mc_cmp_less_equal(_mongocrypt_tester_t *tester) {
    (void)tester;

    ASSERT(mc_cmp_less_equal_ss(0, 0));
    ASSERT(!mc_cmp_less_equal_ss(0, -1));
    ASSERT(mc_cmp_less_equal_ss(0, 1));
    ASSERT(mc_cmp_less_equal_ss(-1, 0));
    ASSERT(mc_cmp_less_equal_ss(-1, -1));
    ASSERT(mc_cmp_less_equal_ss(-1, 1));
    ASSERT(!mc_cmp_less_equal_ss(1, 0));
    ASSERT(!mc_cmp_less_equal_ss(1, -1));
    ASSERT(mc_cmp_less_equal_ss(1, 1));

    ASSERT(mc_cmp_less_equal_uu(0u, 0u));
    ASSERT(mc_cmp_less_equal_uu(0u, 1u));
    ASSERT(!mc_cmp_less_equal_uu(1u, 0u));
    ASSERT(mc_cmp_less_equal_uu(1u, 1u));

    ASSERT(mc_cmp_less_equal_su(0, 0u));
    ASSERT(mc_cmp_less_equal_su(0, 1u));
    ASSERT(mc_cmp_less_equal_su(-1, 0u));
    ASSERT(mc_cmp_less_equal_su(-1, 1u));
    ASSERT(!mc_cmp_less_equal_su(1, 0u));
    ASSERT(mc_cmp_less_equal_su(1, 1u));

    ASSERT(mc_cmp_less_equal_us(0u, 0));
    ASSERT(!mc_cmp_less_equal_us(0u, -1));
    ASSERT(mc_cmp_less_equal_us(0u, 1));
    ASSERT(!mc_cmp_less_equal_us(1u, 0));
    ASSERT(!mc_cmp_less_equal_us(1u, -1));
    ASSERT(mc_cmp_less_equal_us(1u, 1));
}

static void test_mc_cmp_greater_equal(_mongocrypt_tester_t *tester) {
    (void)tester;

    ASSERT(mc_cmp_greater_equal_ss(0, 0));
    ASSERT(mc_cmp_greater_equal_ss(0, -1));
    ASSERT(!mc_cmp_greater_equal_ss(0, 1));
    ASSERT(!mc_cmp_greater_equal_ss(-1, 0));
    ASSERT(mc_cmp_greater_equal_ss(-1, -1));
    ASSERT(!mc_cmp_greater_equal_ss(-1, 1));
    ASSERT(mc_cmp_greater_equal_ss(1, 0));
    ASSERT(mc_cmp_greater_equal_ss(1, -1));
    ASSERT(mc_cmp_greater_equal_ss(1, 1));

    ASSERT(mc_cmp_greater_equal_uu(0u, 0u));
    ASSERT(!mc_cmp_greater_equal_uu(0u, 1u));
    ASSERT(mc_cmp_greater_equal_uu(1u, 0u));
    ASSERT(mc_cmp_greater_equal_uu(1u, 1u));

    ASSERT(mc_cmp_greater_equal_su(0, 0u));
    ASSERT(!mc_cmp_greater_equal_su(0, 1u));
    ASSERT(!mc_cmp_greater_equal_su(-1, 0u));
    ASSERT(!mc_cmp_greater_equal_su(-1, 1u));
    ASSERT(mc_cmp_greater_equal_su(1, 0u));
    ASSERT(mc_cmp_greater_equal_su(1, 1u));

    ASSERT(mc_cmp_greater_equal_us(0u, 0));
    ASSERT(mc_cmp_greater_equal_us(0u, -1));
    ASSERT(!mc_cmp_greater_equal_us(0u, 1));
    ASSERT(mc_cmp_greater_equal_us(1u, 0));
    ASSERT(mc_cmp_greater_equal_us(1u, -1));
    ASSERT(mc_cmp_greater_equal_us(1u, 1));
}

static void test_mc_in_range(_mongocrypt_tester_t *tester) {
    (void)tester;

    const int64_t int8_min = INT8_MIN;
    const int64_t int8_max = INT8_MAX;
    const int64_t int32_min = INT32_MIN;
    const int64_t int32_max = INT32_MAX;

    const uint64_t uint8_max = UINT8_MAX;
    const uint64_t uint32_max = UINT32_MAX;

    const ssize_t ssize_min = SSIZE_MIN;
    const ssize_t ssize_max = SSIZE_MAX;

    ASSERT(!mc_in_range_signed(int8_t, int8_min - 1));
    ASSERT(mc_in_range_signed(int8_t, int8_min));
    ASSERT(mc_in_range_signed(int8_t, 0));
    ASSERT(mc_in_range_signed(int8_t, int8_max));
    ASSERT(!mc_in_range_signed(int8_t, int8_max + 1));

    ASSERT(mc_in_range_unsigned(int8_t, 0u));
    ASSERT(mc_in_range_unsigned(int8_t, (uint64_t)int8_max));
    ASSERT(!mc_in_range_unsigned(int8_t, (uint64_t)(int8_max + 1)));

    ASSERT(!mc_in_range_signed(uint8_t, int8_min - 1));
    ASSERT(!mc_in_range_signed(uint8_t, int8_min));
    ASSERT(mc_in_range_signed(uint8_t, 0));
    ASSERT(mc_in_range_signed(uint8_t, int8_max));
    ASSERT(mc_in_range_signed(uint8_t, int8_max + 1));
    ASSERT(mc_in_range_signed(uint8_t, (int64_t)uint8_max));
    ASSERT(!mc_in_range_signed(uint8_t, (int64_t)uint8_max + 1));

    ASSERT(mc_in_range_unsigned(uint8_t, 0u));
    ASSERT(mc_in_range_unsigned(uint8_t, uint8_max));
    ASSERT(!mc_in_range_unsigned(uint8_t, uint8_max + 1u));

    ASSERT(!mc_in_range_signed(int32_t, int32_min - 1));
    ASSERT(mc_in_range_signed(int32_t, int32_min));
    ASSERT(mc_in_range_signed(int32_t, 0));
    ASSERT(mc_in_range_signed(int32_t, int32_max));
    ASSERT(!mc_in_range_signed(int32_t, int32_max + 1));

    ASSERT(mc_in_range_unsigned(int32_t, 0u));
    ASSERT(mc_in_range_unsigned(int32_t, (uint64_t)int32_max));
    ASSERT(!mc_in_range_unsigned(int32_t, (uint64_t)(int32_max + 1)));

    ASSERT(!mc_in_range_signed(uint32_t, int32_min - 1));
    ASSERT(!mc_in_range_signed(uint32_t, int32_min));
    ASSERT(mc_in_range_signed(uint32_t, 0));
    ASSERT(mc_in_range_signed(uint32_t, int32_max));
    ASSERT(mc_in_range_signed(uint32_t, int32_max + 1));
    ASSERT(mc_in_range_signed(uint32_t, (int64_t)uint32_max));
    ASSERT(!mc_in_range_signed(uint32_t, (int64_t)uint32_max + 1));

    ASSERT(mc_in_range_unsigned(uint32_t, 0u));
    ASSERT(mc_in_range_unsigned(uint32_t, uint32_max));
    ASSERT(!mc_in_range_unsigned(uint32_t, uint32_max + 1u));

    ASSERT(mc_in_range_signed(ssize_t, ssize_min));
    ASSERT(mc_in_range_signed(ssize_t, 0));
    ASSERT(mc_in_range_signed(ssize_t, ssize_max));

    ASSERT(mc_in_range_unsigned(ssize_t, 0u));
    ASSERT(mc_in_range_unsigned(ssize_t, (size_t)ssize_max));
    ASSERT(!mc_in_range_unsigned(ssize_t, (size_t)ssize_max + 1u));

    ASSERT(!mc_in_range_signed(size_t, ssize_min));
    ASSERT(mc_in_range_signed(size_t, 0));
    ASSERT(mc_in_range_signed(size_t, ssize_max));

    ASSERT(mc_in_range_unsigned(size_t, 0u));
    ASSERT(mc_in_range_unsigned(size_t, (size_t)ssize_max));
    ASSERT(mc_in_range_unsigned(size_t, (size_t)ssize_max + 1u));
}

void _mongocrypt_tester_install_mc_cmp(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_cmp_equal);
    INSTALL_TEST(test_mc_cmp_not_equal);
    INSTALL_TEST(test_mc_cmp_less);
    INSTALL_TEST(test_mc_cmp_greater);
    INSTALL_TEST(test_mc_cmp_less_equal);
    INSTALL_TEST(test_mc_cmp_greater_equal);
    INSTALL_TEST(test_mc_in_range);
}
