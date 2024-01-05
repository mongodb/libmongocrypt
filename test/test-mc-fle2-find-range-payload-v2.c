/*
 * Copyright 2023-present MongoDB, Inc.
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

#include <bson/bson.h>

#include "mc-fle2-find-range-payload-private-v2.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#define TEST_FIND_RANGE_PAYLOAD_HEX_V2                                                                                 \
    "dd000000037061796c6f61640099000000046700850000000330007d00000005640020000"                                        \
    "00000280edab4190763d1f4183d383f8830773859c3a74a13161094e6fd44e7390fed0573"                                        \
    "0020000000008773322a2b9e6c08886db6bc65b46ffdd64651e8a49400a9e55ff5bc550d4"                                        \
    "5bf056c00200000000086cc691b04514af096dfe1497bbb27151ac71f18d61ddc4c7c3a75"                                        \
    "503df6974b000012636d00040000000000000000107061796c6f616449640000000000106"                                        \
    "6697273744f70657261746f720002000000107365636f6e644f70657261746f7200040000"                                        \
    "0000"

static void _test_FLE2FindRangePayloadV2_roundtrip(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    mc_FLE2FindRangePayloadV2_t payload;
    _mongocrypt_buffer_t expect_edcDerivedToken;
    _mongocrypt_buffer_t expect_escDerivedToken;
    _mongocrypt_buffer_t expect_serverDerivedFromDataToken;
    mc_FLE2RangeOperator_t expect_firstOperator = FLE2RangeOperator_kGte;
    mc_FLE2RangeOperator_t expect_secondOperator = FLE2RangeOperator_kLte;

    bson_t in_bson;
    bson_t out_bson;

    _mongocrypt_buffer_copy_from_hex(&expect_edcDerivedToken,
                                     "280edab4190763d1f4183d383f8830773859c3a74a13161094e6fd44e7390fed");

    _mongocrypt_buffer_copy_from_hex(&expect_escDerivedToken,
                                     "8773322a2b9e6c08886db6bc65b46ffdd64651e8a49400a9e55ff5bc550d45bf");

    _mongocrypt_buffer_copy_from_hex(&expect_serverDerivedFromDataToken,
                                     "86cc691b04514af096dfe1497bbb27151ac71f18d61ddc4c7c3a75503df6974b");

    _mongocrypt_buffer_copy_from_hex(&input, TEST_FIND_RANGE_PAYLOAD_HEX_V2);

    ASSERT(bson_init_static(&in_bson, input.data, input.len));

    mc_FLE2FindRangePayloadV2_init(&payload);

    {
        mc_EdgeFindTokenSetV2_t tokenSet;
        tokenSet.edcDerivedToken = expect_edcDerivedToken;
        tokenSet.escDerivedToken = expect_escDerivedToken;
        tokenSet.serverDerivedFromDataToken = expect_serverDerivedFromDataToken;
        _mc_array_append_val(&payload.payload.value.edgeFindTokenSetArray, tokenSet);
        payload.payload.value.maxContentionFactor = (uint64_t)4;
    }

    payload.payload.set = true;
    payload.payloadId = 0x0;

    payload.firstOperator = expect_firstOperator;
    payload.secondOperator = expect_secondOperator;

    bson_init(&out_bson);
    mc_FLE2FindRangePayloadV2_serialize(&payload, &out_bson);

    ASSERT_EQUAL_BSON(&in_bson, &out_bson);

    bson_destroy(&out_bson);
    bson_destroy(&in_bson);
    mc_FLE2FindRangePayloadV2_cleanup(&payload);
    _mongocrypt_buffer_cleanup(&input);
}

#undef TEST_FIND_RANGE_PAYLOAD_HEX_V2

void _mongocrypt_tester_install_fle2_payload_find_range_v2(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_FLE2FindRangePayloadV2_roundtrip);
}