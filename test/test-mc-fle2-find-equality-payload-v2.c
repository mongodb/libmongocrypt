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

#include "mc-fle2-find-equality-payload-private-v2.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#define TEST_FIND_EQ_PAYLOAD_HEX_V2                                                                                    \
    "890000000564002000000000fe88309ead860127cc991c969ed9d4157aed46b40d7984104"                                        \
    "d082cdd72197de605730020000000004e66e2f903d7ffbea7af1cb2482d7389329e141a95"                                        \
    "ac2833898a33b5e4f7150e056c002000000000c3c8980ed11e63ec199104bc9a0889322c9"                                        \
    "eb80d00eee0b5148dc83f7e78adb712636d00040000000000000000"

static void _test_FLE2FindEqualityPayloadV2_roundtrip(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    _mongocrypt_buffer_t expect_edcDerivedToken;
    _mongocrypt_buffer_t expect_escDerivedToken;
    _mongocrypt_buffer_t expect_serverDerivedFromDataToken;
    bson_t in_bson;
    bson_t out_bson;
    mc_FLE2FindEqualityPayloadV2_t payload;

    _mongocrypt_buffer_copy_from_hex(&expect_edcDerivedToken,
                                     "fe88309ead860127cc991c969ed9d4157aed46b40d7984104d082cdd72197de6");

    _mongocrypt_buffer_copy_from_hex(&expect_escDerivedToken,
                                     "4e66e2f903d7ffbea7af1cb2482d7389329e141a95ac2833898a33b5e4f7150e");

    _mongocrypt_buffer_copy_from_hex(&expect_serverDerivedFromDataToken,
                                     "c3c8980ed11e63ec199104bc9a0889322c9eb80d00eee0b5148dc83f7e78adb7");

    _mongocrypt_buffer_copy_from_hex(&input, TEST_FIND_EQ_PAYLOAD_HEX_V2);

    ASSERT(bson_init_static(&in_bson, input.data, input.len));

    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_FLE2FindEqualityPayloadV2_init(&payload);

    ASSERT_OK_STATUS(mc_FLE2FindEqualityPayloadV2_parse(&payload, &in_bson, status), status);

    ASSERT_CMPBUF(expect_edcDerivedToken, payload.edcDerivedToken);
    ASSERT_CMPBUF(expect_escDerivedToken, payload.escDerivedToken);
    ASSERT_CMPBUF(expect_serverDerivedFromDataToken, payload.serverDerivedFromDataToken);

    bson_init(&out_bson);
    mc_FLE2FindEqualityPayloadV2_serialize(&payload, &out_bson);
    ASSERT_EQUAL_BSON(&in_bson, &out_bson);

    mongocrypt_status_destroy(status);
    mc_FLE2FindEqualityPayloadV2_cleanup(&payload);
    bson_destroy(&out_bson);
    bson_destroy(&in_bson);
    _mongocrypt_buffer_cleanup(&expect_serverDerivedFromDataToken);
    _mongocrypt_buffer_cleanup(&expect_escDerivedToken);
    _mongocrypt_buffer_cleanup(&expect_edcDerivedToken);
    _mongocrypt_buffer_cleanup(&input);
}

#undef TEST_FIND_EQ_PAYLOAD_HEX_V2

void _mongocrypt_tester_install_fle2_payload_find_equality_v2(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_FLE2FindEqualityPayloadV2_roundtrip);
}