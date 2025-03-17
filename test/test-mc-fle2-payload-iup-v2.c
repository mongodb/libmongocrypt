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

#include "mc-fle-blob-subtype-private.h"
#include "mc-fle2-insert-update-payload-private-v2.h"
#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt.h"

#define TEST_IUP_HEX_V2                                                                                                \
    "045f0100000564002000000000d9a58a50d253b4d6dc55504a242a051377a7e33dd6b5065"                                        \
    "50fb1e41097f5a621057300200000000004516951c06f8d5cb5ef5ec42cd7d419b6f4e896"                                        \
    "a0f7d0609626a0cda8ced6990570003000000000993cc8be4fbe7d8b9ab5871c12204c3fb"                                        \
    "2ad0ce29eb5f6b96a224b2bd7b41bb994c3ea2679497e95da93be2cb9ab73c30575001000"                                        \
    "0000044c2352e235314b429c897d833b411b771074000200000005760050000000004c235"                                        \
    "2e235314b429c897d833b411b777e6c20c2aa5e2df89f5ccaceb9a5ed9164a7e2802c9312"                                        \
    "139f5580775e846eb328b5804603d0bde6c12cf5d96b8b6b7a173bb25088a5ba8ce754f4f"                                        \
    "4d57088ba0565002000000000a4c5de2625c5d5eae40076f0cc0f581c8d4784f2a3906035"                                        \
    "e710202432a17d99056c002000000000c3c8980ed11e63ec199104bc9a0889322c9eb80d0"                                        \
    "0eee0b5148dc83f7e78adb7126b00020000000000000000"

static void _test_FLE2InsertUpdatePayloadV2_parse(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    mc_FLE2InsertUpdatePayloadV2_t iup;
    _mongocrypt_buffer_t expect_edcDerivedToken;
    _mongocrypt_buffer_t expect_escDerivedToken;
    _mongocrypt_buffer_t expect_encryptedTokens;
    _mongocrypt_buffer_t expect_indexKeyId;
    bson_type_t expect_valueType = BSON_TYPE_UTF8;
    _mongocrypt_buffer_t expect_value;
    _mongocrypt_buffer_t expect_serverEncryptionToken;
    _mongocrypt_buffer_t expect_serverDerivedFromDataToken;
    _mongocrypt_buffer_t expect_userKeyId;

    _mongocrypt_buffer_copy_from_hex(&expect_edcDerivedToken,
                                     "D9A58A50D253B4D6DC55504A242A051377A7E33DD6B506550FB1E41097F5A621");

    _mongocrypt_buffer_copy_from_hex(&expect_escDerivedToken,
                                     "04516951C06F8D5CB5EF5EC42CD7D419B6F4E896A0F7D0609626A0CDA8CED699");

    _mongocrypt_buffer_copy_from_hex(&expect_encryptedTokens,
                                     "993CC8BE4FBE7D8B9AB5871C12204C3FB2AD0CE29EB5F6B96A224B2BD7B41BB99"
                                     "4C3EA2679497E95DA93BE2CB9AB73C3");

    _mongocrypt_buffer_copy_from_hex(&expect_indexKeyId, "4c2352e235314b429c897d833b411b77");

    _mongocrypt_buffer_copy_from_hex(&expect_value,
                                     "4C2352E235314B429C897D833B411B777E6C20C2AA5E2DF89F5CCACEB9A5ED9"
                                     "164A7E2802C9312139F5580775E846EB328B5804603D0BDE6C12CF5D96B8B6B"
                                     "7A173BB25088A5BA8CE754F4F4D57088BA");

    _mongocrypt_buffer_copy_from_hex(&expect_serverEncryptionToken,
                                     "A4C5DE2625C5D5EAE40076F0CC0F581C8D4784F2A3906035E710202432A17D99");

    _mongocrypt_buffer_copy_from_hex(&expect_serverDerivedFromDataToken,
                                     "C3C8980ED11E63EC199104BC9A0889322C9EB80D00EEE0B5148DC83F7E78ADB7");

    _mongocrypt_buffer_copy_from_hex(&expect_userKeyId, "4c2352e235314b429c897d833b411b77");

    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, TEST_IUP_HEX_V2);
        mc_FLE2InsertUpdatePayloadV2_init(&iup);
        ASSERT_OK_STATUS(mc_FLE2InsertUpdatePayloadV2_parse(&iup, &input, status), status);

        ASSERT_CMPBUF(expect_edcDerivedToken, iup.edcDerivedToken);
        ASSERT_CMPBUF(expect_escDerivedToken, iup.escDerivedToken);
        ASSERT_CMPBUF(expect_encryptedTokens, iup.encryptedTokens);
        ASSERT_CMPBUF(expect_indexKeyId, iup.indexKeyId);
        ASSERT(expect_valueType == iup.valueType);
        ASSERT_CMPBUF(expect_value, iup.value);
        ASSERT_CMPBUF(expect_serverEncryptionToken, iup.serverEncryptionToken);
        ASSERT_CMPBUF(expect_serverDerivedFromDataToken, iup.serverDerivedFromDataToken);
        ASSERT_CMPBUF(expect_userKeyId, iup.userKeyId);
        mc_FLE2InsertUpdatePayloadV2_cleanup(&iup);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
    }

    _mongocrypt_buffer_cleanup(&expect_edcDerivedToken);
    _mongocrypt_buffer_cleanup(&expect_escDerivedToken);
    _mongocrypt_buffer_cleanup(&expect_encryptedTokens);
    _mongocrypt_buffer_cleanup(&expect_indexKeyId);
    _mongocrypt_buffer_cleanup(&expect_value);
    _mongocrypt_buffer_cleanup(&expect_serverEncryptionToken);
    _mongocrypt_buffer_cleanup(&expect_serverDerivedFromDataToken);
    _mongocrypt_buffer_cleanup(&expect_userKeyId);
}

static void _test_mc_FLE2InsertUpdatePayloadV2_decrypt(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    mc_FLE2InsertUpdatePayloadV2_t iup;
    _mongocrypt_buffer_t expect_plaintext;
    _mongocrypt_buffer_t correct_key;
    mongocrypt_t *crypt;

    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    _mongocrypt_buffer_copy_from_hex(&correct_key,
                                     "2d4a2ca8e12c47c0c7ba29f878556ff563b1e083a7aae5dc40c7b61a0094f558198b88f7"
                                     "5007e0eea658b4aab6e5a86908e5efeabe9b48c2b290052665f60828c87b19781ed935a0"
                                     "4d4366e104a3b66996d0108ae62c4c675321c6f8c2871436");

    ASSERT(
        _mongocrypt_buffer_copy_from_data_and_size(&expect_plaintext, (const uint8_t *)"\x08\x00\x00\x00shreyas", 12));

    /* Test successful decrypt. */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, TEST_IUP_HEX_V2);
        mc_FLE2InsertUpdatePayloadV2_init(&iup);
        ASSERT_OK_STATUS(mc_FLE2InsertUpdatePayloadV2_parse(&iup, &input, status), status);
        const _mongocrypt_buffer_t *got =
            mc_FLE2InsertUpdatePayloadV2_decrypt(crypt->crypto, &iup, &correct_key, status);
        ASSERT_OK_STATUS(got != NULL, status);
        ASSERT_CMPBUF(expect_plaintext, *got);

        mc_FLE2InsertUpdatePayloadV2_cleanup(&iup);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
    }

    /* Test incorrect key. */
    {
        _mongocrypt_buffer_t incorrect_key;

        _mongocrypt_buffer_init(&incorrect_key);
        _mongocrypt_buffer_copy_to(&correct_key, &incorrect_key);
        /* The middle 32 bytes of key are used to generate the mac. Change first
         * byte to make user key incorrect. */
        incorrect_key.data[32] = 0;

        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, TEST_IUP_HEX_V2);
        mc_FLE2InsertUpdatePayloadV2_init(&iup);
        ASSERT_OK_STATUS(mc_FLE2InsertUpdatePayloadV2_parse(&iup, &input, status), status);
        const _mongocrypt_buffer_t *got =
            mc_FLE2InsertUpdatePayloadV2_decrypt(crypt->crypto, &iup, &incorrect_key, status);
        ASSERT_FAILS_STATUS(got != NULL, status, "HMAC validation failure");

        mc_FLE2InsertUpdatePayloadV2_cleanup(&iup);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
        _mongocrypt_buffer_cleanup(&incorrect_key);
    }

    _mongocrypt_buffer_cleanup(&expect_plaintext);
    _mongocrypt_buffer_cleanup(&correct_key);
    mongocrypt_destroy(crypt);
}

#undef TEST_IUP_HEX_V2

static void _test_mc_FLE2InsertUpdatePayloadV2_includes_crypto_params(_mongocrypt_tester_t *tester) {
    mc_FLE2InsertUpdatePayloadV2_t payload;
    mc_FLE2InsertUpdatePayloadV2_init(&payload);
    payload.sparsity = OPT_I64(1);
    payload.precision = OPT_I32(2);
    payload.trimFactor = OPT_I32(3);
    bson_value_t indexMin = {.value.v_int32 = 4, .value_type = BSON_TYPE_INT32};
    bson_value_copy(&indexMin, &payload.indexMin);
    bson_value_t indexMax = {.value.v_int32 = 5, .value_type = BSON_TYPE_INT32};
    bson_value_copy(&indexMax, &payload.indexMax);

    // Test crypto params from SERVER-91889 are included in "range" payload.
    {
        bson_t got = BSON_INITIALIZER;
        const bool use_range_v2 = true;
        ASSERT(mc_FLE2InsertUpdatePayloadV2_serializeForRange(&payload, &got, use_range_v2));
        _assert_match_bson(&got, TMP_BSON(BSON_STR({"sp" : 1, "pn" : 2, "tf" : 3, "mn" : 4, "mx" : 5})));
        bson_destroy(&got);
    }

    // Test crypto params from SERVER-91889 are excluded in "rangePreview" payload.
    {
        bson_t got = BSON_INITIALIZER;
        const bool use_range_v2 = false;
        ASSERT(mc_FLE2InsertUpdatePayloadV2_serializeForRange(&payload, &got, use_range_v2));
        _assert_match_bson(&got, TMP_BSON(BSON_STR({
            "sp" : {"$exists" : false},
            "pn" : {"$exists" : false},
            "tf" : {"$exists" : false},
            "mn" : {"$exists" : false},
            "mx" : {"$exists" : false}
        })));
        bson_destroy(&got);
    }
    mc_FLE2InsertUpdatePayloadV2_cleanup(&payload);
}

static void _test_mc_FLE2InsertUpdatePayloadV2_parses_crypto_params(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *payload = TEST_FILE("test/data/range-sends-cryptoParams/explicit-insert-int32/expected.json");

    _mongocrypt_buffer_t payload_buf;
    // Unwrap the { "v": <BSON binary> } into a `_mongocrypt_buffer_t`.
    {
        bson_t payload_bson;
        ASSERT(_mongocrypt_binary_to_bson(payload, &payload_bson));
        bson_iter_t iter;
        ASSERT(bson_iter_init_find(&iter, &payload_bson, "v"));
        ASSERT(_mongocrypt_buffer_from_binary_iter(&payload_buf, &iter));
    }

    mc_FLE2InsertUpdatePayloadV2_t got;
    mc_FLE2InsertUpdatePayloadV2_init(&got);

    mongocrypt_status_t *status = mongocrypt_status_new();
    ASSERT_OK_STATUS(mc_FLE2InsertUpdatePayloadV2_parse(&got, &payload_buf, status), status);
    mongocrypt_status_destroy(status);

    ASSERT(got.sparsity.set);
    ASSERT_CMPINT64(got.sparsity.value, ==, 3);

    ASSERT(!got.precision.set); // Payload does not include precision.

    ASSERT(got.trimFactor.set);
    ASSERT_CMPINT32(got.trimFactor.value, ==, 4);

    ASSERT(got.indexMin.value_type == BSON_TYPE_INT32);
    ASSERT_CMPINT32(got.indexMin.value.v_int32, ==, 0);

    ASSERT(got.indexMax.value_type == BSON_TYPE_INT32);
    ASSERT_CMPINT32(got.indexMax.value.v_int32, ==, 1234567);

    mc_FLE2InsertUpdatePayloadV2_cleanup(&got);
}

static void _test_mc_FLE2InsertUpdatePayloadV2_parse_errors(_mongocrypt_tester_t *tester) {
    bson_t *input_bson = TMP_BSON(BSON_STR({
        "d" : {"$binary" : {"base64" : "AAAA", "subType" : "00"}}, //
        "t" : "wrong type!"
    }));
    _mongocrypt_buffer_t input_buf;
    _mongocrypt_buffer_init_size(&input_buf, 1 + input_bson->len);
    input_buf.data[0] = (uint8_t)MC_SUBTYPE_FLE2InsertUpdatePayloadV2;
    memcpy(input_buf.data + 1, bson_get_data(input_bson), input_bson->len);

    mc_FLE2InsertUpdatePayloadV2_t payload;
    mc_FLE2InsertUpdatePayloadV2_init(&payload);
    mongocrypt_status_t *status = mongocrypt_status_new();
    ASSERT_FAILS_STATUS(mc_FLE2InsertUpdatePayloadV2_parse(&payload, &input_buf, status),
                        status,
                        "Field 't' expected to hold an int32");
    mc_FLE2InsertUpdatePayloadV2_cleanup(&payload);
    mongocrypt_status_destroy(status);
    _mongocrypt_buffer_cleanup(&input_buf);
}

void _mongocrypt_tester_install_fle2_payload_iup_v2(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_FLE2InsertUpdatePayloadV2_parse);
    INSTALL_TEST(_test_mc_FLE2InsertUpdatePayloadV2_decrypt);
    INSTALL_TEST(_test_mc_FLE2InsertUpdatePayloadV2_includes_crypto_params);
    INSTALL_TEST(_test_mc_FLE2InsertUpdatePayloadV2_parses_crypto_params);
    INSTALL_TEST(_test_mc_FLE2InsertUpdatePayloadV2_parse_errors);
}
