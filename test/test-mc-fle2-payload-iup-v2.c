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

#include "mc-fle2-insert-update-payload-private-v2.h"
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
        printf("Common Crypto with no CTR support detected. Skipping.");
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

void _mongocrypt_tester_install_fle2_payload_iup_v2(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_FLE2InsertUpdatePayloadV2_parse);
    INSTALL_TEST(_test_mc_FLE2InsertUpdatePayloadV2_decrypt);
}
