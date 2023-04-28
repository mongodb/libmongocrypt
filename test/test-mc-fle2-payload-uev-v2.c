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

#include "mc-fle2-payload-uev-v2-private.h"
#include "test-mongocrypt.h"

#define TEST_KEY_UUID_HEX "abcdefab123498761234123456789012"
#define TEST_KEY_HEX                                                                                                   \
    "a7ddbc4c8be00d51f68d9d8e485f351c8edc8d2206b24d8e0e1816d005fbe520e4891250"                                         \
    "47d647b0d8684bfbdbf09c304085ed086aba6c2b2b1677ccc91ced8847a733bf5e5682c8"                                         \
    "4b3ee7969e4a5fe0e0c21e5e3ee190595a55f83147d8de2a"
#define TEST_PLAINTEXT "\x09\x00\x00\x00value123\x00"
#define TEST_PLAINTEXT_LEN 13

// prefix = (FLE_TYPE || KEY_UUID || BSON_TYPE)
#define TEST_PREFIX_HEX "10" TEST_KEY_UUID_HEX "02"
// ciphertext = (IV || S || HMAC)
#define TEST_CIPHERTEXT_HEX                                                                                            \
    "abcdefabdeadbeeffeedbacc012345671f7c9cf4b09b2baa7f8752b9fb7a8c77469f00a1f"                                        \
    "b1735ed5b4b941f151bad3d709a1f3555788fef373088d47ceb9677"
// uev = (prefix || ciphertext)
#define TEST_UEV_HEX TEST_PREFIX_HEX TEST_CIPHERTEXT_HEX

// This ciphertext was encrypted with CTR mode and has a valid HMAC. This is for
// testing failure during the block alignment check when decrypting with CBC
// mode.
#define TEST_UEV_CTR_HEX                                                                                               \
    TEST_PREFIX_HEX "abcdefabdeadbeeffeedbacc012345679fc22f7a164b528b1018bb117"                                        \
                    "52b904cb6ee00c837d7e0b4d32b47be3617bc3783507dd676b21d7720"                                        \
                    "58b17794726884d79dd851aa8786bafdd544dab9"

static void test_FLE2UnindexedEncryptedValueV2_parse(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    _mongocrypt_buffer_t expect_key_uuid;
    mc_FLE2UnindexedEncryptedValueV2_t *uev;

    /* Test successful parse. */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, TEST_UEV_HEX);
        _mongocrypt_buffer_copy_from_hex(&expect_key_uuid, TEST_KEY_UUID_HEX);

        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status), status);
        const _mongocrypt_buffer_t *got = mc_FLE2UnindexedEncryptedValueV2_get_key_uuid(uev, status);
        ASSERT_OR_PRINT(got != NULL, status);
        ASSERT_CMPBUF(expect_key_uuid, *got);
        bson_type_t got_bson_type = mc_FLE2UnindexedEncryptedValueV2_get_original_bson_type(uev, status);
        ASSERT_OR_PRINT(got_bson_type == BSON_TYPE_UTF8, status);
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&expect_key_uuid);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
    }

    /* Test too-short input. */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, "10123456781234");
        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_FAILS_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status),
                            status,
                            "expected byte length >= 17 got: 7");
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
    }

    /* Test incorrect fle_blob_subtype */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, TEST_UEV_HEX);
        input.data[0] = 5;
        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_FAILS_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status),
                            status,
                            "expected fle_blob_subtype=16 got: 5");
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
    }

    /* Test double parsing */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&input, TEST_UEV_HEX);
        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status), status);
        ASSERT_FAILS_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status),
                            status,
                            "must not be called twice");
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&input);
        mongocrypt_status_destroy(status);
    }

    /* Test attempting to get key_uuid or original_bson_type before parsing. */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        const _mongocrypt_buffer_t *got = mc_FLE2UnindexedEncryptedValueV2_get_key_uuid(uev, status);
        ASSERT_FAILS_STATUS(got != NULL, status, "must be called after mc_FLE2UnindexedEncryptedValueV2_parse");

        mongocrypt_status_destroy(status);
        status = mongocrypt_status_new();

        bson_type_t got_bson_type = mc_FLE2UnindexedEncryptedValueV2_get_original_bson_type(uev, status);
        ASSERT_FAILS_STATUS(got_bson_type != 0, status, "must be called after mc_FLE2UnindexedEncryptedValueV2_parse");

        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        mongocrypt_status_destroy(status);
    }
}

static void test_FLE2UnindexedEncryptedValueV2_decrypt(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    _mongocrypt_buffer_t correct_key;
    mc_FLE2UnindexedEncryptedValueV2_t *uev;
    _mongocrypt_buffer_t expect_key_uuid;
    _mongocrypt_buffer_t expect_plaintext;
    mongocrypt_t *crypt;

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    _mongocrypt_buffer_copy_from_hex(&input, TEST_UEV_HEX);
    _mongocrypt_buffer_copy_from_hex(&expect_key_uuid, TEST_KEY_UUID_HEX);
    _mongocrypt_buffer_copy_from_hex(&correct_key, TEST_KEY_HEX);
    ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&expect_plaintext,
                                                      (const uint8_t *)TEST_PLAINTEXT,
                                                      TEST_PLAINTEXT_LEN));

    /* Test success. */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status), status);

        const _mongocrypt_buffer_t *got = mc_FLE2UnindexedEncryptedValueV2_get_key_uuid(uev, status);
        ASSERT_OR_PRINT(got != NULL, status);
        ASSERT_CMPBUF(expect_key_uuid, *got);

        got = mc_FLE2UnindexedEncryptedValueV2_decrypt(crypt->crypto, uev, &correct_key, status);
        ASSERT_OK_STATUS(got != NULL, status);
        ASSERT_CMPBUF(expect_plaintext, *got);
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        mongocrypt_status_destroy(status);
    }

    /* Test an incorrect key. */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_t incorrect_key;

        _mongocrypt_buffer_init(&incorrect_key);
        _mongocrypt_buffer_copy_to(&correct_key, &incorrect_key);
        /* The middle 32 bytes of key are used to generate the mac. Change first
         * byte to make S_Key incorrect. */
        incorrect_key.data[32] = 0;
        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &input, status), status);
        const _mongocrypt_buffer_t *got =
            mc_FLE2UnindexedEncryptedValueV2_decrypt(crypt->crypto, uev, &incorrect_key, status);
        ASSERT_FAILS_STATUS(got != NULL, status, "HMAC validation failure");
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&incorrect_key);
        mongocrypt_status_destroy(status);
    }

    /* Test empty ciphertext */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_t short_input;

        _mongocrypt_buffer_copy_from_hex(&short_input, TEST_PREFIX_HEX);

        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &short_input, status), status);
        const _mongocrypt_buffer_t *got =
            mc_FLE2UnindexedEncryptedValueV2_decrypt(crypt->crypto, uev, &correct_key, status);
        ASSERT_FAILS_STATUS(got != NULL, status, "input ciphertext too small");
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&short_input);
        mongocrypt_status_destroy(status);
    }

    /* Test non-block aligned ciphertext */
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        _mongocrypt_buffer_t bad_input;

        _mongocrypt_buffer_copy_from_hex(&bad_input, TEST_UEV_CTR_HEX);

        uev = mc_FLE2UnindexedEncryptedValueV2_new();
        ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &bad_input, status), status);
        const _mongocrypt_buffer_t *got =
            mc_FLE2UnindexedEncryptedValueV2_decrypt(crypt->crypto, uev, &correct_key, status);
        ASSERT_FAILS_STATUS(got != NULL, status, "ciphertext length is not a multiple of block size");
        mc_FLE2UnindexedEncryptedValueV2_destroy(uev);
        _mongocrypt_buffer_cleanup(&bad_input);
        mongocrypt_status_destroy(status);
    }

    _mongocrypt_buffer_cleanup(&expect_plaintext);
    _mongocrypt_buffer_cleanup(&correct_key);
    _mongocrypt_buffer_cleanup(&expect_key_uuid);
    _mongocrypt_buffer_cleanup(&input);
    mongocrypt_destroy(crypt);
}

static void test_FLE2UnindexedEncryptedValueV2_ctx_decrypt(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    {
        // {v: BinData(ENCRYPTED, payload)}
        _mongocrypt_buffer_t payload;
        _mongocrypt_buffer_copy_from_hex(&payload, TEST_UEV_HEX);
        bson_t doc;
        bson_init(&doc);
        ASSERT(bson_append_binary(&doc, "v", (int)strlen("v"), BSON_SUBTYPE_ENCRYPTED, payload.data, payload.len));
        mongocrypt_binary_t *bin = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(&doc), doc.len);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, bin), ctx);
        mongocrypt_binary_destroy(bin);
        bson_destroy(&doc);
        _mongocrypt_buffer_cleanup(&payload);
    }

    // Decryption key.
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);

    {
        _mongocrypt_buffer_t keyId;
        _mongocrypt_buffer_t key;
        _mongocrypt_buffer_copy_from_hex(&keyId, TEST_KEY_UUID_HEX);
        _mongocrypt_buffer_copy_from_hex(&key, TEST_KEY_HEX);
        _test_ctx_wrap_and_feed_key(ctx, &keyId, &key, status);
        _mongocrypt_buffer_cleanup(&key);
        _mongocrypt_buffer_cleanup(&keyId);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
    }

    // Value ready.
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);

    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));

        bson_t expect_bson;
        bson_init(&expect_bson);
        bson_value_t expect_value;
        _mongocrypt_buffer_t value_buf = {.data = (uint8_t *)TEST_PLAINTEXT, .len = TEST_PLAINTEXT_LEN};
        ASSERT(_mongocrypt_buffer_to_bson_value(&value_buf, BSON_TYPE_UTF8, &expect_value));
        ASSERT(bson_append_value(&expect_bson, "v", (int)strlen("v"), &expect_value));
        ASSERT(bson_compare(&out_bson, &expect_bson) == 0);
        bson_value_destroy(&expect_value);
        mongocrypt_binary_destroy(out);
        bson_destroy(&expect_bson);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
}

static void test_FLE2UnindexedEncryptedValueV2_encrypt(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_status_t *status = mongocrypt_status_new();

    _mongocrypt_buffer_t plaintext;
    _mongocrypt_buffer_t ciphertext;
    _mongocrypt_buffer_t key_uuid;
    _mongocrypt_buffer_t key;
    _mongocrypt_buffer_t prefix;
    _mongocrypt_buffer_t serialized_uev;

    ASSERT(_mongocrypt_buffer_copy_from_data_and_size(&plaintext, (const uint8_t *)TEST_PLAINTEXT, TEST_PLAINTEXT_LEN));

    /* Test encrypt/decrypt round trip */
    _mongocrypt_buffer_init(&ciphertext);
    _mongocrypt_buffer_copy_from_hex(&key_uuid, TEST_KEY_UUID_HEX);
    _mongocrypt_buffer_copy_from_hex(&key, TEST_KEY_HEX);

    bool res = mc_FLE2UnindexedEncryptedValueV2_encrypt(crypt->crypto,
                                                        &key_uuid,
                                                        BSON_TYPE_UTF8,
                                                        &plaintext,
                                                        &key,
                                                        &ciphertext,
                                                        status);
    ASSERT_OK_STATUS(res, status);

    // build the serialized UEV by combining the prefix and the ciphertext
    _mongocrypt_buffer_copy_from_hex(&prefix, TEST_PREFIX_HEX);
    _mongocrypt_buffer_t bufs[] = {prefix, ciphertext};
    ASSERT(_mongocrypt_buffer_concat(&serialized_uev, bufs, 2));

    // verify the serialized UEV decrypts to the same plaintext
    mc_FLE2UnindexedEncryptedValueV2_t *uev = mc_FLE2UnindexedEncryptedValueV2_new();

    ASSERT_OK_STATUS(mc_FLE2UnindexedEncryptedValueV2_parse(uev, &serialized_uev, status), status);
    const _mongocrypt_buffer_t *got = mc_FLE2UnindexedEncryptedValueV2_decrypt(crypt->crypto, uev, &key, status);
    ASSERT_OK_STATUS(got != NULL, status);
    ASSERT_CMPBUF(plaintext, *got);
    mc_FLE2UnindexedEncryptedValueV2_destroy(uev);

    _mongocrypt_buffer_cleanup(&serialized_uev);
    _mongocrypt_buffer_cleanup(&prefix);
    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&key);
    _mongocrypt_buffer_cleanup(&key_uuid);
    _mongocrypt_buffer_cleanup(&plaintext);
    mongocrypt_status_destroy(status);
    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_fle2_payload_uev_v2(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_FLE2UnindexedEncryptedValueV2_parse);
    INSTALL_TEST(test_FLE2UnindexedEncryptedValueV2_decrypt);
    INSTALL_TEST(test_FLE2UnindexedEncryptedValueV2_ctx_decrypt);
    INSTALL_TEST(test_FLE2UnindexedEncryptedValueV2_encrypt);
}
