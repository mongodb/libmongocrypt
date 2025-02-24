/*
 * Copyright 2022-present MongoDB, Inc.
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
#include "mc-fle2-payload-iev-private-v2.h"
#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

typedef enum { kTypeEquality, kTypeRange, kTypeText } _mc_fle2_iev_type;

typedef struct {
    _mc_fle2_iev_type type;
    _mongocrypt_buffer_t payload;
    _mongocrypt_buffer_t S_KeyId;
    _mongocrypt_buffer_t S_Key;
    _mongocrypt_buffer_t K_KeyId;
    _mongocrypt_buffer_t K_Key;
    uint8_t bson_value_type;
    _mongocrypt_buffer_t bson_value;
    uint32_t edge_count;
    uint32_t substr_tag_count;
    uint32_t suffix_tag_count;
    mc_FLE2TagAndEncryptedMetadataBlock_t *metadata;
} _mc_fle2_iev_v2_test;

#define kMetadataLen 96U
#define kMetadataFieldLen 32U
#define kMinServerEncryptedValueLen 17U // IV(16) + EncryptCTR(1byte)

static void _mc_fle2_iev_v2_test_destroy(_mc_fle2_iev_v2_test *test) {
    _mongocrypt_buffer_cleanup(&test->payload);
    _mongocrypt_buffer_cleanup(&test->S_KeyId);
    _mongocrypt_buffer_cleanup(&test->S_Key);
    _mongocrypt_buffer_cleanup(&test->K_KeyId);
    _mongocrypt_buffer_cleanup(&test->K_Key);
    _mongocrypt_buffer_cleanup(&test->bson_value);
    for (uint32_t i = 0; i < test->edge_count; ++i) {
        mc_FLE2TagAndEncryptedMetadataBlock_cleanup(&test->metadata[i]);
    }

    bson_free(test->metadata);
}

static _mongocrypt_buffer_t copy_buf(_mongocrypt_buffer_t *src) {
    _mongocrypt_buffer_t dst;
    _mongocrypt_buffer_init(&dst);
    _mongocrypt_buffer_copy_to(src, &dst);
    return dst;
}

// Fill out the fields manually with no checks, then serialize.
static void
_mc_fle2_iev_v2_test_serialize_payload(mongocrypt_t *crypt, _mc_fle2_iev_v2_test *test, _mongocrypt_buffer_t *payload) {
    mc_FLE2IndexedEncryptedValueV2_t *iev = mc_FLE2IndexedEncryptedValueV2_new();
    iev->type = test->type == kTypeEquality ? kFLE2IEVTypeEqualityV2
              : test->type == kTypeRange    ? kFLE2IEVTypeRangeV2
                                            : kFLE2IEVTypeText;
    iev->fle_blob_subtype = test->type == kTypeEquality ? MC_SUBTYPE_FLE2IndexedEqualityEncryptedValueV2
                          : test->type == kTypeRange    ? MC_SUBTYPE_FLE2IndexedRangeEncryptedValueV2
                                                        : MC_SUBTYPE_FLE2IndexedTextEncryptedValue;
    iev->bson_value_type = test->bson_value_type;
    iev->edge_count = test->edge_count;
    iev->substr_tag_count = test->substr_tag_count;
    iev->suffix_tag_count = test->suffix_tag_count;
    iev->S_KeyId = copy_buf(&test->S_KeyId);
    _mongocrypt_buffer_init(&iev->ServerEncryptedValue);

    // Encrypt the client value (bson_value) into the SEV
    // First, encrypt with K_Key -> CEV
    mongocrypt_status_t *status = mongocrypt_status_new();
    const _mongocrypt_value_encryption_algorithm_t *fle2v2aead = _mcFLE2v2AEADAlgorithm();
    const uint32_t ClientEncryptedValueLen = fle2v2aead->get_ciphertext_len(test->bson_value.len, status);
    ASSERT_OK_STATUS(ClientEncryptedValueLen, status);

    _mongocrypt_buffer_t clientEncryptedValue;
    _mongocrypt_buffer_init_size(&clientEncryptedValue, ClientEncryptedValueLen);

    _mongocrypt_buffer_t iv;
    _mongocrypt_buffer_init_size(&iv, MONGOCRYPT_IV_LEN);
    ASSERT_OK_STATUS(_mongocrypt_random(crypt->crypto, &iv, MONGOCRYPT_IV_LEN, status), status);

    uint32_t bytes_written = 0;
    ASSERT_OK_STATUS(fle2v2aead->do_encrypt(crypt->crypto,
                                            &iv,
                                            &test->K_KeyId,
                                            &test->K_Key,
                                            &test->bson_value,
                                            &clientEncryptedValue,
                                            &bytes_written,
                                            status),
                     status);
    ASSERT(bytes_written == ClientEncryptedValueLen);

    // Then, add K_Key_Id + CEV -> DSEV
    _mongocrypt_buffer_t decryptedServerEncryptedValue;
    _mongocrypt_buffer_init_size(&decryptedServerEncryptedValue, clientEncryptedValue.len + UUID_LEN);
    memcpy(decryptedServerEncryptedValue.data, test->K_KeyId.data, UUID_LEN);
    memcpy(decryptedServerEncryptedValue.data + UUID_LEN, clientEncryptedValue.data, clientEncryptedValue.len);
    // Finally, encrypt DSEV -> SEV
    /* Get the TokenKey from the last 32 bytes of S_Key */
    _mongocrypt_buffer_t TokenKey;
    ASSERT(_mongocrypt_buffer_from_subrange(&TokenKey,
                                            &test->S_Key,
                                            test->S_Key.len - MONGOCRYPT_TOKEN_KEY_LEN,
                                            MONGOCRYPT_TOKEN_KEY_LEN));

    /* Use TokenKey to create ServerDataEncryptionLevel1Token and encrypt
     * DSEV into ServerEncryptedValue */
    mc_ServerDataEncryptionLevel1Token_t *token =
        mc_ServerDataEncryptionLevel1Token_new(crypt->crypto, &TokenKey, status);
    ASSERT_OK_STATUS(token, status);

    const _mongocrypt_value_encryption_algorithm_t *fle2alg = _mcFLE2Algorithm();
    const uint32_t ServerEncryptedValueLen = fle2alg->get_ciphertext_len(decryptedServerEncryptedValue.len, status);
    ASSERT_OK_STATUS(ServerEncryptedValueLen, status);

    _mongocrypt_buffer_resize(&iev->ServerEncryptedValue, ServerEncryptedValueLen);
    bytes_written = 0;
    ASSERT_OK_STATUS(fle2alg->do_encrypt(crypt->crypto,
                                         &iv,
                                         NULL /* aad */,
                                         mc_ServerDataEncryptionLevel1Token_get(token),
                                         &decryptedServerEncryptedValue,
                                         &iev->ServerEncryptedValue,
                                         &bytes_written,
                                         status),
                     status);
    ASSERT(bytes_written == ServerEncryptedValueLen);

    // Finally, add metadata, and we have a complete IEV.
    iev->metadata = bson_malloc0(test->edge_count * sizeof(mc_FLE2TagAndEncryptedMetadataBlock_t));
    for (uint32_t i = 0; i < test->edge_count; i++) {
        _mongocrypt_buffer_t tmp_buf;
        _mongocrypt_buffer_init_size(&tmp_buf, kMetadataLen);
        memcpy(tmp_buf.data, test->metadata[i].encryptedCount.data, kMetadataFieldLen);
        memcpy(tmp_buf.data + kMetadataFieldLen, test->metadata[i].tag.data, kMetadataFieldLen);
        memcpy(tmp_buf.data + kMetadataFieldLen * 2, test->metadata[i].encryptedZeros.data, kMetadataFieldLen);

        ASSERT_OK_STATUS(mc_FLE2TagAndEncryptedMetadataBlock_parse(&iev->metadata[i], &tmp_buf, status), status);
        _mongocrypt_buffer_cleanup(&tmp_buf);
    }

    // Now serialize our IEV to the payload.
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_serialize(iev, payload, status), status);
    mongocrypt_status_destroy(status);
    _mongocrypt_buffer_cleanup(&clientEncryptedValue);
    _mongocrypt_buffer_cleanup(&iv);
    _mongocrypt_buffer_cleanup(&decryptedServerEncryptedValue);
    mc_ServerDataEncryptionLevel1Token_destroy(token);
    mc_FLE2IndexedEncryptedValueV2_destroy(iev);
}

static bool _mc_fle2_iev_v2_test_parse(_mc_fle2_iev_v2_test *test, bson_iter_t *iter) {
    bool hasType = false;

    while (bson_iter_next(iter)) {
        const char *field = bson_iter_key(iter);
        ASSERT(field);

#define HEXBUF_FIELD(Name)                                                                                             \
    if (!strcmp(field, #Name)) {                                                                                       \
        ASSERT_OR_PRINT_MSG(!test->Name.data, "Duplicate field '" #Name "' in test");                                  \
        ASSERT(BSON_ITER_HOLDS_UTF8(iter));                                                                            \
        const char *value = bson_iter_utf8(iter, NULL);                                                                \
        _mongocrypt_buffer_copy_from_hex(&test->Name, value);                                                          \
        ASSERT(strlen(value) == (test->Name.len * 2));                                                                 \
    } else
        HEXBUF_FIELD(payload)
        HEXBUF_FIELD(S_KeyId)
        HEXBUF_FIELD(S_Key)
        HEXBUF_FIELD(K_KeyId)
        HEXBUF_FIELD(K_Key)
        HEXBUF_FIELD(bson_value)
#undef HEXBUF_FIELD
        /* else */ if (!strcmp(field, "bson_value_type")) {
            ASSERT_OR_PRINT_MSG(!test->bson_value_type, "Duplicate field 'bson_value_type'");
            ASSERT(BSON_ITER_HOLDS_INT32(iter) || BSON_ITER_HOLDS_INT64(iter));
            int64_t value = bson_iter_as_int64(iter);
            ASSERT_OR_PRINT_MSG((value > 0) && (value < 128), "Field 'bson_value_type' must be 1..127");
            test->bson_value_type = (uint8_t)value;
        } else if (!strcmp(field, "substr_tag_count")) {
            ASSERT_OR_PRINT_MSG(!test->substr_tag_count, "Duplicate field 'substr_tag_count'");
            ASSERT(BSON_ITER_HOLDS_INT32(iter) || BSON_ITER_HOLDS_INT64(iter));
            int64_t value = bson_iter_as_int64(iter);
            ASSERT_OR_PRINT_MSG((value >= 0) && (value < UINT32_MAX), "Field 'substr_tag_count' must be 0..2^32-1");
            test->substr_tag_count = (uint32_t)value;
        } else if (!strcmp(field, "suffix_tag_count")) {
            ASSERT_OR_PRINT_MSG(!test->suffix_tag_count, "Duplicate field 'suffix_tag_count'");
            ASSERT(BSON_ITER_HOLDS_INT32(iter) || BSON_ITER_HOLDS_INT64(iter));
            int64_t value = bson_iter_as_int64(iter);
            ASSERT_OR_PRINT_MSG((value >= 0) && (value < UINT32_MAX), "Field 'suffix_tag_count' must be 0..2^32-1");
            test->suffix_tag_count = (uint32_t)value;
        } else if (!strcmp(field, "type")) {
            ASSERT_OR_PRINT_MSG(!hasType, "Duplicate field 'type'");
            ASSERT(BSON_ITER_HOLDS_UTF8(iter));
            const char *value = bson_iter_utf8(iter, NULL);
            if (!strcmp(value, "equality")) {
                test->type = kTypeEquality;
            } else if (!strcmp(value, "range")) {
                test->type = kTypeRange;
            } else if (!strcmp(value, "text")) {
                test->type = kTypeText;
            } else {
                TEST_ERROR("Unknown type '%s'", value);
            }
            hasType = true;
        } else if (!strcmp(field, "metadata")) {
            ASSERT_OR_PRINT_MSG(!test->metadata, "Duplicate field 'metadata'");

            // Use bson functions to loop through array
            ASSERT(BSON_ITER_HOLDS_ARRAY(iter));
            const uint8_t *metadata_array_data = NULL;
            uint32_t metadata_array_len = 0;
            bson_iter_array(iter, &metadata_array_len, &metadata_array_data);

            bson_t metadata_array;
            bson_iter_t metadata_array_iter;
            if (!bson_init_static(&metadata_array, metadata_array_data, metadata_array_len)
                || !bson_iter_init(&metadata_array_iter, &metadata_array)) {
                TEST_ERROR("Failed to initialize array iterator");
                return false;
            }

            // Count metadata blocks
            size_t metadata_count = 0;
            while (bson_iter_next(&metadata_array_iter)) {
                ASSERT(BSON_ITER_HOLDS_UTF8(&metadata_array_iter));
                metadata_count++;
            }

            // Allocate memory for the metadata array
            test->metadata = (mc_FLE2TagAndEncryptedMetadataBlock_t *)bson_malloc0(
                metadata_count * sizeof(mc_FLE2TagAndEncryptedMetadataBlock_t));
            if (!test->metadata) {
                TEST_ERROR("Failed to allocate memory for metadata array");
                return false;
            }

            // Reinitialize iter and parse each metadata block
            bson_iter_init(&metadata_array_iter, &metadata_array);
            uint32_t i = 0;
            while (bson_iter_next(&metadata_array_iter)) {
                ASSERT(BSON_ITER_HOLDS_UTF8(&metadata_array_iter));

                mongocrypt_status_t *tmp_status = mongocrypt_status_new();
                const char *value = bson_iter_utf8(&metadata_array_iter, NULL);

                _mongocrypt_buffer_t tmp_buf;
                _mongocrypt_buffer_copy_from_hex(&tmp_buf, value);

                ASSERT_OK_STATUS(mc_FLE2TagAndEncryptedMetadataBlock_parse(&test->metadata[i], &tmp_buf, tmp_status),
                                 tmp_status);

                _mongocrypt_buffer_cleanup(&tmp_buf);
                mongocrypt_status_destroy(tmp_status);
                i++;
            }

            test->edge_count = i;

        } else {
            TEST_ERROR("Unknown field '%s'", field);
        }
    }

#define CHECK_HAS(Name) ASSERT_OR_PRINT_MSG(test->Name.data, "Missing field '" #Name "'")
    CHECK_HAS(payload);
    CHECK_HAS(S_KeyId);
    CHECK_HAS(S_Key);
    CHECK_HAS(K_KeyId);
    CHECK_HAS(K_Key);
    CHECK_HAS(bson_value);
#undef CHECK_HAS
    ASSERT_OR_PRINT_MSG(hasType, "Missing field 'type'");
    ASSERT_OR_PRINT_MSG(test->bson_value_type, "Missing field 'bson_value_type'");

    return true;
}

static void _mc_fle2_iev_v2_test_run(mongocrypt_t *crypt, _mongocrypt_tester_t *tester, _mc_fle2_iev_v2_test *test) {
    mongocrypt_status_t *status = mongocrypt_status_new();

    mc_FLE2IndexedEncryptedValueV2_t *iev = mc_FLE2IndexedEncryptedValueV2_new();

    if (!test->payload.data) {
        // This is a self-test; i.e. we serialize the payload from the given fields, parse, and assert sameness.
        _mc_fle2_iev_v2_test_serialize_payload(crypt, test, &test->payload);
    }

    // Parse payload.
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_parse(iev, &test->payload, status), status);

    // Reserialize and assert that the result is the same as the initial input
    _mongocrypt_buffer_t serialized_buf;
    _mongocrypt_buffer_init_size(&serialized_buf, test->payload.len);
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_serialize(iev, &serialized_buf, status), status);
    ASSERT_CMPBUF(serialized_buf, test->payload);
    _mongocrypt_buffer_cleanup(&serialized_buf);

    // Validate S_KeyId as parsed.
    const _mongocrypt_buffer_t *S_KeyId = mc_FLE2IndexedEncryptedValueV2_get_S_KeyId(iev, status);
    ASSERT_OK_STATUS(S_KeyId, status);
    ASSERT_CMPBUF(*S_KeyId, test->S_KeyId);

    // Validate bson_value_type as parsed.
    bson_type_t bson_value_type = mc_FLE2IndexedEncryptedValueV2_get_bson_value_type(iev, status);
    ASSERT_OK_STATUS(bson_value_type, status);
    ASSERT_CMPINT(bson_value_type, ==, test->bson_value_type);

    // Decrypt ServerEncryptedValue.
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_add_S_Key(crypt->crypto, iev, &test->S_Key, status), status);

    // Validate K_KeyId as decrypted.
    const _mongocrypt_buffer_t *K_KeyId = mc_FLE2IndexedEncryptedValueV2_get_K_KeyId(iev, status);
    ASSERT_OK_STATUS(K_KeyId, status);
    ASSERT_CMPBUF(*K_KeyId, test->K_KeyId);

    // Decrypt ClientEncryptedValue.
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_add_K_Key(crypt->crypto, iev, &test->K_Key, status), status);

    // Validate decrypted value.
    const _mongocrypt_buffer_t *bson_value = mc_FLE2IndexedEncryptedValueV2_get_ClientValue(iev, status);
    ASSERT_OK_STATUS(bson_value, status);
    ASSERT_CMPBUF(*bson_value, test->bson_value);

    uint32_t edge_count = 1;
    if (test->type == kTypeRange || test->type == kTypeText) {
        // Validate edge count
        edge_count = mc_FLE2IndexedEncryptedValueV2_get_edge_count(iev, status);
        ASSERT_OK_STATUS(edge_count, status);
        ASSERT_CMPUINT32(edge_count, ==, test->edge_count);
    }

    uint32_t substr_tag_count = 0, suffix_tag_count = 0, prefix_tag_count = 0;
    if (test->type == kTypeText) {
        // Validate substr/suffix/prefix tag counts
        ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_get_substr_tag_count(iev, &substr_tag_count, status), status);
        ASSERT_CMPUINT32(substr_tag_count, ==, test->substr_tag_count);
        ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_get_suffix_tag_count(iev, &suffix_tag_count, status), status);
        ASSERT_CMPUINT32(suffix_tag_count, ==, test->suffix_tag_count);
        ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_get_prefix_tag_count(iev, &prefix_tag_count, status), status);
        ASSERT_CMPUINT32(prefix_tag_count, ==, test->edge_count - test->substr_tag_count - test->suffix_tag_count - 1);
    }

    // Validate edges/metadata
    mc_FLE2TagAndEncryptedMetadataBlock_t metadata;
    for (uint32_t i = 0; i < edge_count; ++i) {
        if (test->type == kTypeText) {
            if (i == 0) {
                ASSERT(mc_FLE2IndexedEncryptedValueV2_get_exact_metadata(iev, &metadata, status));
            } else if (i < substr_tag_count + 1) {
                ASSERT(mc_FLE2IndexedEncryptedValueV2_get_substr_metadata(iev, &metadata, i - 1, status));
            } else if (i < suffix_tag_count + substr_tag_count + 1) {
                ASSERT(mc_FLE2IndexedEncryptedValueV2_get_suffix_metadata(iev,
                                                                          &metadata,
                                                                          i - substr_tag_count - 1,
                                                                          status));
            } else {
                ASSERT(mc_FLE2IndexedEncryptedValueV2_get_prefix_metadata(iev,
                                                                          &metadata,
                                                                          i - substr_tag_count - suffix_tag_count - 1,
                                                                          status));
            }
        } else if (test->type == kTypeRange) {
            ASSERT(mc_FLE2IndexedEncryptedValueV2_get_edge(iev, &metadata, i, status));
        } else {
            ASSERT(mc_FLE2IndexedEncryptedValueV2_get_metadata(iev, &metadata, status));
        }
        ASSERT_CMPBUF(metadata.encryptedCount, test->metadata[i].encryptedCount);
        ASSERT_CMPBUF(metadata.tag, test->metadata[i].tag);
        ASSERT_CMPBUF(metadata.encryptedZeros, test->metadata[i].encryptedZeros);
    }

    // All done!
    mc_FLE2IndexedEncryptedValueV2_destroy(iev);
    mongocrypt_status_destroy(status);
}

// Synthesize documents using ctx-decrypt workflow.
static void _mc_fle2_iev_v2_test_explicit_ctx(_mongocrypt_tester_t *tester, _mc_fle2_iev_v2_test *test) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);

    {
        // {v: BinData(ENCRYPTED, payload)}
        bson_t doc;
        bson_init(&doc);
        ASSERT(bson_append_binary(&doc,
                                  "v",
                                  (int)strlen("v"),
                                  BSON_SUBTYPE_ENCRYPTED,
                                  test->payload.data,
                                  test->payload.len));
        mongocrypt_binary_t *bin = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(&doc), doc.len);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, bin), ctx);
        mongocrypt_binary_destroy(bin);
        bson_destroy(&doc);
    }

    // First we need an S_Key.
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);

    _test_ctx_wrap_and_feed_key(ctx, &test->S_KeyId, &test->S_Key, status);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    // Next we need an K_Key.
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);

    _test_ctx_wrap_and_feed_key(ctx, &test->K_KeyId, &test->K_Key, status);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    // Decryption ready.
    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);

    {
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));

        bson_t expect_bson;
        bson_init(&expect_bson);
        bson_value_t expect_value;
        ASSERT(_mongocrypt_buffer_to_bson_value(&test->bson_value, test->bson_value_type, &expect_value));
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

static void _mc_fle2_iev_v2_validate(_mongocrypt_tester_t *tester, _mc_fle2_iev_v2_test *test) {
    mongocrypt_status_t *status = mongocrypt_status_new();

    mc_FLE2IndexedEncryptedValueV2_t *iev = mc_FLE2IndexedEncryptedValueV2_new();

    // Parse payload.
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_parse(iev, &test->payload, status), status);

    // Assert valid IEV.
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_validate(iev, status), status);

    // Modify each value on the IEV to be invalid and assert failure, then change back to valid value.
    mc_fle_blob_subtype_t temp_fle_blob_subtype = iev->fle_blob_subtype;
    iev->fle_blob_subtype = MC_SUBTYPE_FLE2UnindexedEncryptedValueV2;
    ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
    iev->fle_blob_subtype = temp_fle_blob_subtype;

    uint8_t temp_bson_value_type = iev->bson_value_type;
    iev->bson_value_type = BSON_TYPE_ARRAY;
    ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
    iev->bson_value_type = temp_bson_value_type;

    uint32_t temp_edge_count = iev->edge_count;
    iev->edge_count = 0;
    ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
    iev->edge_count = temp_edge_count;
    if (test->type == kTypeEquality) {
        iev->edge_count = 5;
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        iev->edge_count = temp_edge_count;
    } else if (test->type == kTypeText) {
        uint32_t temp_substr_count = iev->substr_tag_count;
        uint32_t temp_suffix_count = iev->suffix_tag_count;

        iev->substr_tag_count = iev->edge_count;
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        iev->substr_tag_count = temp_substr_count;

        iev->suffix_tag_count = iev->edge_count;
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        iev->suffix_tag_count = temp_suffix_count;
    }

    _mongocrypt_buffer_resize(&iev->ServerEncryptedValue, kMinServerEncryptedValueLen - 1);
    ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
    _mongocrypt_buffer_resize(&iev->ServerEncryptedValue, kMinServerEncryptedValueLen);

    _mongocrypt_buffer_resize(&iev->S_KeyId, UUID_LEN - 1);
    ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
    _mongocrypt_buffer_resize(&iev->S_KeyId, UUID_LEN);

    bool temp_CVD = iev->ClientValueDecoded;
    bool temp_CEVD = iev->ClientEncryptedValueDecoded;
    iev->ClientValueDecoded = true;
    iev->ClientEncryptedValueDecoded = false;
    ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
    iev->ClientValueDecoded = false;
    _mongocrypt_status_reset(status);
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_validate(iev, status), status);
    iev->ClientValueDecoded = temp_CVD;
    iev->ClientEncryptedValueDecoded = temp_CEVD;

    if (iev->ClientEncryptedValueDecoded) {
        uint32_t temp_DSEV_len = iev->DecryptedServerEncryptedValue.len;
        _mongocrypt_buffer_resize(&iev->DecryptedServerEncryptedValue, temp_DSEV_len - 1);
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        _mongocrypt_buffer_resize(&iev->DecryptedServerEncryptedValue, temp_DSEV_len);

        uint32_t temp_CEV_len = iev->ClientEncryptedValue.len;
        _mongocrypt_buffer_resize(&iev->ClientEncryptedValue, temp_CEV_len - 1);
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        _mongocrypt_buffer_resize(&iev->ClientEncryptedValue, temp_CEV_len);

        _mongocrypt_buffer_resize(&iev->K_KeyId, UUID_LEN - 1);
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        _mongocrypt_buffer_resize(&iev->K_KeyId, UUID_LEN);
    }

    if (iev->ClientValueDecoded) {
        uint32_t temp_CV_len = iev->ClientValue.len;
        _mongocrypt_buffer_resize(&iev->ClientValue, temp_CV_len - 1);
        ASSERT(!mc_FLE2IndexedEncryptedValueV2_validate(iev, status));
        _mongocrypt_buffer_resize(&iev->ClientValue, temp_CV_len);
    }

    // IEV should still be valid.
    _mongocrypt_status_reset(status);
    ASSERT_OK_STATUS(mc_FLE2IndexedEncryptedValueV2_validate(iev, status), status);

    mc_FLE2IndexedEncryptedValueV2_destroy(iev);
    mongocrypt_status_destroy(status);
}

static void test_fle2_iev_v2_test(mongocrypt_t *crypt, _mongocrypt_tester_t *tester, const char *path) {
    TEST_PRINTF("Loading test from %s...\n", path);

    mongocrypt_binary_t *test_bin = TEST_FILE(path);
    if (!test_bin) {
        TEST_ERROR("Failed loading test data file '%s'\n", path);
    }
    if (test_bin->len == 5) {
        TEST_ERROR("Invalid JSON in file '%s'\n", path);
    }

    bson_t test_bson;
    ASSERT(bson_init_static(&test_bson, test_bin->data, test_bin->len));
    ASSERT(bson_validate(&test_bson, BSON_VALIDATE_NONE, NULL));

    _mc_fle2_iev_v2_test test = {.payload = {0}};
    bson_iter_t iter;
    ASSERT(bson_iter_init(&iter, &test_bson));
    ASSERT(_mc_fle2_iev_v2_test_parse(&test, &iter));
    // Run once with given payload, then run with empty payload (self-test).
    _mc_fle2_iev_v2_test_run(crypt, tester, &test);
    _mongocrypt_buffer_cleanup(&test.payload);
    test.payload.data = NULL;
    _mc_fle2_iev_v2_test_run(crypt, tester, &test);

    _mc_fle2_iev_v2_test_explicit_ctx(tester, &test);
    _mc_fle2_iev_v2_validate(tester, &test);
    _mc_fle2_iev_v2_test_destroy(&test);
}

static void test_fle2_iev_v2(_mongocrypt_tester_t *tester) {
    if (!_aes_ctr_is_supported_by_os) {
        TEST_PRINTF("Common Crypto with no CTR support detected. Skipping.");
        return;
    }
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    // Produced by Server test: (FLECrudTest, insertOneV2)
    test_fle2_iev_v2_test(crypt, tester, "test/data/iev-v2/FLECrudTest-insertOneV2.json");
    // Produced by Server test: (FLECrudTest, insertOneRangeV2)
    test_fle2_iev_v2_test(crypt, tester, "test/data/iev-v2/FLECrudTest-insertOneRangeV2.json");
    // Fields are modified from insertOneRangeV2.json, payload was produced by _mc_fle2_iev_v2_test_serialize_payload in
    // this test
    test_fle2_iev_v2_test(crypt, tester, "test/data/iev-v2/FLECrudTest-insertOneText.json");
    // Fields are modified from insertOneText.json, payload was produced by _mc_fle2_iev_v2_test_serialize_payload in
    // this test
    test_fle2_iev_v2_test(crypt, tester, "test/data/iev-v2/FLECrudTest-insertOneTextLarge.json");
    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_fle2_iev_v2_payloads(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_fle2_iev_v2);
}
