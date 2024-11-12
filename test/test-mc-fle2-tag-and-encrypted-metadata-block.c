#include "mc-fle2-tag-and-encrypted-metadata-block-private.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#define TEST_TAG_AND_ENCRYPTED_METADATA_BLOCK                                                                          \
    "34bc1b32ce6404f3e39c97fdb86b077d70c86896fa329faf3029a14012fe4b743d2267d98b888e9006c683039c1a1347baf18e50f02704b1" \
    "46bfc018cf41a55752815f53d5795c66ad0ed2f2bde7f6471da0b7effca4fe213695f2a16ab9be13"

static void _test_mc_FLE2TagAndEncryptedMetadataBlock_roundtrip(_mongocrypt_tester_t *tester) {
    _mongocrypt_buffer_t input;
    _mongocrypt_buffer_t expect_encryptedCount;
    _mongocrypt_buffer_t expect_tag;
    _mongocrypt_buffer_t expect_encryptedZeros;
    _mongocrypt_buffer_t output;
    mc_FLE2TagAndEncryptedMetadataBlock_t metadata;

    _mongocrypt_buffer_copy_from_hex(&expect_encryptedCount,
                                     "34bc1b32ce6404f3e39c97fdb86b077d70c86896fa329faf3029a14012fe4b74");
    _mongocrypt_buffer_copy_from_hex(&expect_tag, "3d2267d98b888e9006c683039c1a1347baf18e50f02704b146bfc018cf41a557");
    _mongocrypt_buffer_copy_from_hex(&expect_encryptedZeros,
                                     "52815f53d5795c66ad0ed2f2bde7f6471da0b7effca4fe213695f2a16ab9be13");

    _mongocrypt_buffer_copy_from_hex(&input, TEST_TAG_AND_ENCRYPTED_METADATA_BLOCK);

    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_FLE2TagAndEncryptedMetadataBlock_init(&metadata);

    // Parse into metadata struct
    ASSERT_OK_STATUS(mc_FLE2TagAndEncryptedMetadataBlock_parse(&metadata, &input, status), status);

    // Check values
    ASSERT_CMPBUF(expect_encryptedCount, metadata.encryptedCount);
    ASSERT_CMPBUF(expect_tag, metadata.tag);
    ASSERT_CMPBUF(expect_encryptedZeros, metadata.encryptedZeros);

    // Serialize back into buffer
    _mongocrypt_buffer_init_size(&output, input.len);
    ASSERT_OK_STATUS(mc_FLE2TagAndEncryptedMetadataBlock_serialize(&metadata, &output, status), status);

    // Check that unparsed input is the same as serialized output
    ASSERT_CMPBUF(input, output);

    mongocrypt_status_destroy(status);
    mc_FLE2TagAndEncryptedMetadataBlock_cleanup(&metadata);
    _mongocrypt_buffer_cleanup(&expect_encryptedCount);
    _mongocrypt_buffer_cleanup(&expect_tag);
    _mongocrypt_buffer_cleanup(&expect_encryptedZeros);
    _mongocrypt_buffer_cleanup(&input);
    _mongocrypt_buffer_cleanup(&output);
}

#undef TEST_TAG_AND_ENCRYPTED_METADATA_BLOCK

void _mongocrypt_tester_install_fle2_tag_and_encrypted_metadata_block(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_mc_FLE2TagAndEncryptedMetadataBlock_roundtrip);
}