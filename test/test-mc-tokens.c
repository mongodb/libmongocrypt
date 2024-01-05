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
#include "mc-tokens-private.h"
#include "test-mongocrypt.h"

#define FOREACH_FIELD(F)                                                                                               \
    F(root)                                                                                                            \
    F(value)                                                                                                           \
    F(collectionsLevel1Token)                                                                                          \
    F(serverDataEncryptionLevel1Token)                                                                                 \
    F(serverTokenDerivationLevel1Token)                                                                                \
    F(EDCToken)                                                                                                        \
    F(ESCToken)                                                                                                        \
    F(ECCToken)                                                                                                        \
    F(ECOCToken)                                                                                                       \
    F(EDCDerivedFromDataToken)                                                                                         \
    F(ESCDerivedFromDataToken)                                                                                         \
    F(ECCDerivedFromDataToken)                                                                                         \
    F(serverDerivedFromDataToken)                                                                                      \
    F(EDCDerivedFromDataTokenAndContentionFactor)                                                                      \
    F(ESCDerivedFromDataTokenAndContentionFactor)                                                                      \
    F(ECCDerivedFromDataTokenAndContentionFactor)                                                                      \
    F(EDCTwiceDerivedToken)                                                                                            \
    F(ESCTwiceDerivedTagToken)                                                                                         \
    F(ESCTwiceDerivedValueToken)                                                                                       \
    F(serverCountAndContentionFactorEncryptionToken)                                                                   \
    F(serverZerosEncryptionToken)

typedef struct {
#define DECLARE_FIELD(f) _mongocrypt_buffer_t f;
    FOREACH_FIELD(DECLARE_FIELD)
#undef DECLARE_FIELD
    uint64_t contentionFactor;
} _mc_token_test;

static void _mc_token_test_cleanup(_mc_token_test *test) {
#define CLEANUP_FIELD(f) _mongocrypt_buffer_cleanup(&test->f);
    FOREACH_FIELD(CLEANUP_FIELD)
#undef CLEANUP_FIELD
}

static void _mc_token_test_run(_mongocrypt_tester_t *tester, const char *path) {
    printf("Loading test from %s...\n", path);

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

    bool hasContentionFactor = false;
    _mc_token_test test = {{0}};
    bson_iter_t it;
    ASSERT(bson_iter_init(&it, &test_bson));
    while (bson_iter_next(&it)) {
        const char *field = bson_iter_key(&it);
        ASSERT(field);

#define PARSE_FIELD(f)                                                                                                 \
    if (!strcmp(field, #f)) {                                                                                          \
        ASSERT_OR_PRINT_MSG(!test.f.data, "Duplicate field '" #f "' in test");                                         \
        ASSERT(BSON_ITER_HOLDS_UTF8(&it));                                                                             \
        const char *value = bson_iter_utf8(&it, NULL);                                                                 \
        _mongocrypt_buffer_copy_from_hex(&test.f, value);                                                              \
        ASSERT(strlen(value) == (test.f.len * 2));                                                                     \
    } else
        FOREACH_FIELD(PARSE_FIELD)
#undef PARSE_FIELD
        /* else */
        if (!strcmp(field, "contentionFactor")) {
            ASSERT_OR_PRINT_MSG(!hasContentionFactor, "Duplicate field 'contentionFactor' in test");
            ASSERT(BSON_ITER_HOLDS_INT32(&it) || BSON_ITER_HOLDS_INT64(&it));
            test.contentionFactor = bson_iter_as_int64(&it);
            hasContentionFactor = true;
        } else {
            TEST_ERROR("Unknown field '%s'", field);
        }
    }

#define CHECK_FIELD(f) ASSERT_OR_PRINT_MSG(test.f.data, "Missing field '" #f "' in test");
    FOREACH_FIELD(CHECK_FIELD)
#undef CHECK_FIELD
    ASSERT_OR_PRINT_MSG(hasContentionFactor, "Missing field 'contentionFactor' in test");

    // Run the actual test.
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    // collectionsLevel1Token
    mc_CollectionsLevel1Token_t *collectionsLevel1Token =
        mc_CollectionsLevel1Token_new(crypt->crypto, &test.root, status);
    ASSERT_OR_PRINT(collectionsLevel1Token, status);
    ASSERT_CMPBUF(*mc_CollectionsLevel1Token_get(collectionsLevel1Token), test.collectionsLevel1Token);

    // ServerDataEncryptionLevel1Token
    mc_ServerDataEncryptionLevel1Token_t *serverDataEncryptionLevel1Token =
        mc_ServerDataEncryptionLevel1Token_new(crypt->crypto, &test.root, status);
    ASSERT_OR_PRINT(serverDataEncryptionLevel1Token, status);
    ASSERT_CMPBUF(*mc_ServerDataEncryptionLevel1Token_get(serverDataEncryptionLevel1Token),
                  test.serverDataEncryptionLevel1Token);

    // ServerTokenDerivationLevel1Token
    mc_ServerTokenDerivationLevel1Token_t *serverTokenDerivationLevel1Token =
        mc_ServerTokenDerivationLevel1Token_new(crypt->crypto, &test.root, status);
    ASSERT_OR_PRINT(serverTokenDerivationLevel1Token, status);
    ASSERT_CMPBUF(*mc_ServerTokenDerivationLevel1Token_get(serverTokenDerivationLevel1Token),
                  test.serverTokenDerivationLevel1Token);

// (EDC|ESC|ECC|ECOC)Token
#define TEST_COLL_TOKEN(Name)                                                                                          \
    mc_##Name##Token_t *Name##Token = mc_##Name##Token_new(crypt->crypto, collectionsLevel1Token, status);             \
    ASSERT_OR_PRINT(Name##Token, status);                                                                              \
    ASSERT_CMPBUF(*mc_##Name##Token_get(Name##Token), test.Name##Token);
    TEST_COLL_TOKEN(EDC)
    TEST_COLL_TOKEN(ESC)
    TEST_COLL_TOKEN(ECC)
    TEST_COLL_TOKEN(ECOC)
#undef TEST_COLL_TOKEN

// (EDC|ESC|ECC)DerivedFromDataToken(AndContentionFactor)?
#define TEST_DERIVED(Name)                                                                                             \
    mc_##Name##DerivedFromDataToken_t *Name##DerivedFromDataToken =                                                    \
        mc_##Name##DerivedFromDataToken_new(crypt->crypto, Name##Token, &test.value, status);                          \
    ASSERT_OR_PRINT(Name##DerivedFromDataToken, status);                                                               \
    ASSERT_CMPBUF(*mc_##Name##DerivedFromDataToken_get(Name##DerivedFromDataToken), test.Name##DerivedFromDataToken);  \
    mc_##Name##DerivedFromDataTokenAndContentionFactor_t *Name##DerivedFromDataTokenAndContentionFactor =              \
        mc_##Name##DerivedFromDataTokenAndContentionFactor_new(crypt->crypto,                                          \
                                                               Name##DerivedFromDataToken,                             \
                                                               test.contentionFactor,                                  \
                                                               status);                                                \
    ASSERT_OR_PRINT(Name##DerivedFromDataTokenAndContentionFactor, status);                                            \
    ASSERT_CMPBUF(                                                                                                     \
        *mc_##Name##DerivedFromDataTokenAndContentionFactor_get(Name##DerivedFromDataTokenAndContentionFactor),        \
        test.Name##DerivedFromDataTokenAndContentionFactor);
    TEST_DERIVED(EDC)
    TEST_DERIVED(ESC)
    TEST_DERIVED(ECC)
#undef TEST_DERIVED_FROM_DATA_TOKEN

// (EDC|ESC)TwiceDerivedToken(Tag|Value)?
#define TEST_TWICE(Name, Suffix)                                                                                       \
    mc_##Name##TwiceDerived##Suffix##_t *Name##TwiceDerived##Suffix =                                                  \
        mc_##Name##TwiceDerived##Suffix##_new(crypt->crypto, Name##DerivedFromDataTokenAndContentionFactor, status);   \
    ASSERT_OR_PRINT(Name##TwiceDerived##Suffix, status);                                                               \
    ASSERT_CMPBUF(*mc_##Name##TwiceDerived##Suffix##_get(Name##TwiceDerived##Suffix), test.Name##TwiceDerived##Suffix);
    TEST_TWICE(EDC, Token);
    TEST_TWICE(ESC, TagToken);
    TEST_TWICE(ESC, ValueToken);
#undef TEST_TWICE

    // ServerDerivedFromDataToken
    mc_ServerDerivedFromDataToken_t *serverDerivedFromDataToken =
        mc_ServerDerivedFromDataToken_new(crypt->crypto, serverTokenDerivationLevel1Token, &test.value, status);
    ASSERT_OR_PRINT(serverDerivedFromDataToken, status);
    ASSERT_CMPBUF(*mc_ServerDerivedFromDataToken_get(serverDerivedFromDataToken), test.serverDerivedFromDataToken);

    // ServerCountAndContentionFactorEncryptionToken
    mc_ServerCountAndContentionFactorEncryptionToken_t *serverCACFET =
        mc_ServerCountAndContentionFactorEncryptionToken_new(crypt->crypto, serverDerivedFromDataToken, status);
    ASSERT_OR_PRINT(serverCACFET, status);
    ASSERT_CMPBUF(*mc_ServerCountAndContentionFactorEncryptionToken_get(serverCACFET),
                  test.serverCountAndContentionFactorEncryptionToken);

    // ServerZerosEncryptionToken
    mc_ServerZerosEncryptionToken_t *serverZeros =
        mc_ServerZerosEncryptionToken_new(crypt->crypto, serverDerivedFromDataToken, status);
    ASSERT_OR_PRINT(serverZeros, status);
    ASSERT_CMPBUF(*mc_ServerZerosEncryptionToken_get(serverZeros), test.serverZerosEncryptionToken);

    // Done.
    mc_ServerZerosEncryptionToken_destroy(serverZeros);
    mc_ServerCountAndContentionFactorEncryptionToken_destroy(serverCACFET);
    mc_ServerDerivedFromDataToken_destroy(serverDerivedFromDataToken);
    mc_ESCTwiceDerivedValueToken_destroy(ESCTwiceDerivedValueToken);
    mc_ESCTwiceDerivedTagToken_destroy(ESCTwiceDerivedTagToken);
    mc_EDCTwiceDerivedToken_destroy(EDCTwiceDerivedToken);
    mc_ECCDerivedFromDataTokenAndContentionFactor_destroy(ECCDerivedFromDataTokenAndContentionFactor);
    mc_ESCDerivedFromDataTokenAndContentionFactor_destroy(ESCDerivedFromDataTokenAndContentionFactor);
    mc_EDCDerivedFromDataTokenAndContentionFactor_destroy(EDCDerivedFromDataTokenAndContentionFactor);
    mc_ECCDerivedFromDataToken_destroy(ECCDerivedFromDataToken);
    mc_ESCDerivedFromDataToken_destroy(ESCDerivedFromDataToken);
    mc_EDCDerivedFromDataToken_destroy(EDCDerivedFromDataToken);
    mc_ECOCToken_destroy(ECOCToken);
    mc_ECCToken_destroy(ECCToken);
    mc_ESCToken_destroy(ESCToken);
    mc_EDCToken_destroy(EDCToken);
    mc_ServerTokenDerivationLevel1Token_destroy(serverTokenDerivationLevel1Token);
    mc_ServerDataEncryptionLevel1Token_destroy(serverDataEncryptionLevel1Token);
    mc_CollectionsLevel1Token_destroy(collectionsLevel1Token);
    _mc_token_test_cleanup(&test);
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);

    printf("Finished tests in %s\n", path);
}

static void _test_mc_tokens(_mongocrypt_tester_t *tester) {
    _mc_token_test_run(tester, "test/data/tokens/mc.json");
    _mc_token_test_run(tester, "test/data/tokens/server.json");
}

static void _test_mc_tokens_error(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status;
    mongocrypt_t *crypt;
    _mongocrypt_buffer_t RootKey;

    status = mongocrypt_status_new();
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    /* RootKey is incorrect length. */
    _mongocrypt_buffer_copy_from_hex(&RootKey, "AAAA");

    mc_CollectionsLevel1Token_t *CollectionsLevel1Token =
        mc_CollectionsLevel1Token_new(crypt->crypto, &RootKey, status);
    ASSERT_FAILS_STATUS(CollectionsLevel1Token != NULL, status, "invalid hmac_sha_256 key length");

    mc_CollectionsLevel1Token_destroy(CollectionsLevel1Token);
    _mongocrypt_buffer_cleanup(&RootKey);
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
}

static void _test_mc_tokens_raw_buffer(_mongocrypt_tester_t *tester) {
    mc_ServerDataEncryptionLevel1Token_t *token;
    _mongocrypt_buffer_t test_input;
    _mongocrypt_buffer_t expected;

    _mongocrypt_buffer_copy_from_hex(&test_input, "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");

    /* Make a token from a raw buffer */
    token = mc_ServerDataEncryptionLevel1Token_new_from_buffer(&test_input);

    /* Assert new_from_buffer did not steal ownership. */
    ASSERT(test_input.owned);
    ASSERT(test_input.len == MONGOCRYPT_HMAC_SHA256_LEN);

    _mongocrypt_buffer_copy_from_hex(&expected, "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");

    ASSERT_CMPBUF(*mc_ServerDataEncryptionLevel1Token_get(token), expected);

    /* Assert new_from_buffer references original buffer instead of a copy. */
    test_input.data[0] = '0';
    expected.data[0] = '0';
    ASSERT_CMPBUF(*mc_ServerDataEncryptionLevel1Token_get(token), expected);

    _mongocrypt_buffer_cleanup(&test_input);
    _mongocrypt_buffer_cleanup(&expected);
    mc_ServerDataEncryptionLevel1Token_destroy(token);
}

void _mongocrypt_tester_install_mc_tokens(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_mc_tokens);
    INSTALL_TEST(_test_mc_tokens_error);
    INSTALL_TEST(_test_mc_tokens_raw_buffer);
}
