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
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#define FOREACH_FIELD(F)                                                                                               \
    F(root)                                                                                                            \
    F(value)                                                                                                           \
    F(collectionsLevel1Token)                                                                                          \
    F(serverDataEncryptionLevel1Token)                                                                                 \
    F(ServerTokenDerivationLevel1Token)                                                                                \
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
    F(serverZerosEncryptionToken)                                                                                      \
    F(AnchorPaddingTokenRoot)                                                                                          \
    F(AnchorPaddingKeyToken)                                                                                           \
    F(AnchorPaddingValueToken)                                                                                         \
    F(EDCTextExactToken)                                                                                               \
    F(EDCTextSubstringToken)                                                                                           \
    F(EDCTextSuffixToken)                                                                                              \
    F(EDCTextPrefixToken)                                                                                              \
    F(ESCTextExactToken)                                                                                               \
    F(ESCTextSubstringToken)                                                                                           \
    F(ESCTextSuffixToken)                                                                                              \
    F(ESCTextPrefixToken)                                                                                              \
    F(ServerTextExactToken)                                                                                            \
    F(ServerTextSubstringToken)                                                                                        \
    F(ServerTextSuffixToken)                                                                                           \
    F(ServerTextPrefixToken)                                                                                           \
    F(EDCTextExactDerivedFromDataTokenAndContentionFactorToken)                                                        \
    F(EDCTextSubstringDerivedFromDataTokenAndContentionFactorToken)                                                    \
    F(EDCTextSuffixDerivedFromDataTokenAndContentionFactorToken)                                                       \
    F(EDCTextPrefixDerivedFromDataTokenAndContentionFactorToken)                                                       \
    F(ESCTextExactDerivedFromDataTokenAndContentionFactorToken)                                                        \
    F(ESCTextSubstringDerivedFromDataTokenAndContentionFactorToken)                                                    \
    F(ESCTextSuffixDerivedFromDataTokenAndContentionFactorToken)                                                       \
    F(ESCTextPrefixDerivedFromDataTokenAndContentionFactorToken)                                                       \
    F(ServerTextExactDerivedFromDataToken)                                                                             \
    F(ServerTextSubstringDerivedFromDataToken)                                                                         \
    F(ServerTextSuffixDerivedFromDataToken)                                                                            \
    F(ServerTextPrefixDerivedFromDataToken)

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
    mc_ServerTokenDerivationLevel1Token_t *ServerTokenDerivationLevel1Token =
        mc_ServerTokenDerivationLevel1Token_new(crypt->crypto, &test.root, status);
    ASSERT_OR_PRINT(ServerTokenDerivationLevel1Token, status);
    ASSERT_CMPBUF(*mc_ServerTokenDerivationLevel1Token_get(ServerTokenDerivationLevel1Token),
                  test.ServerTokenDerivationLevel1Token);

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

#define TEST_HELPER(Base, BaseSuffix, TokenSuffix, ExtraArgsToNew)                                                     \
    mc_##Base##TokenSuffix##_t *Base##TokenSuffix =                                                                    \
        mc_##Base##TokenSuffix##_new(crypt->crypto, Base##BaseSuffix, ExtraArgsToNew status);                          \
    ASSERT_OR_PRINT(Base##TokenSuffix, status);                                                                        \
    ASSERT_CMPBUF(*mc_##Base##TokenSuffix##_get(Base##TokenSuffix), test.Base##TokenSuffix)

#define COMMA ,

// (EDC|ESC|ECC)DerivedFromDataToken(AndContentionFactor)?
#define TEST_DERIVED(Name)                                                                                             \
    TEST_HELPER(Name, Token, DerivedFromDataToken, &test.value COMMA);                                                 \
    TEST_HELPER(Name, DerivedFromDataToken, DerivedFromDataTokenAndContentionFactor, test.contentionFactor COMMA)
    TEST_DERIVED(EDC);
    TEST_DERIVED(ESC);
    TEST_DERIVED(ECC);
#undef TEST_DERIVED

// (EDC|ESC)TwiceDerivedToken(Tag|Value)?
#define TEST_TWICE(Name, Suffix) TEST_HELPER(Name, DerivedFromDataTokenAndContentionFactor, TwiceDerived##Suffix, )
    TEST_TWICE(EDC, Token);
    TEST_TWICE(ESC, TagToken);
    TEST_TWICE(ESC, ValueToken);
#undef TEST_TWICE

    // ServerDerivedFromDataToken
    mc_ServerDerivedFromDataToken_t *serverDerivedFromDataToken =
        mc_ServerDerivedFromDataToken_new(crypt->crypto, ServerTokenDerivationLevel1Token, &test.value, status);
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

    // AnchorPaddingTokenRoot
    mc_AnchorPaddingTokenRoot_t *padding = mc_AnchorPaddingTokenRoot_new(crypt->crypto, ESCToken, status);
    ASSERT_OR_PRINT(padding, status);
    ASSERT_CMPBUF(*mc_AnchorPaddingTokenRoot_get(padding), test.AnchorPaddingTokenRoot);

    mc_AnchorPaddingKeyToken_t *paddingKey = mc_AnchorPaddingKeyToken_new(crypt->crypto, padding, status);
    ASSERT_OR_PRINT(paddingKey, status);
    ASSERT_CMPBUF(*mc_AnchorPaddingKeyToken_get(paddingKey), test.AnchorPaddingKeyToken);

    mc_AnchorPaddingValueToken_t *paddingValue = mc_AnchorPaddingValueToken_new(crypt->crypto, padding, status);
    ASSERT_OR_PRINT(paddingValue, status);
    ASSERT_CMPBUF(*mc_AnchorPaddingValueToken_get(paddingValue), test.AnchorPaddingValueToken);

#define TEST_TEXT(Name, Suffix) TEST_HELPER(Name, Token, Text##Suffix##Token, )
#define TEST_TEXT_EXTRA(Name, Suffix, BaseSuffix) TEST_HELPER(Name, BaseSuffix##Token, Text##Suffix##Token, )
#define TEST_TEXT_DERIVED_FROM_BOTH(Name)                                                                              \
    TEST_HELPER(Name,                                                                                                  \
                Token,                                                                                                 \
                DerivedFromDataTokenAndContentionFactorToken,                                                          \
                &test.value COMMA test.contentionFactor COMMA)
#define TEST_TEXT_DERIVED_FROM_DATA(Name) TEST_HELPER(Name, Token, DerivedFromDataToken, &test.value COMMA)

    TEST_TEXT(EDC, Exact);
    TEST_TEXT(EDC, Substring);
    TEST_TEXT(EDC, Suffix);
    TEST_TEXT(EDC, Prefix);

    TEST_TEXT(ESC, Exact);
    TEST_TEXT(ESC, Substring);
    TEST_TEXT(ESC, Suffix);
    TEST_TEXT(ESC, Prefix);

    TEST_TEXT_EXTRA(Server, Exact, TokenDerivationLevel1);
    TEST_TEXT_EXTRA(Server, Substring, TokenDerivationLevel1);
    TEST_TEXT_EXTRA(Server, Suffix, TokenDerivationLevel1);
    TEST_TEXT_EXTRA(Server, Prefix, TokenDerivationLevel1);

    TEST_TEXT_DERIVED_FROM_BOTH(EDCTextExact);
    TEST_TEXT_DERIVED_FROM_BOTH(EDCTextSubstring);
    TEST_TEXT_DERIVED_FROM_BOTH(EDCTextPrefix);
    TEST_TEXT_DERIVED_FROM_BOTH(EDCTextSuffix);

    TEST_TEXT_DERIVED_FROM_BOTH(ESCTextExact);
    TEST_TEXT_DERIVED_FROM_BOTH(ESCTextSubstring);
    TEST_TEXT_DERIVED_FROM_BOTH(ESCTextPrefix);
    TEST_TEXT_DERIVED_FROM_BOTH(ESCTextSuffix);

    TEST_TEXT_DERIVED_FROM_DATA(ServerTextExact);
    TEST_TEXT_DERIVED_FROM_DATA(ServerTextSubstring);
    TEST_TEXT_DERIVED_FROM_DATA(ServerTextPrefix);
    TEST_TEXT_DERIVED_FROM_DATA(ServerTextSuffix);

    // Done.
    mc_ServerTextPrefixDerivedFromDataToken_destroy(ServerTextPrefixDerivedFromDataToken);
    mc_ServerTextSuffixDerivedFromDataToken_destroy(ServerTextSuffixDerivedFromDataToken);
    mc_ServerTextSubstringDerivedFromDataToken_destroy(ServerTextSubstringDerivedFromDataToken);
    mc_ServerTextExactDerivedFromDataToken_destroy(ServerTextExactDerivedFromDataToken);
    mc_ESCTextPrefixDerivedFromDataTokenAndContentionFactorToken_destroy(
        ESCTextPrefixDerivedFromDataTokenAndContentionFactorToken);
    mc_ESCTextSuffixDerivedFromDataTokenAndContentionFactorToken_destroy(
        ESCTextSuffixDerivedFromDataTokenAndContentionFactorToken);
    mc_ESCTextSubstringDerivedFromDataTokenAndContentionFactorToken_destroy(
        ESCTextSubstringDerivedFromDataTokenAndContentionFactorToken);
    mc_ESCTextExactDerivedFromDataTokenAndContentionFactorToken_destroy(
        ESCTextExactDerivedFromDataTokenAndContentionFactorToken);
    mc_EDCTextPrefixDerivedFromDataTokenAndContentionFactorToken_destroy(
        EDCTextPrefixDerivedFromDataTokenAndContentionFactorToken);
    mc_EDCTextSuffixDerivedFromDataTokenAndContentionFactorToken_destroy(
        EDCTextSuffixDerivedFromDataTokenAndContentionFactorToken);
    mc_EDCTextSubstringDerivedFromDataTokenAndContentionFactorToken_destroy(
        EDCTextSubstringDerivedFromDataTokenAndContentionFactorToken);
    mc_EDCTextExactDerivedFromDataTokenAndContentionFactorToken_destroy(
        EDCTextExactDerivedFromDataTokenAndContentionFactorToken);
    mc_ServerTextPrefixToken_destroy(ServerTextPrefixToken);
    mc_ServerTextSuffixToken_destroy(ServerTextSuffixToken);
    mc_ServerTextSubstringToken_destroy(ServerTextSubstringToken);
    mc_ServerTextExactToken_destroy(ServerTextExactToken);
    mc_ESCTextPrefixToken_destroy(ESCTextPrefixToken);
    mc_ESCTextSuffixToken_destroy(ESCTextSuffixToken);
    mc_ESCTextSubstringToken_destroy(ESCTextSubstringToken);
    mc_ESCTextExactToken_destroy(ESCTextExactToken);
    mc_EDCTextPrefixToken_destroy(EDCTextPrefixToken);
    mc_EDCTextSuffixToken_destroy(EDCTextSuffixToken);
    mc_EDCTextSubstringToken_destroy(EDCTextSubstringToken);
    mc_EDCTextExactToken_destroy(EDCTextExactToken);
    mc_AnchorPaddingValueToken_destroy(paddingValue);
    mc_AnchorPaddingKeyToken_destroy(paddingKey);
    mc_AnchorPaddingTokenRoot_destroy(padding);
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
    mc_ServerTokenDerivationLevel1Token_destroy(ServerTokenDerivationLevel1Token);
    mc_ServerDataEncryptionLevel1Token_destroy(serverDataEncryptionLevel1Token);
    mc_CollectionsLevel1Token_destroy(collectionsLevel1Token);
    _mc_token_test_cleanup(&test);
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);

    TEST_PRINTF("Finished tests in %s\n", path);
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
    mc_ServerDataEncryptionLevel1Token_t *token1;
    mc_ServerDataEncryptionLevel1Token_t *token2;
    _mongocrypt_buffer_t test_input;
    _mongocrypt_buffer_t expected;

    _mongocrypt_buffer_copy_from_hex(&test_input, "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");

    /* Make a token from a raw buffer */
    token1 = mc_ServerDataEncryptionLevel1Token_new_from_buffer(&test_input);
    token2 = mc_ServerDataEncryptionLevel1Token_new_from_buffer_copy(&test_input);

    /* Assert new_from_buffer did not steal ownership. */
    ASSERT(test_input.owned);
    ASSERT(test_input.len == MONGOCRYPT_HMAC_SHA256_LEN);

    _mongocrypt_buffer_copy_from_hex(&expected, "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");

    ASSERT_CMPBUF(*mc_ServerDataEncryptionLevel1Token_get(token1), expected);
    ASSERT_CMPBUF(*mc_ServerDataEncryptionLevel1Token_get(token2), expected);

    /* Assert new_from_buffer references original buffer instead of a copy. */
    test_input.data[0] = '0';
    expected.data[0] = '0';
    ASSERT_CMPBUF(*mc_ServerDataEncryptionLevel1Token_get(token1), expected);

    // Assert new_from_buffer_copy references a new buffer.
    ASSERT_CMPUINT8(mc_ServerDataEncryptionLevel1Token_get(token2)->data[0], !=, expected.data[0]);

    _mongocrypt_buffer_cleanup(&test_input);
    _mongocrypt_buffer_cleanup(&expected);
    mc_ServerDataEncryptionLevel1Token_destroy(token1);
    mc_ServerDataEncryptionLevel1Token_destroy(token2);
}

void _mongocrypt_tester_install_mc_tokens(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_mc_tokens);
    INSTALL_TEST(_test_mc_tokens_error);
    INSTALL_TEST(_test_mc_tokens_raw_buffer);
}
