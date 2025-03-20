/*
 * Copyright 2025-present MongoDB, Inc.
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

#include "mc-fle2-find-text-payload-private.h"
#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#define VALIDATE_TOKEN_SET(p, e)                                                                                       \
    ASSERT_CMPBUF((p)->edcDerivedToken, (e)->edcDerivedToken);                                                         \
    ASSERT_CMPBUF((p)->escDerivedToken, (e)->escDerivedToken);                                                         \
    ASSERT_CMPBUF((p)->serverDerivedFromDataToken, (e)->serverDerivedFromDataToken)

static void _validate_parsed_payload(_mongocrypt_tester_t *tester,
                                     mc_FLE2FindTextPayload_t *expected,
                                     mc_FLE2FindTextPayload_t *parsed) {
    ASSERT(parsed->tokenSets.exact.set == expected->tokenSets.exact.set);
    ASSERT(parsed->tokenSets.substring.set == expected->tokenSets.substring.set);
    ASSERT(parsed->tokenSets.suffix.set == expected->tokenSets.suffix.set);
    ASSERT(parsed->tokenSets.prefix.set == expected->tokenSets.prefix.set);
    ASSERT(parsed->caseFold == expected->caseFold);
    ASSERT(parsed->diacriticFold == expected->diacriticFold);
    ASSERT(parsed->substringSpec.set == expected->substringSpec.set);
    ASSERT(parsed->suffixSpec.set == expected->suffixSpec.set);
    ASSERT(parsed->prefixSpec.set == expected->prefixSpec.set);

    if (parsed->tokenSets.exact.set) {
        VALIDATE_TOKEN_SET(&parsed->tokenSets.exact.value, &expected->tokenSets.exact.value);
    }
    if (parsed->tokenSets.substring.set) {
        VALIDATE_TOKEN_SET(&parsed->tokenSets.substring.value, &expected->tokenSets.substring.value);
    }
    if (parsed->tokenSets.suffix.set) {
        VALIDATE_TOKEN_SET(&parsed->tokenSets.suffix.value, &expected->tokenSets.suffix.value);
    }
    if (parsed->tokenSets.prefix.set) {
        VALIDATE_TOKEN_SET(&parsed->tokenSets.prefix.value, &expected->tokenSets.prefix.value);
    }

    if (parsed->substringSpec.set) {
        ASSERT_CMPUINT32(parsed->substringSpec.value.lb, ==, expected->substringSpec.value.lb);
        ASSERT_CMPUINT32(parsed->substringSpec.value.ub, ==, expected->substringSpec.value.ub);
        ASSERT_CMPUINT32(parsed->substringSpec.value.mlen, ==, expected->substringSpec.value.mlen);
    }
    if (parsed->suffixSpec.set) {
        ASSERT_CMPUINT32(parsed->suffixSpec.value.lb, ==, expected->suffixSpec.value.lb);
        ASSERT_CMPUINT32(parsed->suffixSpec.value.ub, ==, expected->suffixSpec.value.ub);
    }
    if (parsed->prefixSpec.set) {
        ASSERT_CMPUINT32(parsed->prefixSpec.value.lb, ==, expected->prefixSpec.value.lb);
        ASSERT_CMPUINT32(parsed->prefixSpec.value.ub, ==, expected->prefixSpec.value.ub);
    }
}

#undef VALIDATE_TOKEN_SET

static void
_do_roundtrip_test(_mongocrypt_tester_t *tester, mc_FLE2FindTextPayload_t *spec, const char *expectedFailMsg) {
    mongocrypt_status_t *status = mongocrypt_status_new();

    bson_t out_bson;
    bson_init(&out_bson);
    ASSERT(mc_FLE2FindTextPayload_serialize(spec, &out_bson));

    mc_FLE2FindTextPayload_t parsed;
    mc_FLE2FindTextPayload_init(&parsed);

    bool ret = mc_FLE2FindTextPayload_parse(&parsed, &out_bson, status);
    if (expectedFailMsg) {
        ASSERT_FAILS_STATUS(ret, status, expectedFailMsg);
    } else {
        ASSERT_OK_STATUS(ret, status);
        _validate_parsed_payload(tester, spec, &parsed);
    }

    mc_FLE2FindTextPayload_cleanup(&parsed);
    bson_destroy(&out_bson);
    mongocrypt_status_destroy(status);
}

static void _do_parse_error_test(_mongocrypt_tester_t *tester, bson_t *to_parse, const char *expectedFailMsg) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mc_FLE2FindTextPayload_t parsed;
    mc_FLE2FindTextPayload_init(&parsed);
    bool ret = mc_FLE2FindTextPayload_parse(&parsed, to_parse, status);
    ASSERT_FAILS_STATUS(ret, status, expectedFailMsg);
    mc_FLE2FindTextPayload_cleanup(&parsed);
    mongocrypt_status_destroy(status);
}

static const char *k_edcToken = "280edab4190763d1f4183d383f8830773859c3a74a13161094e6fd44e7390fed";
static const char *k_escToken = "c3c8980ed11e63ec199104bc9a0889322c9eb80d00eee0b5148dc83f7e78adb7";
static const char *k_svrToken = "8773322a2b9e6c08886db6bc65b46ffdd64651e8a49400a9e55ff5bc550d45bf";

// Tests mc_FLE2FindTextPayload_serialize() works correctly, and non-error cases
// for mc_FLE2FindTextPayload_parse().
static void _test_FLE2FindTextPayload_roundtrip(_mongocrypt_tester_t *tester) {
    // Test exact token set + prefix spec present
    {
        mc_FLE2FindTextPayload_t payload;
        mc_FLE2FindTextPayload_init(&payload);
        payload.tokenSets.exact.set = true;
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.exact.value.edcDerivedToken, k_edcToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.exact.value.escDerivedToken, k_escToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.exact.value.serverDerivedFromDataToken, k_svrToken);
        payload.caseFold = true;
        payload.diacriticFold = false;
        payload.maxContentionFactor = 43;
        payload.prefixSpec.set = true;
        payload.prefixSpec.value.lb = 2;
        payload.prefixSpec.value.ub = 20;
        _do_roundtrip_test(tester, &payload, NULL);
        mc_FLE2FindTextPayload_cleanup(&payload);
    }

    // Test substring token set + substring spec present
    {
        mc_FLE2FindTextPayload_t payload;
        mc_FLE2FindTextPayload_init(&payload);
        payload.tokenSets.substring.set = true;
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.substring.value.edcDerivedToken, k_edcToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.substring.value.escDerivedToken, k_escToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.substring.value.serverDerivedFromDataToken, k_svrToken);
        payload.caseFold = false;
        payload.diacriticFold = true;
        payload.maxContentionFactor = 12;
        payload.substringSpec.set = true;
        payload.substringSpec.value.lb = 3;
        payload.substringSpec.value.ub = 30;
        payload.substringSpec.value.mlen = 300;
        _do_roundtrip_test(tester, &payload, NULL);
        mc_FLE2FindTextPayload_cleanup(&payload);
    }

    // Test suffix token set + suffix & prefix specs present
    {
        mc_FLE2FindTextPayload_t payload;
        mc_FLE2FindTextPayload_init(&payload);
        payload.tokenSets.suffix.set = true;
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.suffix.value.edcDerivedToken, k_edcToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.suffix.value.escDerivedToken, k_escToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.suffix.value.serverDerivedFromDataToken, k_svrToken);
        payload.caseFold = true;
        payload.diacriticFold = true;
        payload.maxContentionFactor = 21;
        payload.suffixSpec.set = true;
        payload.suffixSpec.value.lb = 4;
        payload.suffixSpec.value.ub = 40;
        payload.prefixSpec.set = true;
        payload.prefixSpec.value.lb = 5;
        payload.prefixSpec.value.ub = 50;
        _do_roundtrip_test(tester, &payload, NULL);
        mc_FLE2FindTextPayload_cleanup(&payload);
    }

    // Test prefix token set + all specs present
    {
        mc_FLE2FindTextPayload_t payload;
        mc_FLE2FindTextPayload_init(&payload);
        payload.tokenSets.prefix.set = true;
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.prefix.value.edcDerivedToken, k_edcToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.prefix.value.escDerivedToken, k_escToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.prefix.value.serverDerivedFromDataToken, k_svrToken);
        payload.caseFold = false;
        payload.diacriticFold = false;
        payload.maxContentionFactor = 55;
        payload.substringSpec.set = true;
        payload.substringSpec.value.lb = 3;
        payload.substringSpec.value.ub = 30;
        payload.substringSpec.value.mlen = 300;
        payload.suffixSpec.set = true;
        payload.suffixSpec.value.lb = 4;
        payload.suffixSpec.value.ub = 40;
        payload.prefixSpec.set = true;
        payload.prefixSpec.value.lb = 5;
        payload.prefixSpec.value.ub = 50;
        _do_roundtrip_test(tester, &payload, NULL);
        mc_FLE2FindTextPayload_cleanup(&payload);
    }
}

#define INT64_JSON "{'$numberLong': '5'}"
#define TOKEN_JSON "{'$binary': 'abcd', '$type': '0'}"
#define BADTOKEN_JSON "{'$binary': 'abcd', '$type': '2'}"
#define D_JSON "'d': " TOKEN_JSON
#define S_JSON "'s': " TOKEN_JSON
#define L_JSON "'l': " TOKEN_JSON
#define TOKENSET_JSON "{" D_JSON ", " S_JSON ", " L_JSON "}"
#define TS_JSON "'ts':{'e':" TOKENSET_JSON "}"
#define CM_JSON "'cm':" INT64_JSON
#define CF_JSON "'cf':false"
#define DF_JSON "'df':true"

// Tests error cases for mc_FLE2FindTextPayload_parse().
static void _test_FLE2FindTextPayload_parse_errors(_mongocrypt_tester_t *tester) {
    // Test multiple optional fields present under ts is disallowed when parsing
    {
        mc_FLE2FindTextPayload_t payload;
        mc_FLE2FindTextPayload_init(&payload);
        payload.tokenSets.exact.set = true;
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.exact.value.edcDerivedToken, k_edcToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.exact.value.escDerivedToken, k_escToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.exact.value.serverDerivedFromDataToken, k_svrToken);
        payload.tokenSets.suffix.set = true;
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.suffix.value.edcDerivedToken, k_edcToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.suffix.value.escDerivedToken, k_escToken);
        _mongocrypt_buffer_copy_from_hex(&payload.tokenSets.suffix.value.serverDerivedFromDataToken, k_svrToken);
        _do_roundtrip_test(tester,
                           &payload,
                           "Error parsing TextSearchFindTokenSets: cannot have multiple optional fields present");
        mc_FLE2FindTextPayload_cleanup(&payload);
    }
    // Test empty ts object is disallowed when parsing
    {
        mc_FLE2FindTextPayload_t payload;
        mc_FLE2FindTextPayload_init(&payload);
        _do_roundtrip_test(tester,
                           &payload,
                           "Error parsing TextSearchFindTokenSets: exactly one optional field is required");
        mc_FLE2FindTextPayload_cleanup(&payload);
    }

    // Test missing required fields in top-level object
    {
        bson_t *no_ts = TMP_BSON("{%s, %s, %s}", CM_JSON, CF_JSON, DF_JSON);
        bson_t *no_cm = TMP_BSON("{%s, %s, %s}", TS_JSON, CF_JSON, DF_JSON);
        bson_t *no_cf = TMP_BSON("{%s, %s, %s}", TS_JSON, CM_JSON, DF_JSON);
        bson_t *no_df = TMP_BSON("{%s, %s, %s}", TS_JSON, CM_JSON, CF_JSON);
        _do_parse_error_test(tester, no_ts, "Missing required field 'ts'");
        _do_parse_error_test(tester, no_cm, "Missing required field 'cm'");
        _do_parse_error_test(tester, no_cf, "Missing required field 'cf'");
        _do_parse_error_test(tester, no_df, "Missing required field 'df'");
    }

    const char *all_required = TS_JSON ", " CM_JSON ", " CF_JSON ", " DF_JSON;
    const char *required_no_ts = CM_JSON ", " CF_JSON ", " DF_JSON;

    // Test missing required fields in token set
    {
        bson_t *no_e_d = TMP_BSON("{'ts': {'e': {%s, %s}}, %s}", S_JSON, L_JSON, required_no_ts);
        bson_t *no_e_s = TMP_BSON("{'ts': {'e': {%s, %s}}, %s}", D_JSON, L_JSON, required_no_ts);
        bson_t *no_e_l = TMP_BSON("{'ts': {'e': {%s, %s}}, %s}", S_JSON, D_JSON, required_no_ts);
        _do_parse_error_test(tester, no_e_d, "Missing required field 'd'");
        _do_parse_error_test(tester, no_e_s, "Missing required field 's'");
        _do_parse_error_test(tester, no_e_l, "Missing required field 'l'");
    }

    // Test invalid types in top-level object
    {
        bson_t *bad_ts = TMP_BSON("{'ts': 23, %s}", required_no_ts);
        bson_t *bad_cm = TMP_BSON("{'cm': 'foo', %s, %s, %s}", TS_JSON, CF_JSON, DF_JSON);
        bson_t *bad_cf = TMP_BSON("{'cf': 'foo', %s, %s, %s}", TS_JSON, CM_JSON, DF_JSON);
        bson_t *bad_df = TMP_BSON("{'df': 'foo', %s, %s, %s}", TS_JSON, CF_JSON, CM_JSON);
        bson_t *bad_ss = TMP_BSON("{'ss': 'foo', %s}", required_no_ts);
        bson_t *bad_fs = TMP_BSON("{'fs': 'foo', %s}", required_no_ts);
        bson_t *bad_ps = TMP_BSON("{'ps': 'foo', %s}", required_no_ts);
        _do_parse_error_test(tester, bad_ts, "expected to be a document");
        _do_parse_error_test(tester, bad_cm, "expected to be int64");
        _do_parse_error_test(tester, bad_cf, "expected to be boolean");
        _do_parse_error_test(tester, bad_df, "expected to be boolean");
        _do_parse_error_test(tester, bad_ss, "must be an iterator to a document");
        _do_parse_error_test(tester, bad_fs, "must be an iterator to a document");
        _do_parse_error_test(tester, bad_ps, "must be an iterator to a document");
    }

    // Test invalid types in ts object
    {
        bson_t *bad_e = TMP_BSON("{'ts': {'e': 23}, %s}", required_no_ts);
        bson_t *bad_s = TMP_BSON("{'ts': {'s': 23}, %s}", required_no_ts);
        bson_t *bad_u = TMP_BSON("{'ts': {'u': 23}, %s}", required_no_ts);
        bson_t *bad_p = TMP_BSON("{'ts': {'p': 23}, %s}", required_no_ts);
        _do_parse_error_test(tester, bad_e, "expected to be a document");
        _do_parse_error_test(tester, bad_s, "expected to be a document");
        _do_parse_error_test(tester, bad_u, "expected to be a document");
        _do_parse_error_test(tester, bad_p, "expected to be a document");
    }

    // Test invalid types in token set
    {
        bson_t *bad_d = TMP_BSON("{'ts': {'e': {'d': 23, %s, %s}}, %s}", S_JSON, L_JSON, required_no_ts);
        bson_t *bad_s = TMP_BSON("{'ts': {'e': {'s': 23, %s, %s}}, %s}", D_JSON, L_JSON, required_no_ts);
        bson_t *bad_l = TMP_BSON("{'ts': {'e': {'l': 23, %s, %s}}, %s}", S_JSON, D_JSON, required_no_ts);
        bson_t *bad_subtype =
            TMP_BSON("{'ts': {'e': {'d': " BADTOKEN_JSON ", %s, %s}}, %s}", S_JSON, L_JSON, required_no_ts);
        _do_parse_error_test(tester, bad_d, "expected to be bindata, got: INT32");
        _do_parse_error_test(tester, bad_s, "expected to be bindata, got: INT32");
        _do_parse_error_test(tester, bad_l, "expected to be bindata, got: INT32");
        _do_parse_error_test(tester, bad_subtype, "expected to be bindata subtype 0");
    }

    // Test unrecognized fields
    {
        bson_t *level1 = TMP_BSON("{'kk': 2, %s}", all_required);
        bson_t *level2 = TMP_BSON("{'ts': {'oo': 2}, %s}", required_no_ts);
        bson_t *level3 = TMP_BSON("{'ts': {'e': {%s, %s, %s, 'pp': 1}}, %s}", D_JSON, S_JSON, L_JSON, required_no_ts);
        _do_parse_error_test(tester, level1, "Unrecognized field 'kk'");
        _do_parse_error_test(tester, level2, "Unrecognized field 'oo'");
        _do_parse_error_test(tester, level3, "Unrecognized field 'pp'");
    }
}

void _mongocrypt_tester_install_fle2_payload_find_text(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_FLE2FindTextPayload_roundtrip);
    INSTALL_TEST(_test_FLE2FindTextPayload_parse_errors);
}
