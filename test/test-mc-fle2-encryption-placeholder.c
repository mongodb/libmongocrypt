/*
 * Copyright 2024-present MongoDB, Inc.
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

#include <mc-fle2-encryption-placeholder-private.h>

#include "mongocrypt-private.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

#define RAW_STRING(...) #__VA_ARGS__

static void _test_FLE2EncryptionPlaceholder_parse(_mongocrypt_tester_t *tester) {
    mc_FLE2EncryptionPlaceholder_t placeholder;
    bson_t as_bson;
    mongocrypt_status_t *status;
    _mongocrypt_buffer_t buf;

    status = mongocrypt_status_new();
    _mongocrypt_buffer_copy_from_hex(&buf,
                                     "03610000001074000100000010610002000000056b690010000000041234567812349876"
                                     "1234123456789012056b75001000000004abcdefab123498761234123456789012027600"
                                     "0900000076616c75653132330012636d00000000000000000000");
    ASSERT(bson_init_static(&as_bson, buf.data + 1, buf.len - 1));
    mc_FLE2EncryptionPlaceholder_init(&placeholder);
    ASSERT_OK_STATUS(mc_FLE2EncryptionPlaceholder_parse(&placeholder, &as_bson, status), status);

    ASSERT(placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT);
    ASSERT(placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_EQUALITY);
    ASSERT(BSON_ITER_HOLDS_UTF8(&placeholder.v_iter));
    ASSERT_STREQUAL(bson_iter_utf8(&placeholder.v_iter, NULL), "value123");

    _mongocrypt_buffer_t expect_index_key_id;
    _mongocrypt_buffer_copy_from_hex(&expect_index_key_id, "12345678123498761234123456789012");
    ASSERT_CMPBUF(placeholder.index_key_id, expect_index_key_id);
    _mongocrypt_buffer_cleanup(&expect_index_key_id);

    _mongocrypt_buffer_t expect_user_key_id;
    _mongocrypt_buffer_copy_from_hex(&expect_user_key_id, "abcdefab123498761234123456789012");
    ASSERT_CMPBUF(placeholder.user_key_id, expect_user_key_id);
    _mongocrypt_buffer_cleanup(&expect_user_key_id);

    ASSERT(placeholder.maxContentionFactor == 0);

    mc_FLE2EncryptionPlaceholder_cleanup(&placeholder);
    _mongocrypt_buffer_cleanup(&buf);
    mongocrypt_status_destroy(status);
}

static void _test_FLE2EncryptionPlaceholder_range_parse(_mongocrypt_tester_t *tester) {
    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT.
    {
        mc_FLE2EncryptionPlaceholder_t placeholder;
        bson_t as_bson;
        mongocrypt_status_t *status;
        _mongocrypt_buffer_t buf;

        status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&buf,
                                         "037d0000001074000100000010610003000000056b690010000000041234567812349"
                                         "8761234123456789012056b75001000000004abcdefab123498761234123456789012"
                                         "0376001e00000010760040e20100106d696e0000000000106d61780087d6120000126"
                                         "36d000000000000000000127300010000000000000000");
        ASSERT(bson_init_static(&as_bson, buf.data + 1, buf.len - 1));
        mc_FLE2EncryptionPlaceholder_init(&placeholder);
        ASSERT_OK_STATUS(mc_FLE2EncryptionPlaceholder_parse(&placeholder, &as_bson, status), status);

        ASSERT(placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT);
        ASSERT(placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_RANGE);

        _mongocrypt_buffer_t expect_index_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_index_key_id, "12345678123498761234123456789012");
        ASSERT_CMPBUF(placeholder.index_key_id, expect_index_key_id);
        _mongocrypt_buffer_cleanup(&expect_index_key_id);

        _mongocrypt_buffer_t expect_user_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_user_key_id, "abcdefab123498761234123456789012");
        ASSERT_CMPBUF(placeholder.user_key_id, expect_user_key_id);
        _mongocrypt_buffer_cleanup(&expect_user_key_id);

        ASSERT_CMPINT64(placeholder.sparsity, ==, 1);

        // Parse FLE2RangeInsertSpec.
        {
            mc_FLE2RangeInsertSpec_t spec;

            ASSERT_OK_STATUS(mc_FLE2RangeInsertSpec_parse(&spec, &placeholder.v_iter, status), status);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.v));
            ASSERT_CMPINT32(bson_iter_int32(&spec.v), ==, 123456);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.min));
            ASSERT_CMPINT32(bson_iter_int32(&spec.min), ==, 0);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.max));
            ASSERT_CMPINT32(bson_iter_int32(&spec.max), ==, 1234567);
        }

        mc_FLE2EncryptionPlaceholder_cleanup(&placeholder);
        _mongocrypt_buffer_cleanup(&buf);
        mongocrypt_status_destroy(status);
    }

    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND.
    {
        mc_FLE2EncryptionPlaceholder_t placeholder;
        bson_t as_bson;
        mongocrypt_status_t *status;
        _mongocrypt_buffer_t buf;

        status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&buf,
                                         "03ec0000001074000200000010610003000000056b690010000000041234567812349"
                                         "8761234123456789012056b75001000000004abcdefab123498761234123456789012"
                                         "0376008d000000036564676573496e666f005b000000106c6f776572426f756e64000"
                                         "0000000086c62496e636c756465640001107570706572426f756e640087d612000875"
                                         "62496e636c75646564000110696e6465784d696e000000000010696e6465784d61780"
                                         "087d6120000107061796c6f6164496400d20400001066697273744f70657261746f72"
                                         "00010000000012636d000000000000000000127300010000000000000000");
        ASSERT(bson_init_static(&as_bson, buf.data + 1, buf.len - 1));
        mc_FLE2EncryptionPlaceholder_init(&placeholder);
        ASSERT_OK_STATUS(mc_FLE2EncryptionPlaceholder_parse(&placeholder, &as_bson, status), status);

        ASSERT(placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND);
        ASSERT(placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_RANGE);

        _mongocrypt_buffer_t expect_index_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_index_key_id, "12345678123498761234123456789012");
        ASSERT_CMPBUF(placeholder.index_key_id, expect_index_key_id);
        _mongocrypt_buffer_cleanup(&expect_index_key_id);

        _mongocrypt_buffer_t expect_user_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_user_key_id, "abcdefab123498761234123456789012");
        ASSERT_CMPBUF(placeholder.user_key_id, expect_user_key_id);
        _mongocrypt_buffer_cleanup(&expect_user_key_id);

        ASSERT_CMPINT64(placeholder.sparsity, ==, 1);

        // Parse FLE2RangeFindSpec.
        {
            mc_FLE2RangeFindSpec_t spec;

            ASSERT_OK_STATUS(mc_FLE2RangeFindSpec_parse(&spec, &placeholder.v_iter, status), status);

            ASSERT(spec.edgesInfo.set);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.edgesInfo.value.lowerBound));
            ASSERT_CMPINT32(bson_iter_int32(&spec.edgesInfo.value.lowerBound), ==, 0);
            ASSERT(spec.edgesInfo.value.lbIncluded);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.edgesInfo.value.upperBound));
            ASSERT_CMPINT32(bson_iter_int32(&spec.edgesInfo.value.upperBound), ==, 1234567);
            ASSERT(spec.edgesInfo.value.ubIncluded);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.edgesInfo.value.indexMin));
            ASSERT_CMPINT32(bson_iter_int32(&spec.edgesInfo.value.indexMin), ==, 0);
            ASSERT(spec.edgesInfo.value.ubIncluded);

            ASSERT(BSON_ITER_HOLDS_INT32(&spec.edgesInfo.value.indexMax));
            ASSERT_CMPINT32(bson_iter_int32(&spec.edgesInfo.value.indexMax), ==, 1234567);
            ASSERT(spec.edgesInfo.value.ubIncluded);

            ASSERT_CMPINT32(spec.payloadId, ==, 1234);

            ASSERT_CMPINT(spec.firstOperator, ==, FLE2RangeOperator_kGt);
            ASSERT_CMPINT(spec.secondOperator, ==, FLE2RangeOperator_kNone);
        }

        mc_FLE2EncryptionPlaceholder_cleanup(&placeholder);
        _mongocrypt_buffer_cleanup(&buf);
        mongocrypt_status_destroy(status);
    }

    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND with precision.
    {
        mc_FLE2EncryptionPlaceholder_t placeholder;
        bson_t as_bson;
        mongocrypt_status_t *status;
        _mongocrypt_buffer_t buf;

        status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&buf,
                                         "030b0100001074000200000010610003000000056b690010000000041234567812349"
                                         "8761234123456789012056b75001000000004abcdefab123498761234123456789012"
                                         "037600ac000000036564676573496e666f007a000000016c6f776572426f756e64000"
                                         "000000000000000086c62496e636c756465640001017570706572426f756e64000000"
                                         "000000006940087562496e636c75646564000110707265636973696f6e00020000000"
                                         "1696e6465784d696e00000000000000000001696e6465784d61780000000000000069"
                                         "4000107061796c6f6164496400d20400001066697273744f70657261746f720001000"
                                         "0000012636d000000000000000000127300010000000000000000");
        ASSERT(bson_init_static(&as_bson, buf.data + 1, buf.len - 1));
        mc_FLE2EncryptionPlaceholder_init(&placeholder);
        ASSERT_OK_STATUS(mc_FLE2EncryptionPlaceholder_parse(&placeholder, &as_bson, status), status);

        ASSERT(placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND);
        ASSERT(placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_RANGE);

        _mongocrypt_buffer_t expect_index_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_index_key_id, "12345678123498761234123456789012");
        ASSERT_CMPBUF(placeholder.index_key_id, expect_index_key_id);
        _mongocrypt_buffer_cleanup(&expect_index_key_id);

        _mongocrypt_buffer_t expect_user_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_user_key_id, "abcdefab123498761234123456789012");
        ASSERT_CMPBUF(placeholder.user_key_id, expect_user_key_id);
        _mongocrypt_buffer_cleanup(&expect_user_key_id);

        ASSERT_CMPINT64(placeholder.sparsity, ==, 1);

        // Parse FLE2RangeFindSpec.
        {
            mc_FLE2RangeFindSpec_t spec;

            ASSERT_OK_STATUS(mc_FLE2RangeFindSpec_parse(&spec, &placeholder.v_iter, status), status);

            ASSERT(spec.edgesInfo.set);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.edgesInfo.value.lowerBound));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.edgesInfo.value.lowerBound), ==, 0.0);
            ASSERT(spec.edgesInfo.value.lbIncluded);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.edgesInfo.value.upperBound));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.edgesInfo.value.upperBound), ==, 200.0);
            ASSERT(spec.edgesInfo.value.ubIncluded);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.edgesInfo.value.indexMin));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.edgesInfo.value.indexMin), ==, 0);
            ASSERT(spec.edgesInfo.value.ubIncluded);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.edgesInfo.value.indexMax));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.edgesInfo.value.indexMax), ==, 200.0);
            ASSERT(spec.edgesInfo.value.ubIncluded);

            ASSERT_CMPDOUBLE(spec.payloadId, ==, 1234);

            ASSERT_CMPINT(spec.firstOperator, ==, FLE2RangeOperator_kGt);
            ASSERT(spec.edgesInfo.value.precision.set);
            ASSERT_CMPUINT32(spec.edgesInfo.value.precision.value, ==, 2);
        }

        mc_FLE2EncryptionPlaceholder_cleanup(&placeholder);
        _mongocrypt_buffer_cleanup(&buf);
        mongocrypt_status_destroy(status);
    }

    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT with precision.
    {
        mc_FLE2EncryptionPlaceholder_t placeholder;
        bson_t as_bson;
        mongocrypt_status_t *status;
        _mongocrypt_buffer_t buf;

        status = mongocrypt_status_new();
        _mongocrypt_buffer_copy_from_hex(&buf,
                                         "03980000001074000100000010610003000000056b690010000000041234567812349"
                                         "8761234123456789012056b75001000000004abcdefab123498761234123456789012"
                                         "0376003900000001760077be9f1a2fdd5e40016d696e000000000000000000016d617"
                                         "800000000000000694010707265636973696f6e00020000000012636d000000000000"
                                         "000000127300010000000000000000");
        ASSERT(bson_init_static(&as_bson, buf.data + 1, buf.len - 1));
        mc_FLE2EncryptionPlaceholder_init(&placeholder);
        ASSERT_OK_STATUS(mc_FLE2EncryptionPlaceholder_parse(&placeholder, &as_bson, status), status);

        ASSERT(placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT);
        ASSERT(placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_RANGE);

        _mongocrypt_buffer_t expect_index_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_index_key_id, "12345678123498761234123456789012");
        ASSERT_CMPBUF(placeholder.index_key_id, expect_index_key_id);
        _mongocrypt_buffer_cleanup(&expect_index_key_id);

        _mongocrypt_buffer_t expect_user_key_id;
        _mongocrypt_buffer_copy_from_hex(&expect_user_key_id, "abcdefab123498761234123456789012");
        ASSERT_CMPBUF(placeholder.user_key_id, expect_user_key_id);
        _mongocrypt_buffer_cleanup(&expect_user_key_id);

        ASSERT_CMPINT64(placeholder.sparsity, ==, 1);

        // Parse FLE2RangeInsertSpec.
        {
            mc_FLE2RangeInsertSpec_t spec;

            ASSERT_OK_STATUS(mc_FLE2RangeInsertSpec_parse(&spec, &placeholder.v_iter, status), status);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.v));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.v), ==, 123.456);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.min));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.min), ==, 0.0);

            ASSERT(BSON_ITER_HOLDS_DOUBLE(&spec.max));
            ASSERT_CMPDOUBLE(bson_iter_double(&spec.max), ==, 200.0);

            ASSERT(spec.precision.set);
            ASSERT_CMPUINT32(spec.precision.value, ==, 2);
        }

        mc_FLE2EncryptionPlaceholder_cleanup(&placeholder);
        _mongocrypt_buffer_cleanup(&buf);
        mongocrypt_status_destroy(status);
    }
}

static bool _parse_text_search_spec_from_placeholder(_mongocrypt_tester_t *tester,
                                                     const char *spec_json_in,
                                                     mc_FLE2TextSearchInsertSpec_t *spec_out,
                                                     mongocrypt_status_t *status_out) {
#define PLACEHOLDER_TEMPLATE                                                                                           \
    RAW_STRING({                                                                                                       \
        "t" : {"$numberInt" : "1"},                                                                                    \
        "a" : {"$numberInt" : "4"},                                                                                    \
        "ki" : {"$binary" : {"base64" : "EjRWeBI0mHYSNBI0VniQEg==", "subType" : "04"}},                                \
        "ku" : {"$binary" : {"base64" : "q83vqxI0mHYSNBI0VniQEg==", "subType" : "04"}},                                \
        "v" : MC_BSON,                                                                                                 \
        "cm" : {"$numberLong" : "7"}                                                                                   \
    })

    bson_t *const as_bson = TMP_BSONF(PLACEHOLDER_TEMPLATE, TMP_BSON_STR(spec_json_in));

    mc_FLE2EncryptionPlaceholder_t placeholder;
    mc_FLE2EncryptionPlaceholder_init(&placeholder);
    ASSERT_OK_STATUS(mc_FLE2EncryptionPlaceholder_parse(&placeholder, as_bson, status_out), status_out);

    ASSERT(placeholder.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT);
    ASSERT(placeholder.algorithm == MONGOCRYPT_FLE2_ALGORITHM_TEXT_SEARCH);

    _mongocrypt_buffer_t expect_index_key_id;
    _mongocrypt_buffer_copy_from_hex(&expect_index_key_id, "12345678123498761234123456789012");
    ASSERT_CMPBUF(placeholder.index_key_id, expect_index_key_id);
    _mongocrypt_buffer_cleanup(&expect_index_key_id);

    _mongocrypt_buffer_t expect_user_key_id;
    _mongocrypt_buffer_copy_from_hex(&expect_user_key_id, "abcdefab123498761234123456789012");
    ASSERT_CMPBUF(placeholder.user_key_id, expect_user_key_id);
    _mongocrypt_buffer_cleanup(&expect_user_key_id);

    ASSERT_CMPINT64(placeholder.sparsity, ==, 0);
    ASSERT(placeholder.maxContentionFactor == 7);

    bool res = mc_FLE2TextSearchInsertSpec_parse(spec_out, &placeholder.v_iter, status_out);

    mc_FLE2EncryptionPlaceholder_cleanup(&placeholder);
    return res;

#undef PLACEHOLDER_TEMPLATE
}

static void _test_FLE2EncryptionPlaceholder_textSearch_parse(_mongocrypt_tester_t *tester) {
    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT with substr + suffix + prefix specs
    {
        const char *input = RAW_STRING({
            "v" : "foobar",
            "casef" : false,
            "diacf" : true,
            "substr" : {"ub" : {"$numberInt" : "200"}, "lb" : {"$numberInt" : "20"}, "mlen" : {"$numberInt" : "2000"}},
            "suffix" : {"ub" : {"$numberInt" : "300"}, "lb" : {"$numberInt" : "30"}},
            "prefix" : {"ub" : {"$numberInt" : "400"}, "lb" : {"$numberInt" : "400"}}
        });
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec;
        ASSERT_OK_STATUS(_parse_text_search_spec_from_placeholder(tester, input, &spec, status), status);
        ASSERT(BSON_ITER_HOLDS_UTF8(&spec.v_iter));
        ASSERT(bson_iter_utf8(&spec.v_iter, NULL) == spec.v);
        ASSERT(strlen("foobar") == spec.len);
        ASSERT(0 == strncmp("foobar", spec.v, spec.len));
        ASSERT(spec.diacf == true);
        ASSERT(spec.casef == false);
        ASSERT(spec.substr.set == true);
        ASSERT(spec.substr.value.lb == 20);
        ASSERT(spec.substr.value.ub == 200);
        ASSERT(spec.substr.value.mlen == 2000);
        ASSERT(spec.suffix.set == true);
        ASSERT(spec.suffix.value.lb == 30);
        ASSERT(spec.suffix.value.ub == 300);
        ASSERT(spec.prefix.set == true);
        ASSERT(spec.prefix.value.lb == 400);
        ASSERT(spec.prefix.value.ub == 400);
        mongocrypt_status_destroy(status);
    }

    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT with lb > ub
#define LB_GT_UB_TEST(Type)                                                                                            \
    do {                                                                                                               \
        const char *input = RAW_STRING({                                                                               \
            "v" : "foobar",                                                                                            \
            "casef" : false,                                                                                           \
            "diacf" : true,                                                                                            \
            Type : {"ub" : {"$numberInt" : "30"}, "lb" : {"$numberInt" : "40"}, "mlen" : {"$numberInt" : "400"}}       \
        });                                                                                                            \
        mongocrypt_status_t *status = mongocrypt_status_new();                                                         \
        mc_FLE2TextSearchInsertSpec_t spec;                                                                            \
        ASSERT_FAILS_STATUS(_parse_text_search_spec_from_placeholder(tester, input, &spec, status),                    \
                            status,                                                                                    \
                            "upper bound cannot be less than the lower bound");                                        \
        mongocrypt_status_destroy(status);                                                                             \
    } while (0)
    LB_GT_UB_TEST("substr");
    LB_GT_UB_TEST("suffix");
    LB_GT_UB_TEST("prefix");
#undef LB_GT_UB_TEST

    // Test type=MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT with mlen < ub
    {
        const char *input = RAW_STRING({
            "v" : "foobar",
            "casef" : false,
            "diacf" : true,
            "substr" :
                {"ub" : {"$numberInt" : "2000"}, "lb" : {"$numberInt" : "20"}, "mlen" : {"$numberInt" : "200"}}
        });
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2TextSearchInsertSpec_t spec;
        ASSERT_FAILS_STATUS(_parse_text_search_spec_from_placeholder(tester, input, &spec, status),
                            status,
                            "maximum indexed length cannot be less than the upper bound");
        mongocrypt_status_destroy(status);
    }
}

static void _test_FLE2EncryptionPlaceholder_parse_errors(_mongocrypt_tester_t *tester) {
    bson_t *input_bson = TMP_BSON_STR(BSON_STR({
        "t" : {"$numberInt" : "1"},
        "a" : {"$numberInt" : "1"},
        "ki" : {"$binary" : {"base64" : "EjRWeBI0mHYSNBI0VniQEg==", "subType" : "04"}},
        "ku" : {"$binary" : {"base64" : "q83vqxI0mHYSNBI0VniQEg==", "subType" : "04"}},
        "v" : "foobar",
        "cm" : "wrong type!"
    }));

    mc_FLE2EncryptionPlaceholder_t payload;
    mc_FLE2EncryptionPlaceholder_init(&payload);
    mongocrypt_status_t *status = mongocrypt_status_new();
    ASSERT_FAILS_STATUS(mc_FLE2EncryptionPlaceholder_parse(&payload, input_bson, status),
                        status,
                        "'cm' must be an int64");
    mc_FLE2EncryptionPlaceholder_cleanup(&payload);
    mongocrypt_status_destroy(status);
}

void _mongocrypt_tester_install_fle2_encryption_placeholder(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_FLE2EncryptionPlaceholder_parse);
    INSTALL_TEST(_test_FLE2EncryptionPlaceholder_range_parse);
    INSTALL_TEST(_test_FLE2EncryptionPlaceholder_textSearch_parse);
    INSTALL_TEST(_test_FLE2EncryptionPlaceholder_parse_errors);
}
