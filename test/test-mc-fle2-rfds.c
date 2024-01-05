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
#include "mc-fle2-range-operator-private.h"
#include "mc-fle2-rfds-private.h"
#include "test-mongocrypt.h"
#include <math.h> // INFINITY

#define RAW_STRING(...) #__VA_ARGS__

static void test_mc_FLE2RangeFindDriverSpec_parse(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *expectError;

        struct {
            const char *field;

            struct {
                bool set;
                int32_t value;
                bool included;
            } lower;

            struct {
                bool set;
                int32_t value;
                bool included;
            } upper;

            bool isAggregateExpression;
        } expect;
    } testcase;

    testcase tests[] = {
        {.desc = "Aggregate Expression",
         .in = RAW_STRING({"$and" : [ {"$gt" : [ "$age", 5 ]}, {"$lt" : [ "$age", 50 ]} ]}),
         .expect = {.field = "$age",
                    .lower = {.set = true, .value = 5, .included = false},
                    .upper = {.set = true, .value = 50, .included = false},
                    .isAggregateExpression = true}},
        {.desc = "Aggregate Expression with inclusive bounds",
         .in = RAW_STRING({"$and" : [ {"$gte" : [ "$age", 5 ]}, {"$lte" : [ "$age", 50 ]} ]}),
         .expect = {.field = "$age",
                    .lower = {.set = true, .value = 5, .included = true},
                    .upper = {.set = true, .value = 50, .included = true},
                    .isAggregateExpression = true}},
        {.desc = "Aggregate Expression with one bound",
         .in = RAW_STRING({"$and" : [ {"$gte" : [ "$age", 5 ]} ]}),
         .expect = {.field = "$age",
                    .lower = {.set = true, .value = 5, .included = true},
                    .upper = {.set = false},
                    .isAggregateExpression = true}},
        {.desc = "Aggregate Expression with unsupported operator",
         .in = RAW_STRING({"$and" : [ {"$foo" : [ "$age", 5 ]}, {"$lte" : [ "$age", 50 ]} ]}),
         .expectError = "expected argument to be document"},
        {.desc = "Aggregate Expression with conflicting operators",
         .in = RAW_STRING({"$and" : [ {"$lt" : [ "$age", 5 ]}, {"$lte" : [ "$age", 50 ]} ]}),
         .expectError = "unexpected duplicate bound"},
        {.desc = "Aggregate Expression with more than two arguments",
         .in = RAW_STRING({"$and" : [ {"$lt" : [ "$age", 5 ]}, {"$gt" : [ "$age", 50 ]}, {"$gt" : [ "$age", 50 ]} ]}),
         .expectError = "unexpected duplicate bound"},
        {.desc = "Aggregate Expression referencing two fields",
         .in = RAW_STRING({"$and" : [ {"$lt" : [ "$age", 5 ]}, {"$gt" : [ "$foo", 50 ]} ]}),
         .expectError = "unexpected field mismatch"},
        {.desc = "Match Expression",
         .in = RAW_STRING({"$and" : [ {"age" : {"$gt" : 5}}, {"age" : {"$lt" : 50}} ]}),
         .expect = {.field = "age",
                    .lower = {.set = true, .value = 5, .included = false},
                    .upper = {.set = true, .value = 50, .included = false},
                    .isAggregateExpression = false}},
        {.desc = "Missing top $and", .in = RAW_STRING({"foo" : "bar"}), .expectError = "error unable to find '$and'"},
        {.desc = "Empty document", .in = RAW_STRING({}), .expectError = "error unable to find '$and'"},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_FLE2RangeFindDriverSpec_t rfds;
        printf("running subtest: %s\n", test->desc);
        bool ret = mc_FLE2RangeFindDriverSpec_parse(&rfds, TMP_BSON(test->in), status);
        if (!test->expectError) {
            ASSERT_OK_STATUS(ret, status);
            ASSERT_STREQUAL(test->expect.field, rfds.field);
            ASSERT_CMPINT(test->expect.lower.set, ==, rfds.lower.set);
            if (test->expect.lower.set) {
                ASSERT_CMPINT32(test->expect.lower.value, ==, bson_iter_int32(&rfds.lower.value));
                ASSERT_CMPINT(test->expect.lower.included, ==, rfds.lower.included);
            }
            ASSERT_CMPINT(test->expect.upper.set, ==, rfds.upper.set);
            if (test->expect.upper.set) {
                ASSERT_CMPINT32(test->expect.upper.value, ==, bson_iter_int32(&rfds.upper.value));
                ASSERT_CMPINT(test->expect.upper.included, ==, rfds.upper.included);
            }
            ASSERT_CMPINT(test->expect.isAggregateExpression, ==, rfds.isAggregateExpression);
        } else {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
        }
        mongocrypt_status_destroy(status);
    }
}

typedef struct {
    bool isStub;
    bson_iter_t lowerBound;
    bool lbIncluded;
    bson_iter_t upperBound;
    bool ubIncluded;
    mc_FLE2RangeOperator_t firstOp;
    mc_FLE2RangeOperator_t secondOp;
} placeholder_args_t;

static void
addPlaceholders_recursive(bson_iter_t *iter, bson_t *out, _mongocrypt_buffer_t *p1, _mongocrypt_buffer_t *p2) {
    while (bson_iter_next(iter)) {
        const char *key = bson_iter_key(iter);

        if (BSON_ITER_HOLDS_ARRAY(iter)) {
            bson_t child;
            bson_iter_t iter_child;
            ASSERT(BSON_APPEND_ARRAY_BEGIN(out, key, &child));
            ASSERT(bson_iter_recurse(iter, &iter_child));
            addPlaceholders_recursive(&iter_child, &child, p1, p2);
            ASSERT(bson_append_array_end(out, &child));
            continue;
        }
        if (BSON_ITER_HOLDS_DOCUMENT(iter)) {
            bson_t child;
            bson_iter_t iter_child;
            ASSERT(BSON_APPEND_DOCUMENT_BEGIN(out, key, &child));
            ASSERT(bson_iter_recurse(iter, &iter_child));
            addPlaceholders_recursive(&iter_child, &child, p1, p2);
            ASSERT(bson_append_document_end(out, &child));
            continue;
        }
        if (BSON_ITER_HOLDS_UTF8(iter)) {
            if (strcmp(bson_iter_utf8(iter, NULL), "<placeholder1>") == 0) {
                ASSERT(p1->data);
                ASSERT(_mongocrypt_buffer_append(p1, out, key, -1));
                continue;
            }
            if (strcmp(bson_iter_utf8(iter, NULL), "<placeholder2>") == 0) {
                ASSERT(p2->data);
                ASSERT(_mongocrypt_buffer_append(p2, out, key, -1));
                continue;
            }
            // Otherwise the value is not a placeholder. Fall through.
        }
        ASSERT(BSON_APPEND_VALUE(out, key, bson_iter_value(iter)));
    }
}

// addPlaceholders replaces values "<placeholder1>" and "<placeholder2>" in bson
// with p1 and p2.
static void addPlaceholders(bson_t **in, _mongocrypt_buffer_t *p1, _mongocrypt_buffer_t *p2) {
    bson_t out = BSON_INITIALIZER;
    bson_iter_t iter;
    ASSERT(bson_iter_init(&iter, *in));
    addPlaceholders_recursive(&iter, &out, p1, p2);
    bson_destroy(*in);
    bson_steal(*in, &out);
}

// Create a bson_iter_t to a temporary BSON int32 value v.
static bson_iter_t tmp_iter(_mongocrypt_tester_t *tester, int32_t v) {
    bson_t *b = TMP_BSON("{'v': %" PRId32 "}", v);
    bson_iter_t iter;
    ASSERT(bson_iter_init_find(&iter, b, "v"));
    return iter;
}

#define TMP_ITER(v) tmp_iter(tester, v)

static void test_mc_FLE2RangeFindDriverSpec_to_placeholders(_mongocrypt_tester_t *tester) {
    mc_FLE2RangeFindDriverSpec_t spec;
    mc_RangeOpts_t range_opts;
    mongocrypt_status_t *const status = mongocrypt_status_new();
    _mongocrypt_buffer_t user_key_id;
    _mongocrypt_buffer_t index_key_id;
    _mongocrypt_buffer_copy_from_hex(&user_key_id, "0123456789abcdefedcba98765432101");
    _mongocrypt_buffer_copy_from_hex(&index_key_id, "abcdefabcdabcdefedcba98765432101");
    user_key_id.subtype = BSON_SUBTYPE_UUID;
    index_key_id.subtype = BSON_SUBTYPE_UUID;

    int64_t maxContentionFactor = 4;
    int64_t sparsity = 1;
    int32_t indexMin = 5;
    int32_t indexMax = 200;
    int32_t payloadId = 123;

    typedef struct {
        const char *desc;
        const char *in;
        placeholder_args_t p1;
        placeholder_args_t p2;
        const char *expected;
    } testcase_t;

    bson_iter_t negInf, posInf;
    bson_t infDoc = BSON_INITIALIZER;
    // Create iterators to infinity
    {
        BCON_APPEND(&infDoc, "p", BCON_DOUBLE(INFINITY), "n", BCON_DOUBLE(-INFINITY));
        ASSERT(bson_iter_init_find(&posInf, &infDoc, "p"));
        ASSERT(bson_iter_init_find(&negInf, &infDoc, "n"));
    }

    testcase_t tests[] = {
        {.desc = "Match Expression with both inclusive bounds",
         .in = RAW_STRING({"$and" : [ {"age" : {"$gte" : 23}}, {"age" : {"$lte" : 35}} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = true,
                .upperBound = TMP_ITER(35),
                .ubIncluded = true,
                .firstOp = FLE2RangeOperator_kGte,
                .secondOp = FLE2RangeOperator_kLte},
         .p2 = {.isStub = true, .firstOp = FLE2RangeOperator_kGte, .secondOp = FLE2RangeOperator_kLte},
         .expected =
             RAW_STRING({"$and" : [ {"age" : {"$gte" : "<placeholder1>"}}, {"age" : {"$lte" : "<placeholder2>"}} ]})},
        {.desc = "Match Expression with one inclusive bound",
         .in = RAW_STRING({"$and" : [ {"age" : {"$gte" : 23}} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = true,
                .upperBound = posInf,
                .ubIncluded = true,
                .firstOp = FLE2RangeOperator_kGte},
         .expected = RAW_STRING({"$and" : [ {"age" : {"$gte" : "<placeholder1>"}} ]})},
        {.desc = "Match Expression with both exclusive bounds",
         .in = RAW_STRING({"$and" : [ {"age" : {"$gt" : 23}}, {"age" : {"$lt" : 35}} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = false,
                .upperBound = TMP_ITER(35),
                .ubIncluded = false,
                .firstOp = FLE2RangeOperator_kGt,
                .secondOp = FLE2RangeOperator_kLt},
         .p2 = {.isStub = true, .firstOp = FLE2RangeOperator_kGt, .secondOp = FLE2RangeOperator_kLt},
         .expected =
             RAW_STRING({"$and" : [ {"age" : {"$gt" : "<placeholder1>"}}, {"age" : {"$lt" : "<placeholder2>"}} ]})},
        {.desc = "Match Expression with one exclusive bound",
         .in = RAW_STRING({"$and" : [ {"age" : {"$lt" : 35}} ]}),
         .p1 = {.lowerBound = negInf,
                .lbIncluded = true,
                .upperBound = TMP_ITER(35),
                .ubIncluded = false,
                .firstOp = FLE2RangeOperator_kLt},
         .expected = RAW_STRING({"$and" : [ {"age" : {"$lt" : "<placeholder1>"}} ]})},
        {.desc = "Match Expression with flipped bounds",
         .in = RAW_STRING({"$and" : [ {"age" : {"$lte" : 35}}, {"age" : {"$gte" : 23}} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = true,
                .upperBound = TMP_ITER(35),
                .ubIncluded = true,
                .firstOp = FLE2RangeOperator_kLte,
                .secondOp = FLE2RangeOperator_kGte},
         .p2 = {.isStub = true, .firstOp = FLE2RangeOperator_kLte, .secondOp = FLE2RangeOperator_kGte},
         .expected =
             RAW_STRING({"$and" : [ {"age" : {"$lte" : "<placeholder1>"}}, {"age" : {"$gte" : "<placeholder2>"}} ]})},
        {.desc = "Aggregate Expression with both inclusive bounds",
         .in = RAW_STRING({"$and" : [ {"$gte" : [ "$age", 23 ]}, {"$lte" : [ "$age", 35 ]} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = true,
                .upperBound = TMP_ITER(35),
                .ubIncluded = true,
                .firstOp = FLE2RangeOperator_kGte,
                .secondOp = FLE2RangeOperator_kLte},
         .p2 = {.isStub = true, .firstOp = FLE2RangeOperator_kGte, .secondOp = FLE2RangeOperator_kLte},
         .expected = RAW_STRING(
             {"$and" : [ {"$gte" : [ "$age", "<placeholder1>" ]}, {"$lte" : [ "$age", "<placeholder2>" ]} ]})},
        {.desc = "Aggregate Expression with one inclusive bound",
         .in = RAW_STRING({"$and" : [ {"$gte" : [ "$age", 23 ]} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = true,
                .upperBound = posInf,
                .ubIncluded = true,
                .firstOp = FLE2RangeOperator_kGte},
         .expected = RAW_STRING({"$and" : [ {"$gte" : [ "$age", "<placeholder1>" ]} ]})},
        {.desc = "Aggregate Expression with both exclusive bounds",
         .in = RAW_STRING({"$and" : [ {"$gt" : [ "$age", 23 ]}, {"$lt" : [ "$age", 35 ]} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = false,
                .upperBound = TMP_ITER(35),
                .ubIncluded = false,
                .firstOp = FLE2RangeOperator_kGt,
                .secondOp = FLE2RangeOperator_kLt},
         .p2 = {.isStub = true, .firstOp = FLE2RangeOperator_kGt, .secondOp = FLE2RangeOperator_kLt},
         .expected =
             RAW_STRING({"$and" : [ {"$gt" : [ "$age", "<placeholder1>" ]}, {"$lt" : [ "$age", "<placeholder2>" ]} ]})},
        {.desc = "Aggregate Expression with one exclusive bound",
         .in = RAW_STRING({"$and" : [ {"$lt" : [ "$age", 35 ]} ]}),
         .p1 = {.lowerBound = negInf,
                .lbIncluded = true,
                .upperBound = TMP_ITER(35),
                .ubIncluded = false,
                .firstOp = FLE2RangeOperator_kLt},
         .expected = RAW_STRING({"$and" : [ {"$lt" : [ "$age", "<placeholder1>" ]} ]})},
        {.desc = "Aggregate Expression with flipped bounds",
         .in = RAW_STRING({"$and" : [ {"$lte" : [ "$age", 35 ]}, {"$gte" : [ "$age", 23 ]} ]}),
         .p1 = {.lowerBound = TMP_ITER(23),
                .lbIncluded = true,
                .upperBound = TMP_ITER(35),
                .ubIncluded = true,
                .firstOp = FLE2RangeOperator_kLte,
                .secondOp = FLE2RangeOperator_kGte},
         .p2 = {.isStub = true, .firstOp = FLE2RangeOperator_kLte, .secondOp = FLE2RangeOperator_kGte},
         .expected = RAW_STRING(
             {"$and" : [ {"$lte" : [ "$age", "<placeholder1>" ]}, {"$gte" : [ "$age", "<placeholder2>" ]} ]})}

    };

    bson_t *range_opts_bson =
        TMP_BSON("{'min': %d, 'max': %d, 'sparsity': {'$numberLong': '%d'}}", indexMin, indexMax, sparsity);

    ASSERT_OK_STATUS(mc_RangeOpts_parse(&range_opts, range_opts_bson, status), status);

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase_t *test = tests + i;
        printf("running subtest: %s : %s\n", test->desc, test->in);
        ASSERT_OK_STATUS(mc_FLE2RangeFindDriverSpec_parse(&spec, TMP_BSON(test->in), status), status);

        // Create the expected document.
        bson_t *expected;
        {
            expected = TMP_BSON(test->expected);

            _mongocrypt_buffer_t p1 = {0}, p2 = {0};

            // Create placeholder arguments with default test values.
            if (test->p1.firstOp) {
                // Placeholder requires firstOp.
                mc_makeRangeFindPlaceholder_args_t p1_args_full = {.isStub = test->p1.isStub,
                                                                   .user_key_id = &user_key_id,
                                                                   .index_key_id = &index_key_id,
                                                                   .lowerBound = test->p1.lowerBound,
                                                                   .lbIncluded = test->p1.lbIncluded,
                                                                   .upperBound = test->p1.upperBound,
                                                                   .ubIncluded = test->p1.ubIncluded,
                                                                   .payloadId = payloadId,
                                                                   .firstOp = test->p1.firstOp,
                                                                   .secondOp = test->p1.secondOp,
                                                                   .indexMin = TMP_ITER(indexMin),
                                                                   .indexMax = TMP_ITER(indexMax),
                                                                   .maxContentionFactor = maxContentionFactor,
                                                                   .sparsity = sparsity};

                ASSERT_OK_STATUS(mc_makeRangeFindPlaceholder(&p1_args_full, &p1, status), status);
            }

            if (test->p2.firstOp) {
                mc_makeRangeFindPlaceholder_args_t p2_args_full = {.isStub = test->p2.isStub,
                                                                   .user_key_id = &user_key_id,
                                                                   .index_key_id = &index_key_id,
                                                                   .lowerBound = test->p2.lowerBound,
                                                                   .lbIncluded = test->p2.lbIncluded,
                                                                   .upperBound = test->p2.upperBound,
                                                                   .ubIncluded = test->p2.ubIncluded,
                                                                   .payloadId = payloadId,
                                                                   .firstOp = test->p2.firstOp,
                                                                   .secondOp = test->p2.secondOp,
                                                                   .indexMin = TMP_ITER(indexMin),
                                                                   .indexMax = TMP_ITER(indexMax),
                                                                   .maxContentionFactor = maxContentionFactor,
                                                                   .sparsity = sparsity};

                ASSERT_OK_STATUS(mc_makeRangeFindPlaceholder(&p2_args_full, &p2, status), status);
            }
            addPlaceholders(&expected, &p1, &p2);
            _mongocrypt_buffer_cleanup(&p2);
            _mongocrypt_buffer_cleanup(&p1);
        }

        bson_t out = BSON_INITIALIZER;
        bool ok = mc_FLE2RangeFindDriverSpec_to_placeholders(&spec,
                                                             &range_opts,
                                                             maxContentionFactor,
                                                             &user_key_id,
                                                             &index_key_id,
                                                             payloadId,
                                                             &out,
                                                             status);
        ASSERT_OK_STATUS(ok, status);
        ASSERT_EQUAL_BSON(expected, &out);
        bson_destroy(&out);
    }

    mc_RangeOpts_cleanup(&range_opts);
    _mongocrypt_buffer_cleanup(&index_key_id);
    _mongocrypt_buffer_cleanup(&user_key_id);
    bson_destroy(&infDoc);
    mongocrypt_status_destroy(status);
}

static void test_mc_getNextPayloadId(_mongocrypt_tester_t *tester) {
    int32_t first = mc_getNextPayloadId();
    int32_t second = mc_getNextPayloadId();
    ASSERT_CMPINT32(first + 1, ==, second);
}

void _mongocrypt_tester_install_mc_FLE2RangeFindDriverSpec(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_FLE2RangeFindDriverSpec_parse);
    INSTALL_TEST(test_mc_FLE2RangeFindDriverSpec_to_placeholders);
    INSTALL_TEST(test_mc_getNextPayloadId);
}
