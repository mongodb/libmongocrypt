/*
 * Copyright 2019-present MongoDB, Inc.
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

#ifndef TEST_MONGOCRYPT_ASSERT_MATCH_BSON_H
#define TEST_MONGOCRYPT_ASSERT_MATCH_BSON_H

#include <bson/bson.h>

/* Copied from libmongoc. */
bool _check_match_bson(const bson_t *doc, const bson_t *pattern, char *errmsg, size_t errmsg_len);

#define _assert_match_bson(doc, pattern)                                                                               \
    if (1) {                                                                                                           \
        char errmsg[1024] = "";                                                                                        \
        if (!_check_match_bson(doc, pattern, errmsg, sizeof(errmsg))) {                                                \
            char *doc_str = bson_as_relaxed_extended_json(doc, NULL);                                                  \
            char *pattern_str = bson_as_relaxed_extended_json(pattern, NULL);                                          \
                                                                                                                       \
            TEST_ERROR("ASSERT_MATCH failed with document:\n\n"                                                        \
                       "%s\n"                                                                                          \
                       "pattern:\n%s\n"                                                                                \
                       "%s\n",                                                                                         \
                       doc_str ? doc_str : "{}",                                                                       \
                       pattern_str,                                                                                    \
                       errmsg);                                                                                        \
                                                                                                                       \
            bson_free(doc_str);                                                                                        \
            bson_free(pattern_str);                                                                                    \
        }                                                                                                              \
    } else                                                                                                             \
        (void)0

#endif /* TEST_MONGOCRYPT_ASSERT_MATCH_BSON_H */
