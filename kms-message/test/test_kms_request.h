/*
 * Copyright 2020-present MongoDB, Inc.
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

#ifndef TEST_KMS_REQUEST_H
#define TEST_KMS_REQUEST_H

#define ASSERT_CMPSTR(_a, _b) compare_strs (__FUNCTION__, (_a), (_b))

#define ASSERT(stmt)                                                        \
   if (!(stmt)) {                                                           \
      fprintf (                                                             \
         stderr, "%s:%d statement failed %s\n", __FILE__, __LINE__, #stmt); \
      abort ();                                                             \
   }

#define ASSERT_CONTAINS(_a, _b)                                              \
   do {                                                                      \
      kms_request_str_t *_a_str = kms_request_str_new_from_chars ((_a), -1); \
      kms_request_str_t *_b_str = kms_request_str_new_from_chars ((_b), -1); \
      kms_request_str_t *_a_lower = kms_request_str_new ();                  \
      kms_request_str_t *_b_lower = kms_request_str_new ();                  \
      kms_request_str_append_lowercase (_a_lower, (_a_str));                 \
      kms_request_str_append_lowercase (_b_lower, (_b_str));                 \
      if (NULL == strstr ((_a_lower->str), (_b_lower->str))) {               \
         fprintf (stderr,                                                    \
                  "%s:%d %s(): [%s] does not contain [%s]\n",                \
                  __FILE__,                                                  \
                  __LINE__,                                                  \
                  __FUNCTION__,                                              \
                  _a,                                                        \
                  _b);                                                       \
         abort ();                                                           \
      }                                                                      \
      kms_request_str_destroy (_a_str);                                      \
      kms_request_str_destroy (_b_str);                                      \
      kms_request_str_destroy (_a_lower);                                    \
      kms_request_str_destroy (_b_lower);                                    \
   } while (0)

#endif /* TEST_KMS_REQUEST_H */