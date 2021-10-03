/*
 * Copyright 2021-present MongoDB, Inc.
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

#include "test-mongocrypt-assert.h"

#include "mongocrypt-binary-private.h"

void
_assert_bin_bson_equal (mongocrypt_binary_t *bin_a, mongocrypt_binary_t *bin_b)
{
   bson_t bin_a_bson, bin_b_bson;
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin_a, &bin_a_bson));
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin_b, &bin_b_bson));
   char *str_a = bson_as_canonical_extended_json (&bin_a_bson, NULL);
   char *str_b = bson_as_canonical_extended_json (&bin_b_bson, NULL);
   char *msg = bson_strdup_printf ("BSON unequal:%s\n!=\n%s\n", str_a, str_b);
   bson_free (str_a);
   bson_free (str_b);
   ASSERT_OR_PRINT_MSG (bson_equal (&bin_a_bson, &bin_b_bson), msg);
   bson_free (msg);
}
