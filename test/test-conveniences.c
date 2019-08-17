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

#include "test-conveniences.h"

void
bson_iter_bson (bson_iter_t *iter, bson_t *bson)
{
   uint32_t len;
   const uint8_t *data = NULL;
   if (BSON_ITER_HOLDS_DOCUMENT (iter)) {
      bson_iter_document (iter, &len, &data);
   }
   if (BSON_ITER_HOLDS_ARRAY (iter)) {
      bson_iter_array (iter, &len, &data);
   }
   BSON_ASSERT (data);
   bson_init_static (bson, data, len);
}