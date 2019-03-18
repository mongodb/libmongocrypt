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

#include <mongocrypt.h>

#include "test-mongocrypt.h"

static void
_init_buffer_with_count (_mongocrypt_buffer_t *out, uint32_t count)
{
   out->len = count;
   out->data = bson_malloc0 (out->len);
   out->owned = true;
}

static void
_test_random_generator (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t out;
   mongocrypt_status_t *status;
   uint32_t count = 32;
   int mid = count / 2;
   char zero[count];

   /* _mongocrypt_random handles the case where the count size is greater
    * than the buffer by throwing an error. Because of that, no additional tests
    * for this case is needed here. */

   memset (zero, 0, count);
   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, count);

   BSON_ASSERT (_mongocrypt_random (&out, status, count));
   BSON_ASSERT (0 != memcmp (zero, out.data, count)); /* initialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);

   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, count);

   BSON_ASSERT (_mongocrypt_random (&out, status, mid));
   BSON_ASSERT (0 != memcmp (zero, out.data, mid));       /* initialized */
   BSON_ASSERT (0 == memcmp (zero, out.data + mid, mid)); /* uninitialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);
}


void
_mongocrypt_tester_install_data_key (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_random_generator);
}