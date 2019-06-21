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

#include "mongocrypt-private.h"
#include "test-mongocrypt.h"
#include "mongocrypt-crypto-private.h"

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
#define TEST_COUNT 32
   int mid = TEST_COUNT / 2;
   char zero[TEST_COUNT];

   /* _mongocrypt_random handles the case where the count size is greater
    * than the buffer by throwing an error. Because of that, no additional tests
    * for this case is needed here. */

   memset (zero, 0, TEST_COUNT);
   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, TEST_COUNT);

   BSON_ASSERT (_mongocrypt_random (&out, status, TEST_COUNT));
   BSON_ASSERT (0 != memcmp (zero, out.data, TEST_COUNT)); /* initialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);

   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, TEST_COUNT);

   BSON_ASSERT (_mongocrypt_random (&out, status, mid));
   BSON_ASSERT (0 != memcmp (zero, out.data, mid));       /* initialized */
   BSON_ASSERT (0 == memcmp (zero, out.data + mid, mid)); /* uninitialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);
}


static void
_print_binary_as_text (mongocrypt_binary_t *binary)
{
   uint32_t i;
   uint8_t *ptr;

   ptr = (uint8_t *) mongocrypt_binary_data (binary);
   for (i = 0; i < mongocrypt_binary_len (binary); i++) {
      printf ("%c", (char) ptr[i]);
   }
   printf ("\n");
}

static void
_test_create_data_key_with_provider (_mongocrypt_tester_t *tester,
                                     _mongocrypt_kms_provider_t provider)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_binary_t *bin;
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_buffer_t buf;
   int64_t created_date;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   if (provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      ASSERT_OK (
         mongocrypt_ctx_setopt_masterkey_aws (ctx, "region", -1, "cmk", -1),
         ctx);
   } else {
      ASSERT_OK (mongocrypt_ctx_setopt_masterkey_local (ctx), ctx);
   }

   ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
   if (provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
      kms = mongocrypt_ctx_next_kms_ctx (ctx);
      BSON_ASSERT (kms);
      ASSERT_OK (mongocrypt_kms_ctx_feed (
                    kms, TEST_FILE ("./test/data/kms-encrypt-reply.txt")),
                 kms);
      BSON_ASSERT (0 == mongocrypt_kms_ctx_bytes_needed (kms));
      ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   }
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);
   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, bin), ctx);
   /* Check the BSON document created. */
   _mongocrypt_binary_to_bson (bin, &as_bson);
   CRYPT_TRACEF (&crypt->log, "created data key: %s\n", tmp_json (&as_bson));
   /* _id is a UUID */
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "_id"));
   BSON_ASSERT (_mongocrypt_buffer_from_binary_iter (&buf, &iter));
   BSON_ASSERT (buf.subtype == BSON_SUBTYPE_UUID);
   /* keyMaterial is a binary blob of >= KEYMATERIAL_LEN bytes. */
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "keyMaterial"));
   BSON_ASSERT (_mongocrypt_buffer_from_binary_iter (&buf, &iter));
   BSON_ASSERT (buf.subtype == BSON_SUBTYPE_BINARY);
   BSON_ASSERT (buf.len >= MONGOCRYPT_KEY_LEN);
   /* creationDate and updatedDate exist and have the same value. */
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "creationDate"));
   BSON_ASSERT (BSON_ITER_HOLDS_DATE_TIME (&iter));
   created_date = bson_iter_date_time (&iter);
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "updateDate"));
   BSON_ASSERT (BSON_ITER_HOLDS_DATE_TIME (&iter));
   BSON_ASSERT (created_date == bson_iter_date_time (&iter));

   /* masterKey matches set options. */
   BSON_ASSERT (bson_iter_init (&iter, &as_bson));
   BSON_ASSERT (bson_iter_find_descendant (&iter, "masterKey.provider", &iter));
   BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
   if (provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      BSON_ASSERT (0 == strcmp ("aws", bson_iter_utf8 (&iter, NULL)));
      BSON_ASSERT (bson_iter_init (&iter, &as_bson));
      BSON_ASSERT (
         bson_iter_find_descendant (&iter, "masterKey.region", &iter));
      BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
      BSON_ASSERT (0 == strcmp ("region", bson_iter_utf8 (&iter, NULL)));
      BSON_ASSERT (bson_iter_init (&iter, &as_bson));
      BSON_ASSERT (bson_iter_find_descendant (&iter, "masterKey.key", &iter));
      BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
      BSON_ASSERT (0 == strcmp ("cmk", bson_iter_utf8 (&iter, NULL)));
   } else {
      BSON_ASSERT (0 == strcmp ("local", bson_iter_utf8 (&iter, NULL)));
   }
   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_create_data_key (_mongocrypt_tester_t *tester)
{
   _test_create_data_key_with_provider (tester, MONGOCRYPT_KMS_PROVIDER_AWS);
   _test_create_data_key_with_provider (tester, MONGOCRYPT_KMS_PROVIDER_LOCAL);
}

void
_mongocrypt_tester_install_data_key (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_random_generator);
   INSTALL_TEST (_test_create_data_key);
}
