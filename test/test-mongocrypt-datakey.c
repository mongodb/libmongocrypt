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
   BSON_ASSERT (out->data);

   out->owned = true;
}

static void
_test_random_generator (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   _mongocrypt_buffer_t out;
   mongocrypt_status_t *status;
#define TEST_COUNT 32
   int mid = TEST_COUNT / 2;
   char zero[TEST_COUNT];

   crypt = _mongocrypt_tester_mongocrypt ();

   /* _mongocrypt_random handles the case where the count size is greater
    * than the buffer by throwing an error. Because of that, no additional tests
    * for this case is needed here. */

   memset (zero, 0, TEST_COUNT);
   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, TEST_COUNT);

   BSON_ASSERT (_mongocrypt_random (crypt->crypto, &out, TEST_COUNT, status));
   BSON_ASSERT (0 != memcmp (zero, out.data, TEST_COUNT)); /* initialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);

   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, TEST_COUNT);

   ASSERT_FAILS_STATUS (_mongocrypt_random (crypt->crypto, &out, mid, status),
                        status,
                        "out should have length 16");


   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);
   mongocrypt_destroy (crypt);
}


static void
_test_create_data_key_with_provider (_mongocrypt_tester_t *tester,
                                     _mongocrypt_kms_provider_t provider,
                                     bool with_alt_name)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_binary_t *bin;
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_buffer_t buf;
   int64_t created_date;
   const int64_t current_epoch_time_ms =
      1565097975532ll; /* the time this code was written */
   const int64_t one_hundred_years_ms =
      (int64_t) 1000ll * 60ll * 60ll * 24ll * 365ll * 100ll;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   if (provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      ASSERT_OK (
         mongocrypt_ctx_setopt_masterkey_aws (ctx, "region", -1, "cmk", -1),
         ctx);
   } else {
      ASSERT_OK (mongocrypt_ctx_setopt_masterkey_local (ctx), ctx);
   }

   if (with_alt_name) {
      ASSERT_OK (mongocrypt_ctx_setopt_key_alt_name (
                    ctx, TEST_BSON ("{'keyAltName': 'b'}")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_setopt_key_alt_name (
                    ctx, TEST_BSON ("{'keyAltName': 'a'}")),
                 ctx);
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
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin, &as_bson));
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
   BSON_ASSERT (created_date > current_epoch_time_ms &&
                created_date < current_epoch_time_ms + one_hundred_years_ms);
   BSON_ASSERT (bson_iter_init_find (&iter, &as_bson, "updateDate"));
   BSON_ASSERT (BSON_ITER_HOLDS_DATE_TIME (&iter));
   BSON_ASSERT (created_date == bson_iter_date_time (&iter));
   if (with_alt_name) {
      BSON_ASSERT (bson_iter_init (&iter, &as_bson));
      BSON_ASSERT (bson_iter_find_descendant (&iter, "keyAltNames.0", &iter));
      BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
      BSON_ASSERT (0 == strcmp (bson_iter_utf8 (&iter, NULL), "a"));
      BSON_ASSERT (bson_iter_init (&iter, &as_bson));
      BSON_ASSERT (bson_iter_find_descendant (&iter, "keyAltNames.1", &iter));
      BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
      BSON_ASSERT (0 == strcmp (bson_iter_utf8 (&iter, NULL), "b"));
      BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
   } else {
      BSON_ASSERT (!bson_iter_init_find (&iter, &as_bson, "keyAltNames"));
   }

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
_test_datakey_custom_endpoint (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_kms_ctx_t *kms_ctx;
   mongocrypt_binary_t *bin;
   const char *endpoint;
   bson_t key_bson;
   bson_iter_t iter;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_setopt_masterkey_aws (ctx, "region", -1, "cmk", -1), ctx);
   ASSERT_OK (
      mongocrypt_ctx_setopt_masterkey_aws_endpoint (ctx, "example.com", -1),
      ctx);
   ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
   BSON_ASSERT (kms_ctx);
   ASSERT_OK (mongocrypt_kms_ctx_endpoint (kms_ctx, &endpoint), ctx);
   BSON_ASSERT (0 == strcmp ("example.com:443", endpoint));
   bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_kms_ctx_message (kms_ctx, bin), ctx);
   BSON_ASSERT (NULL != strstr ((char *) bin->data, "Host:example.com"));
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms_ctx, TEST_FILE ("./test/data/kms-encrypt-reply.txt")),
              kms_ctx);
   BSON_ASSERT (0 == mongocrypt_kms_ctx_bytes_needed (kms_ctx));
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);

   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, bin), ctx);
   /* Check the BSON document created. */
   BSON_ASSERT (_mongocrypt_binary_to_bson (bin, &key_bson));
   BSON_ASSERT (bson_iter_init (&iter, &key_bson));
   BSON_ASSERT (bson_iter_find_descendant (&iter, "masterKey.endpoint", &iter));
   BSON_ASSERT (0 == strcmp (bson_iter_utf8 (&iter, NULL), "example.com"));

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_datakey_custom_key_material (_mongocrypt_tester_t *tester)
{
   const uint8_t expected_dek[MONGOCRYPT_KEY_LEN] = "0123456789abcdef"
                                                    "0123456789abcdef"
                                                    "0123456789abcdef"
                                                    "0123456789abcdef"
                                                    "0123456789abcdef"
                                                    "0123456789abcdef";

   mongocrypt_t *const crypt = _mongocrypt_tester_mongocrypt ();

   _mongocrypt_buffer_t encrypted_dek_buf;

   {
      mongocrypt_ctx_t *ctx = mongocrypt_ctx_new (crypt);

      /* Generate encrypted DEK using custom key material. */
      {
         mongocrypt_binary_t *const kek = TEST_BSON ("{'provider': 'local'}");

         bson_t bson;
         _mongocrypt_buffer_t key_material_buf;
         mongocrypt_binary_t key_material;

         bson_init (&bson);
         ASSERT (BSON_APPEND_BINARY (&bson,
                                     "keyMaterial",
                                     BSON_SUBTYPE_BINARY,
                                     expected_dek,
                                     MONGOCRYPT_KEY_LEN));
         _mongocrypt_buffer_from_bson (&key_material_buf, &bson);
         _mongocrypt_buffer_to_binary (&key_material_buf, &key_material);

         ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (ctx, kek), ctx);
         ASSERT_OK (mongocrypt_ctx_setopt_key_material (ctx, &key_material),
                    ctx);
         ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);

         bson_destroy (&bson);
      }

      /* Extract encrypted DEK from datakey. */
      {
         mongocrypt_binary_t *const datakey = mongocrypt_binary_new ();

         bson_t bson;
         bson_iter_t iter;
         const uint8_t *binary;
         uint32_t len;
         bson_subtype_t subtype;

         _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
         ASSERT_OK (mongocrypt_ctx_finalize (ctx, datakey), ctx);
         ASSERT (_mongocrypt_binary_to_bson (datakey, &bson));

         ASSERT (bson_iter_init_find (&iter, &bson, "keyMaterial"));
         ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
         bson_iter_binary (&iter, &subtype, &len, &binary);
         ASSERT (_mongocrypt_buffer_copy_from_data_and_size (
            &encrypted_dek_buf, binary, len));

         mongocrypt_binary_destroy (datakey);
      }

      mongocrypt_ctx_destroy (ctx);
   }

   /* Decrypt key material and confirm it matches original DEK. */
   {
      _mongocrypt_buffer_t decrypted_dek_buf;
      mongocrypt_binary_t decrypted_dek;

      ASSERT (_mongocrypt_unwrap_key (crypt->crypto,
                                      &crypt->opts.kms_provider_local.key,
                                      &encrypted_dek_buf,
                                      &decrypted_dek_buf,
                                      crypt->status));

      _mongocrypt_buffer_to_binary (&decrypted_dek_buf, &decrypted_dek);

      ASSERT_CMPBYTES (expected_dek,
                       MONGOCRYPT_KEY_LEN,
                       decrypted_dek.data,
                       decrypted_dek.len);

      _mongocrypt_buffer_cleanup (&decrypted_dek_buf);
   }

   _mongocrypt_buffer_cleanup (&encrypted_dek_buf);
   mongocrypt_destroy (crypt);
}


static void
_test_create_data_key (_mongocrypt_tester_t *tester)
{
   _test_create_data_key_with_provider (
      tester, MONGOCRYPT_KMS_PROVIDER_AWS, false /* with_alt_name */);
   _test_create_data_key_with_provider (
      tester, MONGOCRYPT_KMS_PROVIDER_LOCAL, false /* with_alt_name */);
   _test_create_data_key_with_provider (
      tester, MONGOCRYPT_KMS_PROVIDER_AWS, true /* with_alt_name */);
   _test_create_data_key_with_provider (
      tester, MONGOCRYPT_KMS_PROVIDER_LOCAL, true /* with_alt_name */);
}


void
_mongocrypt_tester_install_data_key (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_random_generator);
   INSTALL_TEST (_test_create_data_key);
   INSTALL_TEST (_test_datakey_custom_endpoint);
   INSTALL_TEST (_test_datakey_custom_key_material);
}
