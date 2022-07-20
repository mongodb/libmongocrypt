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
#include "test-mongocrypt-assert-match-bson.h"

/* Tests have the form
{
   ctx: [],
   http_reply: [
      "HTTP line 1\r\n",
      "HTTP line 2\r\n"
   ],
   expect: "ok" | "error message" | <array of strings>
}
*/

static void
_satisfy_oauth_request (mongocrypt_kms_ctx_t *kms_ctx)
{
   const char *valid_reply =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 85\r\n"
      "\r\n"
      "{\"token_type\":\"Bearer\",\"expires_in\":3599,\"ext_expires_"
      "in\":3599,\"access_token\":\"AAAA\"}";

   mongocrypt_binary_t *bin = mongocrypt_binary_new_from_data (
      (uint8_t *) valid_reply, (uint32_t) strlen (valid_reply));
   ASSERT_OK (mongocrypt_kms_ctx_feed (kms_ctx, bin), kms_ctx);
   mongocrypt_binary_destroy (bin);
}

static void
_test_one_kms_response (_mongocrypt_tester_t *tester, bson_t *test)
{
   mongocrypt_t *crypt;
   mongocrypt_kms_ctx_t *kms_ctx;
   mongocrypt_ctx_t *ctx;
   bson_iter_t iter;
   bson_iter_t ctx_iter;

   BSON_ASSERT (bson_iter_init_find (&iter, test, "description"));
   printf ("- %s\n", bson_iter_utf8 (&iter, NULL));
   BSON_ASSERT (bson_iter_init_find (&ctx_iter, test, "ctx"));
   BSON_ASSERT (bson_iter_recurse (&ctx_iter, &ctx_iter));
   while (bson_iter_next (&ctx_iter)) {
      const char *ctx_type = bson_iter_utf8 (&ctx_iter, NULL);
      bool ok = false;
      mongocrypt_status_t *status;
      mongocrypt_binary_t *bin = NULL;
      char *expect;

      status = mongocrypt_status_new ();
      crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      ctx = mongocrypt_ctx_new (crypt);

      /* Test both contexts for creating a data key and automatic decryption
       * since they go through different code paths related to KMS. */
      if (0 == strcmp ("datakey", ctx_type)) {
         mongocrypt_ctx_setopt_masterkey_aws (
            ctx, "example", -1, "example", -1);
         ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
      } else if (0 == strcmp ("decrypt", ctx_type)) {
         mongocrypt_binary_destroy (bin);
         bin = _mongocrypt_tester_encrypted_doc (tester);
         tester->paths.key_file = "./test/example/key-document.json";
         ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, bin), ctx);
      } else if (0 == strcmp ("azure_oauth_datakey", ctx_type) ||
                 0 == strcmp ("azure_datakey", ctx_type)) {
         mongocrypt_ctx_setopt_key_encryption_key (
            ctx,
            TEST_BSON ("{'provider': 'azure', 'keyVaultEndpoint': "
                       "'example.vault.azure.net', 'keyName': 'test'}"));
         ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
      } else if (0 == strcmp ("azure_oauth_decrypt", ctx_type)
                 || 0 == strcmp ("azure_decrypt", ctx_type)) {
         bin = _mongocrypt_tester_encrypted_doc (tester);
         tester->paths.key_file = "./test/data/key-document-azure.json";
         ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, bin), ctx);
      } else if (0 == strcmp ("gcp_oauth_datakey", ctx_type) ||
                 0 == strcmp ("gcp_datakey", ctx_type)) {
         mongocrypt_ctx_setopt_key_encryption_key (
            ctx,
            TEST_BSON ("{'provider': 'gcp', 'projectId': 'test', 'location': "
                       "'global', 'keyRing': 'test', 'keyName': 'test'}"));
         ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
      } else if (0 == strcmp ("gcp_oauth_decrypt", ctx_type) ||
                 0 == strcmp ("gcp_decrypt", ctx_type)) {
         bin = _mongocrypt_tester_encrypted_doc (tester);
         tester->paths.key_file = "./test/data/key-document-gcp.json";
         ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, bin), ctx);
      } else {
         fprintf (stderr, "unsupported ctx type: %s\n", ctx_type);
         abort ();
      }

      _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
      kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
      BSON_ASSERT (kms_ctx);
      BSON_ASSERT (mongocrypt_kms_ctx_bytes_needed (kms_ctx) > 0);

      if (0 == strcmp ("gcp_datakey", ctx_type) ||
          0 == strcmp ("gcp_decrypt", ctx_type) ||
          0 == strcmp ("azure_datakey", ctx_type) ||
          0 == strcmp ("azure_decrypt", ctx_type)) {
         /* The targeted request is after the oauth request.
          * Satisfy the oauth request with a valid response */
         _satisfy_oauth_request (kms_ctx);
         ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
         ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
         kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
         BSON_ASSERT (kms_ctx);
         BSON_ASSERT (mongocrypt_kms_ctx_bytes_needed (kms_ctx) > 0);
      }

      /* Feed until failure or completion. */
      BSON_ASSERT (bson_iter_init_find (&iter, test, "http_reply"));
      BSON_ASSERT (bson_iter_recurse (&iter, &iter));
      while (bson_iter_next (&iter)) {
         uint32_t len;
         uint8_t *data;

         mongocrypt_binary_destroy (bin);
         data = (uint8_t *) bson_iter_utf8 (&iter, &len);
         bin = mongocrypt_binary_new_from_data (data, len);
         if (!mongocrypt_kms_ctx_feed (kms_ctx, bin)) {
            mongocrypt_kms_ctx_status (kms_ctx, status);
            goto failed;
         }
      }

      if (!mongocrypt_ctx_kms_done (ctx)) {
         mongocrypt_ctx_status (ctx, status);
         goto failed;
      }

      ok = true;

   failed:
      BSON_ASSERT (bson_iter_init_find (&iter, test, "expect"));
      if (BSON_ITER_HOLDS_ARRAY (&iter)) {
         // Concatenate array into one string.
         bson_string_t *builder = bson_string_new (NULL);
         bson_iter_recurse (&iter, &iter);
         while (bson_iter_next (&iter)) {
            ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
            bson_string_append (builder, bson_iter_utf8 (&iter, NULL));
         }
         expect = bson_string_free (builder, false /* free segment */);
      } else {
         expect = bson_strdup (bson_iter_utf8 (&iter, NULL));
      }

      if (0 == strcmp ("ok", expect)) {
         ASSERT_OR_PRINT (ok, status);
      } else {
         ASSERT_STATUS_CONTAINS (status, expect);
      }

      bson_free (expect);
      mongocrypt_binary_destroy (bin);
      mongocrypt_status_destroy (status);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }
}

static void
_test_kms_responses (_mongocrypt_tester_t *tester)
{
   bson_t test_file;
   bson_iter_t iter;

   _load_json_as_bson ("./test/data/kms-tests.json", &test_file);
   for (bson_iter_init (&iter, &test_file); bson_iter_next (&iter);) {
      bson_t test;

      bson_iter_bson (&iter, &test);
      _test_one_kms_response (tester, &test);
      bson_destroy (&test);
   }
   bson_destroy (&test_file);
}

void
_mongocrypt_tester_install_kms_responses (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_kms_responses);
}
