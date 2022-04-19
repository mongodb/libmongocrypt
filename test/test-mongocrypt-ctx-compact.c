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

#include "test-mongocrypt.h"
#include "test-mongocrypt-assert-match-bson.h"

static void
_test_compact_success (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   efc = TEST_FILE ("./test/data/efc/efc-oneField.json");

   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, efc), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (
            ctx,
            TEST_FILE ("./test/data/keys/"
                       "12345678123498761234123456789012-local-document.json")),
         ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      bson_t out_bson;
      mongocrypt_binary_t *out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'compactionTokens': {'firstName': {'$binary': {'base64': "
                   "'noN+05JsuO1oDg59yypIGj45i+eFH6HOTXOPpeZ//Mk=','subType': "
                   "'0'}}}}"));
      mongocrypt_binary_destroy (out);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_compact_nonlocal_kms (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   efc = TEST_FILE ("./test/data/efc/efc-oneField.json");

   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, efc), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (
            ctx,
            TEST_FILE ("./test/data/keys/"
                       "12345678123498761234123456789012-aws-document.json")),
         ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   {
      mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
      ASSERT (kms_ctx);
      ASSERT_OK (
         mongocrypt_kms_ctx_feed (kms_ctx,
                                  TEST_FILE ("./test/data/keys/"
                                             "12345678123498761234123456789012-"
                                             "aws-decrypt-reply.txt")),
         kms_ctx);
      ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx));
      ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      bson_t out_bson;
      mongocrypt_binary_t *out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'compactionTokens': {'firstName': {'$binary': {'base64': "
                   "'noN+05JsuO1oDg59yypIGj45i+eFH6HOTXOPpeZ//Mk=','subType': "
                   "'0'}}}}"));
      mongocrypt_binary_destroy (out);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_compact_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Test success. */
   {
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_compact_init (
            ctx, TEST_FILE ("./test/data/efc/efc-oneField.json")),
         ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      mongocrypt_ctx_destroy (ctx);
   }

   /* Test bad EncryptedFieldConfig. */
   {
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_FAILS (
         mongocrypt_ctx_compact_init (
            ctx, TEST_FILE ("./test/data/efc/efc-missingKeyId.json")),
         ctx,
         "unable to find 'keyId' in 'field' document");
      mongocrypt_ctx_destroy (ctx);
   }

   /* Test incorrect option. */
   {
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (mongocrypt_ctx_setopt_algorithm (
                    ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1),
                 ctx);
      ASSERT_FAILS (
         mongocrypt_ctx_compact_init (
            ctx, TEST_FILE ("./test/data/efc/efc-missingKeyId.json")),
         ctx,
         "algorithm prohibited");
      mongocrypt_ctx_destroy (ctx);
   }

   mongocrypt_destroy (crypt);
}

static void
_test_compact_key_not_provided (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   efc = TEST_FILE ("./test/data/efc/efc-oneField.json");

   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, efc), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_done (ctx),
                 ctx,
                 "not all keys requested were satisfied");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_compact_need_kms_credentials (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'aws': {}}")),
      crypt);
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   efc = TEST_FILE ("./test/data/efc/efc-oneField.json");

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, efc), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   {
      ASSERT_OK (mongocrypt_ctx_provide_kms_providers (
                    ctx,
                    TEST_BSON ("{'aws': {"
                               "   'accessKeyId': 'example',"
                               "   'secretAccessKey': 'example'}}")),
                 ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (
            ctx,
            TEST_FILE ("./test/data/keys/"
                       "12345678123498761234123456789012-aws-document.json")),
         ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   {
      mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
      ASSERT (kms_ctx);
      ASSERT_OK (
         mongocrypt_kms_ctx_feed (kms_ctx,
                                  TEST_FILE ("./test/data/keys/"
                                             "12345678123498761234123456789012-"
                                             "aws-decrypt-reply.txt")),
         kms_ctx);
      ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx));
      ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      bson_t out_bson;
      mongocrypt_binary_t *out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'compactionTokens': {'firstName': {'$binary': {'base64': "
                   "'noN+05JsuO1oDg59yypIGj45i+eFH6HOTXOPpeZ//Mk=','subType': "
                   "'0'}}}}"));
      mongocrypt_binary_destroy (out);
   }


   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_compact_no_fields (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);

   efc = TEST_BSON ("{'escCollection': 'esc', 'eccCollection': 'ecc', "
                    "'ecocCollection': 'ecoc', 'fields': []}");

   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, efc), ctx);

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      bson_t out_bson;
      mongocrypt_binary_t *out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (&out_bson, TMP_BSON ("{'compactionTokens': {}}"));
      mongocrypt_binary_destroy (out);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_ctx_compact (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_compact_success);
   INSTALL_TEST (_test_compact_nonlocal_kms);
   INSTALL_TEST (_test_compact_init);
   INSTALL_TEST (_test_compact_key_not_provided);
   INSTALL_TEST (_test_compact_need_kms_credentials);
   INSTALL_TEST (_test_compact_no_fields);
}
