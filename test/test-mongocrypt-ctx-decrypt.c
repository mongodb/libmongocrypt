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

#include "mongocrypt-ctx-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt.h"
#include "test-mongocrypt-assert-match-bson.h"

static void
_test_explicit_decrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *msg;
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   msg = TEST_BSON ("{ 'v': { '$binary': { 'subType': '06', 'base64': "
                    "'AWFhYWFhYWFhYWFhYWFhYWECRTOW9yZzNDn5dGwuqsrJQNLtgMEKaujhs"
                    "9aRWRp+7Yo3JK8N8jC8P0Xjll6C1CwLsE/"
                    "iP5wjOMhVv1KMMyOCSCrHorXRsb2IKPtzl2lKTqQ=' } } }");

   /* NULL document. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_explicit_decrypt_init (ctx, NULL), ctx, "invalid msg");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_explicit_decrypt_init (ctx, msg), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


/* Test individual ctx states. */
static void
_test_decrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   encrypted = _mongocrypt_tester_encrypted_doc (tester);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   /* NULL document. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_decrypt_init (ctx, NULL), ctx, "invalid doc");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_binary_destroy (encrypted);
   mongocrypt_destroy (crypt);
}


static void
_test_decrypt_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted;

   encrypted = _mongocrypt_tester_encrypted_doc (tester);

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/key-document.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* TODO: CDRIVER-3044 test that decryption warns when keys are not
    * found/inactive. */

   mongocrypt_binary_destroy (encrypted);
}


static void
_test_decrypt_ready (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted, *decrypted;
   bson_t as_bson;
   bson_iter_t iter;

   encrypted = _mongocrypt_tester_encrypted_doc (tester);
   decrypted = mongocrypt_binary_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, decrypted), ctx);
   BSON_ASSERT (_mongocrypt_binary_to_bson (decrypted, &as_bson));
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
   BSON_ASSERT (0 == strcmp (bson_iter_utf8 (&iter, NULL),
                             _mongocrypt_tester_plaintext (tester)));
   mongocrypt_binary_destroy (decrypted);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   mongocrypt_binary_destroy (encrypted);
}


/* Test with empty AWS credentials. */
void
_test_decrypt_empty_aws (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_setopt_kms_provider_aws (crypt, "", -1, "", -1),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (
                 ctx, TEST_FILE ("./test/data/encrypted-cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/example/key-document.json")),
                 ctx,
                 "failed to create KMS message");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_empty_binary (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   _mongocrypt_buffer_t encrypted;

   bin = mongocrypt_binary_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   mongocrypt_ctx_setopt_key_alt_name (
      ctx, TEST_BSON ("{'keyAltName': 'keyDocumentName'}"));
   mongocrypt_ctx_setopt_algorithm (
      ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1);
   mongocrypt_ctx_explicit_encrypt_init (
      ctx,
      TEST_BSON ("{'v': { '$binary': { 'base64': '', 'subType': '00' } } }"));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);
   /* Copy the encrypted ciphertext since it is tied to the lifetime of ctx. */
   _mongocrypt_buffer_copy_from_binary (&encrypted, bin);
   mongocrypt_ctx_destroy (ctx);

   /* Decrypt it back. */
   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (
      ctx, _mongocrypt_buffer_as_binary (&encrypted));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   _mongocrypt_buffer_cleanup (&encrypted);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_per_ctx_credentials (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   _mongocrypt_buffer_t encrypted;

   bin = mongocrypt_binary_new ();
   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'aws': {}}"));
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   mongocrypt_ctx_setopt_key_alt_name (
      ctx, TEST_BSON ("{'keyAltName': 'keyDocumentName'}"));
   mongocrypt_ctx_setopt_algorithm (
      ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1);
   mongocrypt_ctx_explicit_encrypt_init (
      ctx,
      TEST_BSON ("{'v': { '$binary': { 'base64': '', 'subType': '00' } } }"));
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   ASSERT_OK (mongocrypt_ctx_provide_kms_providers (
                 ctx,
                 TEST_BSON ("{'aws':{'accessKeyId': 'example',"
                            "'secretAccessKey': 'example'}}")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);
   /* Copy the encrypted ciphertext since it is tied to the lifetime of ctx. */
   _mongocrypt_buffer_copy_from_binary (&encrypted, bin);
   mongocrypt_ctx_destroy (ctx);

   /* Decrypt it back. */
   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (
      ctx, _mongocrypt_buffer_as_binary (&encrypted));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   _mongocrypt_buffer_cleanup (&encrypted);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_per_ctx_credentials_local (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   _mongocrypt_buffer_t encrypted;
   /* local_kek is the KEK used to encrypt the keyMaterial in
    * ./test/data/key-document-local.json */
   const char *local_kek =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
   /* local_uuid is the hex of the UUID of the key in
    * ./test/data/key-document-local.json */
   const char *local_uuid = "61616161616161616161616161616161";
   _mongocrypt_buffer_t local_uuid_buf;

   bin = mongocrypt_binary_new ();
   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'local': {}}"));
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   _mongocrypt_buffer_copy_from_hex (&local_uuid_buf, local_uuid);
   mongocrypt_ctx_setopt_key_id (
      ctx, _mongocrypt_buffer_as_binary (&local_uuid_buf));
   mongocrypt_ctx_setopt_algorithm (
      ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1);
   mongocrypt_ctx_explicit_encrypt_init (
      ctx,
      TEST_BSON ("{'v': { '$binary': { 'base64': '', 'subType': '00' } } }"));
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   ASSERT_OK (mongocrypt_ctx_provide_kms_providers (
                 ctx,
                 TEST_BSON ("{'local':{'key': { '$binary': {'base64': '%s', "
                            "'subType': '00'}}}}",
                            local_kek)),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-local.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);
   /* Copy the encrypted ciphertext since it is tied to the lifetime of ctx. */
   _mongocrypt_buffer_copy_from_binary (&encrypted, bin);
   mongocrypt_ctx_destroy (ctx);

   /* Decrypt it back. */
   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (
      ctx, _mongocrypt_buffer_as_binary (&encrypted));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);

   _mongocrypt_buffer_cleanup (&local_uuid_buf);
   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   _mongocrypt_buffer_cleanup (&encrypted);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_fle2 (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t K_KeyId;

   if (!_aes_ctr_is_supported_by_os) {
      printf ("Common Crypto with no CTR support detected. Skipping.");
      return;
   }

#define TEST_IEEV_BASE64                                                       \
   "BxI0VngSNJh2EjQSNFZ4kBICQ7uhTd9C2oI8M1afRon0ZaYG0s6oTmt0aBZ9kO4S4mm5vId01" \
   "BsW7tBHytA8pDJ2IiWBCmah3OGH2M4ET7PSqekQD4gkUCo4JeEttx4yj05Ou4D6yZUmYfVKmE" \
   "ljge16NCxKm7Ir9gvmQsp8x1wqGBzpndA6gkqFxsxfvQ/"                             \
   "cIqOwMW9dGTTWsfKge+jYkCUIFMfms+XyC/8evQhjjA+qR6eEmV+N/"                    \
   "kwpR7Q7TJe0lwU5kw2kSe3/KiPKRZZTbn8znadvycfJ0cCWGad9SQ=="

   _mongocrypt_buffer_copy_from_hex (&S_KeyId,
                                     "12345678123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (&K_KeyId,
                                     "ABCDEFAB123498761234123456789012");

   /* Test success with an FLE2IndexedEqualityEncryptedValue payload. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      {
         mongocrypt_binary_t *filter = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, filter), ctx);
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_FILE ("./test/data/fle2-decrypt-ieev/first-filter.json"),
            filter);
         mongocrypt_binary_destroy (filter);
      }
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      {
         mongocrypt_binary_t *filter = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, filter), ctx);
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_FILE ("./test/data/fle2-decrypt-ieev/second-filter.json"),
            filter);
         mongocrypt_binary_destroy (filter);
      }
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Test success with a non-local KMS provider. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-aws-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
      {
         mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
         ASSERT (kms_ctx);
         ASSERT_OK (mongocrypt_kms_ctx_feed (
                       kms_ctx,
                       TEST_FILE ("./test/data/keys/"
                                  "12345678123498761234123456789012-"
                                  "aws-decrypt-reply.txt")),
                    kms_ctx);
         ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx));
         ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
      }
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-aws-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
      {
         mongocrypt_kms_ctx_t *kms_ctx = mongocrypt_ctx_next_kms_ctx (ctx);
         ASSERT (kms_ctx);
         ASSERT_OK (mongocrypt_kms_ctx_feed (
                       kms_ctx,
                       TEST_FILE ("./test/data/keys/"
                                  "ABCDEFAB123498761234123456789012-"
                                  "aws-decrypt-reply.txt")),
                    kms_ctx);
         ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx));
         ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
      }
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Test success with two FLE2IndexedEqualityEncryptedValue payloads. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted1':{'$binary':{'base64'"
                       ":'" TEST_IEEV_BASE64 "','subType':'6'}}, "
                       "'encrypted2':{'$binary':{'base64':'" TEST_IEEV_BASE64
                       "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (&out_bson,
                          TMP_BSON ("{'plainText': 'sample', 'encrypted1': "
                                    "'value123', 'encrypted2': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Test success when S_Key is cached, K_Key is not cached. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "' " TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      mongocrypt_ctx_destroy (ctx);

      /* Create a new context. S_Key is cached in crypt. */
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123' }"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Test success when S_Key is cached, K_Key is cached. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      mongocrypt_ctx_destroy (ctx);

      /* Create a new ctx. S_Key and K_Key are cached in crypt. */
      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      out = mongocrypt_binary_new ();
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Test error when S_Key is not provided. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_FAILS (mongocrypt_ctx_mongo_done (ctx),
                    ctx,
                    "not all keys requested were satisfied");
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Test error when K_Key is not provided. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IEEV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_FAILS (mongocrypt_ctx_mongo_done (ctx),
                    ctx,
                    "not all keys requested were satisfied");
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   _mongocrypt_buffer_cleanup (&K_KeyId);
   _mongocrypt_buffer_cleanup (&S_KeyId);

#undef TEST_IEEV_BASE64
}

static void
_test_explicit_decrypt_fle2_ieev (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t K_KeyId;

   if (!_aes_ctr_is_supported_by_os) {
      printf ("Common Crypto with no CTR support detected. Skipping.");
      return;
   }

#define TEST_IEEV_BASE64                                                       \
   "BxI0VngSNJh2EjQSNFZ4kBICQ7uhTd9C2oI8M1afRon0ZaYG0s6oTmt0aBZ9kO4S4mm5vId01" \
   "BsW7tBHytA8pDJ2IiWBCmah3OGH2M4ET7PSqekQD4gkUCo4JeEttx4yj05Ou4D6yZUmYfVKmE" \
   "ljge16NCxKm7Ir9gvmQsp8x1wqGBzpndA6gkqFxsxfvQ/"                             \
   "cIqOwMW9dGTTWsfKge+jYkCUIFMfms+XyC/8evQhjjA+qR6eEmV+N/"                    \
   "kwpR7Q7TJe0lwU5kw2kSe3/KiPKRZZTbn8znadvycfJ0cCWGad9SQ=="

   _mongocrypt_buffer_copy_from_hex (&S_KeyId,
                                     "12345678123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (&K_KeyId,
                                     "ABCDEFAB123498761234123456789012");

   /* Test success with an FLE2IndexedEqualityEncryptedValue payload. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (mongocrypt_ctx_explicit_decrypt_init (
                    ctx,
                    TEST_BSON ("{'v':{'$binary':{'base64': '" TEST_IEEV_BASE64
                               "','subType':'6'}}}")),
                 ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (&out_bson, TMP_BSON ("{'v': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }
   _mongocrypt_buffer_cleanup (&K_KeyId);
   _mongocrypt_buffer_cleanup (&S_KeyId);

#undef TEST_IEEV_BASE64
}

#define TEST_IUP_BASE64                                                        \
   "BHEBAAAFZAAgAAAAAHb62aV7+mqmaGcotPLdG3KP7S8diFwWMLM/"                      \
   "5rYtqLrEBXMAIAAAAAAVJ6OWHRv3OtCozHpt3ZzfBhaxZirLv3B+"                      \
   "G8PuaaO4EgVjACAAAAAAsZXWOWA+UiCBbrJNB6bHflB/"                              \
   "cn7pWSvwWN2jw4FPeIUFcABQAAAAAMdD1nV2nqeI1eXEQNskDflCy8I7/"                 \
   "HvvqDKJ6XxjhrPQWdLqjz+8GosGUsB7A8ee/uG9/"                                  \
   "guENuL25XD+"                                                               \
   "Fxxkv1LLXtavHOlLF7iW0u9yabqqBXUAEAAAAAQSNFZ4EjSYdhI0EjRWeJASEHQAAgAAAAV2A" \
   "E0AAAAAq83vqxI0mHYSNBI0VniQEkzZZBBDgeZh+h+gXEmOrSFtVvkUcnHWj/"             \
   "rfPW7iJ0G3UJ8zpuBmUM/VjOMJCY4+eDqdTiPIwX+/vNXegc8FZQAgAAAAAOuac/"          \
   "eRLYakKX6B0vZ1r3QodOQFfjqJD+xlGiPu4/PsAA=="

static void
_test_decrypt_fle2_iup (_mongocrypt_tester_t *tester)
{
   if (!_aes_ctr_is_supported_by_os) {
      printf ("Common Crypto with no CTR support detected. Skipping.");
      return;
   }

   /* Test success with an FLE2InsertUpdatePayload. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IUP_BASE64 "','subType':'6'}}}")),
         ctx);

      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (
            ctx,
            TEST_FILE ("./test/data/keys/"
                       "ABCDEFAB123498761234123456789012-local-document.json")),
         ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }
}
#undef TEST_IUP_BASE64

/* Test decrypting a BSON binary non-subtype 6 is an error. */
static void
_test_decrypt_wrong_binary_subtype (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *ctx = mongocrypt_ctx_new (crypt);
   /* Use subtype 0. */
   ASSERT_FAILS (
      mongocrypt_ctx_explicit_decrypt_init (
         ctx,
         TEST_BSON (
            "{'v': { '$binary': { 'base64': 'AAAA', 'subType': '00' }}}")),
      ctx,
      "decryption expected BSON binary subtype 6, got 0");
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

/* Test decrypting FLE2IndexedRangeEncryptedValue */
static void
_test_decrypt_fle2_irev (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t K_KeyId;

   if (!_aes_ctr_is_supported_by_os) {
      printf ("Common Crypto with no CTR support detected. Skipping.");
      return;
   }

#define TEST_IREV_BASE64                                                       \
   "CRI0VngSNJh2EjQSNFZ4kBIQsPF0Ii0Hfv7ZMhnNt/yt+mviydF8EUw0YlO+amC3IF8dX2J/"  \
   "GmRZRnihW3VqJYoLMk0BIit0x9YQiQEEQPxPcTXnCx4t1fquOY7cRGqIAWTDHuQ9AdUw94EY1" \
   "J55mq9UhwD7flh0ySR/SbkTwjIU32U1iM6Bv4AriE4smI87Yd0V7Z7kDoDx7afx9vM/"       \
   "+h9NWZvpfYcZ+P32sfILb3BdXT5zLrkyc5Xb3myDxE9abTrR8ePG0YuEmeqwGE4bZ6QHKzd/"  \
   "RLmHciWstKOtER5uRpo3p570wGO8QE9QtQoJp/7N7Su30dK/"                          \
   "bk59hVvlNO6i3nUPwqMd13DePobNGn84q3Fag5O4Kw8P4EGfomFWzxydlVQ0SppGVfan9tIj1" \
   "CFu5doYYT4adzX7L9HinKsTWE5ctD9Qxhhzb2cVs5JO96j4mpwOaloF/"                  \
   "4qJhyqlzTEpoCXGQ0X9aeEplibFxQ7FJkaFfYzIDIxA2d6lzwVel3j+VwQ7zOP/"           \
   "bCnaFu6EP1OQw3ZarsaWGENf45DFuK5RsKX198vZTlqtH24YhAL1+noQTMtpTOp/"          \
   "6vrczOXkr7dJGQ6RAfliq1maD18PN5yjdyNhr7BXsrK6f01DX2Xr4s51AARxQ/"            \
   "0U5hmb4HjKg8Sbno4Th+Wza3I0RMgM0YzhRUJz+BXzx2l9NPdeyuECdQ1Q2wP1MNOCBy/"     \
   "QBJmc+"                                                                    \
   "RWYK57oWCuv5vmkpN8IlriyRv0PGRhYr4ZcLkDdzmuyfK6SGAvIPD4veDJRj3cXEazyMh6g+"  \
   "rvwt70laxo2IOhvUXDc89WvarthTOzlFt5FNrA8uXhUYyL1q1XSWYCiCu5vRv77BvRUJjf2B6" \
   "5kaIKUAGDhYuhch2yU6O9VsHLik3xOGSwIUZJbdMyHY+eA8ZlWZeKJbpjz7a/"             \
   "TyBQU6VNG4+Z5SXJjURogkODNkx21QS0Z1+b7ZnCSXf1OQceomkDrREB7vyD2HX5rN2/"      \
   "KIBMgH3J7DnG2VpNhYJ9Ve1hMDGcrQggjkCpdP7lloc6QiH837tD/81gYmr95IbuIHe/"      \
   "x20oHh9heGHUELnCQ6hXYWOBvSFlGcqZs/"                                        \
   "f0qxn5Fe2OfQPRzEstxoW99IdPvgotDnL2vaz2JNFvFqiofc2pIP7XvpFKIoQO7q8LX9z7ah1" \
   "Yh8cbi6us8g5y9WzOfh882jU7vQT+31a1ZaeDMbFV1Cemc+/"                          \
   "d0HNksi1qMJtcjrH2MQgXJ3BTyAuJH9OFK8iGqSzHhop9hp5z8mvx834PPjgBfZGt4w/"      \
   "7qeie+T4sooGVVqA6F3jl8YfFdIUAwkxe5GBQVVvaRLYm/"                            \
   "4SLGBf54Dexi7e0+rL2sG5DeKygNdFzMc6lRO+"                                    \
   "gvmAMmDucRm4bxmu7ycNZCQUcuSKoMUWWu6A6eUiyBCQUxrrlX/"                       \
   "3CkRXkQQ6JCwZZMvTgBokYx3WQR6LpW70xWLXyQhav4ZnHKzgITSOe7mUkMJ35NDMD+"       \
   "qsxXY7sWbGz+b60DWF7yaMVzDPzIGjWLpckMRMxgN3bQ5SE/mFxdjoZD5yYb84q/"          \
   "O7EjwGA9MSTp9MFEZt7VV3f5TDWiNUZKmjUgOdjBoTSAkVzAO2nqqQNg23x6Z6FQDBeefRkfc" \
   "9FoUiBqHuN4fU/zc4Hkthp1McwIkYwRdlgPceD/"                                   \
   "BSNbkNRNAnzghBhCquIqpXd8AptBX2qO67rfT7COhpn/"                              \
   "fzVo3ueCRTaM2DtjD3uuH4rMNb3LDjyJFX1DZ5eEWkGq9UE/"                          \
   "AFivfeia4cA0a8Z1LzZcW7WvE5Y1WIZN4gy9SZcNgHEQq8Ad8Q4fAbxe8XJ6/"             \
   "tNvG+AvAuLEvNJtbhC/4Ei/"                                                   \
   "JoXplvutDlW5d6g4KEWj4GICqggM5ZSv0TCkbfFkLdaJrOHrn+oI++"                    \
   "krv1U4yQk6P18Mg2bE18ibe+LdWNsqn01V7yDmS+"                                  \
   "VAvqQF8f2p4rOOyWsGc7CoyXSrq9LCuGq9eMPR6auo+"                               \
   "tyS1Nek2t6SgpOpzBBDdQnC5sHC1OWTW3ui7w4H0NKCuZOiMncbSDOlegn8C0zZa6Z5iYAce8" \
   "a8Ow3jryBEnKBaguhjjOMG8iX/eka8XP+UTxvso4fKVVOXQwobZMdYbf/"                 \
   "sXNJbMbWrFc1S9rdlXL/"                                                      \
   "nnYvYrRMnOBJ27Mz5vvtOpd4fyQ+wi1q+"                                         \
   "5VvuLDM8u51B4oaYqpGUZZ3qVS5BBYm9cDxgMtcdoXjOSopHasdAhron+"                 \
   "NdbGFBxyrUGKnnVXYocEuvsvwhBEA3HUUVV94m3C0agh2eVpmCIyWrs+"                  \
   "grkpAaNLZwXVuzegttJ0GoTxzQnDIWkvlvkS3ZGo25spfPp+/Nda4SZAYRNmtnGfB2TRl0Wx/" \
   "o/"                                                                        \
   "V2vx+9qnGyDq52CSkMftpfnsMXAnAv6ps7U+"                                      \
   "mgbgNPUFjv1Y0xKaeJdshu1HyEmq5aYqHJSfF2EzvPfH4d0Ijz1lsxMxL4IsqB7kufcOR4FFn" \
   "aYXKIXLjRwM5VZNAK/3dvCb3l9H7QMOiJPbdoxAd123aymjz9N/"                       \
   "2O33wMaG6OE8pXp0iYEaW7DOr0FfT913JeUnPNPcqqsA9YXod2UuNWZElTW/"              \
   "saL32v9akNwA4Jd7Y5VgI4y+XyDH3kAU0Uc8g6YCx/hqcn4pd2+ryH+/"                  \
   "5nVQhnCE0KNOjjrFS92RNLD71GUhWR+VXMw2tKXBUSKnt9Ai4LLJrdvFbwrdqK+"           \
   "AjBUVqI3MgylNxRw2395ppAbheE1pAcoqLoDOGyOs66Y8kJGpaqs0AmdmZHw2OA26btw+"     \
   "ceBN+UgScsB5P5wNIup1AvU5J7h1vlFBNygg3WO/MJGCz48xgJ/"                       \
   "klg9wCLQ+vXtrhYJz15RgguADFLBrTcV/Miel20KulnprI+/"                          \
   "lXtRvEAoGJSc0UZ8J7UVTf8kvYzT3hF7XzZzlhKxPYebjdnp2la4o2PkyZXcc/"            \
   "gFLa7ickR28ZPUigwpW0lK5sJIwWbnZmP5wbQNhiGO8QL9gVpFOnu0xHpu8MqBvfZGf2HiE+"  \
   "qBUSR89v88gz6u/TVP9zVH1dnk9PE54Uw3yPdxL/"                                  \
   "feukvF71sEI6WWd2fdupgRlDGzASrKSAsFbaZobwUViEIFbWo7zPYVZyMglCrD1Xoxdd6EBeU" \
   "SJDkS1nhiHOR/7FpIhae8fggAD+StXR7725vzcwIOX21ozRcE2iWw6OP99vDoqLQ8VYzYS0/"  \
   "f3WMME6b5ndYz25uC0AiULXYI="

   _mongocrypt_buffer_copy_from_hex (&S_KeyId,
                                     "12345678123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (&K_KeyId,
                                     "ABCDEFAB123498761234123456789012");

   /* Test success with an FLE2IndexedEqualityEncryptedValue payload. */
   {
      mongocrypt_t *crypt =
         _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (
         mongocrypt_ctx_decrypt_init (
            ctx,
            TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':"
                       "'" TEST_IREV_BASE64 "','subType':'6'}}}")),
         ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      {
         mongocrypt_binary_t *filter = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, filter), ctx);
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_FILE ("./test/data/fle2-decrypt-ieev/first-filter.json"),
            filter);
         mongocrypt_binary_destroy (filter);
      }
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "12345678123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests K_Key.
       */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      {
         mongocrypt_binary_t *filter = mongocrypt_binary_new ();
         ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, filter), ctx);
         ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
            TEST_FILE ("./test/data/fle2-decrypt-ieev/second-filter.json"),
            filter);
         mongocrypt_binary_destroy (filter);
      }
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/"
                               "ABCDEFAB123498761234123456789012-local-"
                               "document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   _mongocrypt_buffer_cleanup (&K_KeyId);
   _mongocrypt_buffer_cleanup (&S_KeyId);

#undef TEST_IREV_BASE64
}

void
_mongocrypt_tester_install_ctx_decrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_explicit_decrypt_init);
   INSTALL_TEST (_test_decrypt_init);
   INSTALL_TEST (_test_decrypt_need_keys);
   INSTALL_TEST (_test_decrypt_ready);
   INSTALL_TEST (_test_decrypt_empty_aws);
   INSTALL_TEST (_test_decrypt_empty_binary);
   INSTALL_TEST (_test_decrypt_per_ctx_credentials);
   INSTALL_TEST (_test_decrypt_per_ctx_credentials_local);
   INSTALL_TEST (_test_decrypt_fle2);
   INSTALL_TEST (_test_explicit_decrypt_fle2_ieev);
   INSTALL_TEST (_test_decrypt_fle2_iup);
   INSTALL_TEST (_test_decrypt_wrong_binary_subtype);
   INSTALL_TEST (_test_decrypt_fle2_irev);
}
