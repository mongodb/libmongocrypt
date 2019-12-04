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

static void
_test_explicit_decrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *msg;
   crypt = _mongocrypt_tester_mongocrypt ();

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

   crypt = _mongocrypt_tester_mongocrypt ();

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
   crypt = _mongocrypt_tester_mongocrypt ();
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
   crypt = _mongocrypt_tester_mongocrypt ();

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
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   mongocrypt_ctx_setopt_key_alt_name (
      ctx, TEST_BSON ("{'keyAltName': 'keyDocumentName'}"));
   mongocrypt_ctx_setopt_algorithm (
      ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
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

void
_mongocrypt_tester_install_ctx_decrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_explicit_decrypt_init);
   INSTALL_TEST (_test_decrypt_init);
   INSTALL_TEST (_test_decrypt_need_keys);
   INSTALL_TEST (_test_decrypt_ready);
   INSTALL_TEST (_test_decrypt_empty_aws);
   INSTALL_TEST (_test_decrypt_empty_binary);
}
