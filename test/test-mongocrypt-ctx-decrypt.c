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

#include "mongocrypt.h"
#include "mongocrypt-ctx-private.h"
#include "test-mongocrypt.h"
#include "mongocrypt-ctx-private.h"

static void
_test_explicit_decrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted;

   crypt = _mongocrypt_tester_mongocrypt ();

   encrypted = _mongocrypt_tester_encrypted_doc (tester);

   /* NULL document. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_explicit_decrypt_init (ctx, NULL), ctx, "invalid doc");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_explicit_decrypt_init (ctx, encrypted), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_binary_destroy (encrypted);
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
   mongocrypt_binary_t *encrypted, *key;

   encrypted = _mongocrypt_tester_encrypted_doc (tester);

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   key = _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, key), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (key);
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
   _mongocrypt_binary_to_bson (decrypted, &as_bson);
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


static void
_get_bytes (const void *in, char *out, int len)
{
   const unsigned char *p = in;

   for (int i = 0, offset = 0; i < len; offset += 3, i++) {
      snprintf (out + offset,
                sizeof (out) / sizeof (char),
                "%02X%c",
                p[i],
                i == len - 1 ? '\0' : ' ');
   }
}

void
_test_mongocrypt_buffer_to_bson_value (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t plaintext = {0};
   uint8_t element_type;
   char *data = "dummy_data";
   char actual[100] = {0};

   element_type = 2;
   plaintext.len = 1 + strlen (data);
   plaintext.data = bson_malloc0 (plaintext.len);
   memcpy (plaintext.data, data, plaintext.len);

   _get_bytes (plaintext.data, actual, plaintext.len);
   BSON_ASSERT (0 == strcmp ("64 75 6D 6D 79 5F 64 61 74 61 00", actual));

   _mongocrypt_buffer_to_bson_value (&plaintext, &element_type);
   _get_bytes (plaintext.data, actual, plaintext.len);
   BSON_ASSERT (
      0 ==
      strcmp ("12 00 00 00 02 00 64 75 6D 6D 79 5F 64 61 74 61 00 00", actual));

   bson_free (plaintext.data);
}

void
_mongocrypt_tester_install_ctx_decrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_decrypt_init);
   INSTALL_TEST (_test_decrypt_need_keys);
   INSTALL_TEST (_test_decrypt_ready);
   INSTALL_TEST (_test_mongocrypt_buffer_to_bson_value);
}
