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

#include "mongocrypt-config.h"
#include "mongocrypt-private.h"
#include "mongocrypt-crypto-private.h"

#include "test-mongocrypt.h"

#define IV_HEX "1F572A1B84EC8F99B7915AA2A2AEA2F4"
#define HMAC_HEX                                                      \
   "60676DE9FD305FD2C0815763C422687270DA2416D94A917B276E9DCBB13F412F" \
   "92FA403AA8AE172BD2E4729ED352793795EE588A2977C9C1F218D2AAD779C997"
/* only the first 32 bytes are appended. */
#define HMAC_HEX_TAG \
   "60676DE9FD305FD2C0815763C422687270DA2416D94A917B276E9DCBB13F412F"

#define HMAC_KEY_HEX \
   "CCD3836C8F24AC5FAAFAAA630C5C6C5D210FD03934EA1440CD67E0DCDE3F8EA6"
#define ENCRYPTION_KEY_HEX \
   "E1D1727BAF970E01181C0868CB9D3E574B47AC09771FF30FE2D093B0950C7DAF"
#define IV_KEY_HEX \
   "0A9328FCB6405ABDF5B4BFEC243FE9CF503CD4F24360872B75F08A2A3961802B"
/* full 96 byte key consists of three "sub" keys */
#define KEY_HEX HMAC_KEY_HEX ENCRYPTION_KEY_HEX IV_KEY_HEX
#define HASH_HEX \
   "489EC3238378DC624C74B8CC4598ACED2B7EA5DE5C5F7602D8761BAE92FD8ABE"
#define RANDOM_HEX                                                             \
   "670ACBB44D4E04A279CC0B95D217493205A038C50F537F452C59EFF6541D0026670ACBB44" \
   "D4E04A279CC0B95D217493205A038C50F537F452C59EFF6541D0026670ACBB44D4E04A279" \
   "CC0B95D217493205A038C50F537F452C59EFF6541D0026"

/* a document containing the history of calls */
static bson_string_t *call_history;

static void
_append_bin (const char *name, mongocrypt_binary_t *bin)
{
   _mongocrypt_buffer_t tmp;
   char *hex;

   _mongocrypt_buffer_from_binary (&tmp, bin);
   hex = _mongocrypt_buffer_to_hex (&tmp);
   bson_string_append_printf (call_history, "%s:%s\n", name, hex);
   bson_free (hex);
   _mongocrypt_buffer_cleanup (&tmp);
}


static bool
_aes_256_cbc_encrypt (void *ctx,
                      mongocrypt_binary_t *key,
                      mongocrypt_binary_t *iv,
                      mongocrypt_binary_t *in,
                      mongocrypt_binary_t *out,
                      uint32_t *bytes_written,
                      mongocrypt_status_t *status)
{
   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("iv", iv);
   _append_bin ("in", in);
   /* append it directly, don't encrypt. */
   memcpy (out->data + *bytes_written, in->data, in->len);
   *bytes_written += in->len;
   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);
   if (0 == strcmp ((char *) ctx, "error_on:aes_256_cbc_encrypt")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

static bool
_aes_256_cbc_decrypt (void *ctx,
                      mongocrypt_binary_t *key,
                      mongocrypt_binary_t *iv,
                      mongocrypt_binary_t *in,
                      mongocrypt_binary_t *out,
                      uint32_t *bytes_written,
                      mongocrypt_status_t *status)
{
   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("iv", iv);
   _append_bin ("in", in);
   /* append it directly, don't decrypt. */
   memcpy (out->data + *bytes_written, in->data, in->len);
   *bytes_written += in->len;
   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);
   if (0 == strcmp ((char *) ctx, "error_on:aes_256_cbc_decrypt")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

bool
_hmac_sha_512 (void *ctx,
               mongocrypt_binary_t *key,
               mongocrypt_binary_t *in,
               mongocrypt_binary_t *out,
               mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t tmp;

   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("in", in);

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_copy_from_hex (&tmp, HMAC_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   if (0 == strcmp ((char *) ctx, "error_on:hmac_sha512")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

bool
_hmac_sha_256 (void *ctx,
               mongocrypt_binary_t *key,
               mongocrypt_binary_t *in,
               mongocrypt_binary_t *out,
               mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t tmp;

   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("in", in);

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_copy_from_hex (&tmp, HASH_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   if (0 == strcmp ((char *) ctx, "error_on:hmac_sha256")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

bool
_sha_256 (void *ctx,
          mongocrypt_binary_t *in,
          mongocrypt_binary_t *out,
          mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t tmp;

   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("in", in);

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_copy_from_hex (&tmp, HASH_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   if (0 == strcmp ((char *) ctx, "error_on:sha256")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

bool
_random (void *ctx,
         mongocrypt_binary_t *out,
         uint32_t count,
         mongocrypt_status_t *status)
{
   /* only have 32 bytes of random test data. */
   BSON_ASSERT (count <= 96);

   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   bson_string_append_printf (call_history, "count:%d\n", (int) count);
   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);

   _mongocrypt_buffer_t tmp;
   _mongocrypt_buffer_copy_from_hex (&tmp, RANDOM_HEX);
   memcpy (out->data, tmp.data, count);
   _mongocrypt_buffer_cleanup (&tmp);
   if (0 == strcmp ((char *) ctx, "error_on:random")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

bool
_sign_rsaes_pkcs1_v1_5 (void *ctx,
                        mongocrypt_binary_t *key,
                        mongocrypt_binary_t *in,
                        mongocrypt_binary_t *out,
                        mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t tmp;

   BSON_ASSERT (0 == strncmp ("error_on:", (char *) ctx, strlen ("error_on:")));
   bson_string_append_printf (call_history, "call:%s\n", BSON_FUNC);
   _append_bin ("key", key);
   _append_bin ("in", in);

   bson_string_append_printf (call_history, "ret:%s\n", BSON_FUNC);
   memset (out->data, 0, out->len);

   _mongocrypt_buffer_copy_from_hex (&tmp, HASH_HEX);
   memcpy (out->data, tmp.data, tmp.len);
   _mongocrypt_buffer_cleanup (&tmp);
   if (0 == strcmp ((char *) ctx, "error_on:sign_rsaes_pkcs1_v1_5")) {
      mongocrypt_status_set (
         status, MONGOCRYPT_STATUS_ERROR_CLIENT, 1, "error message", -1);
      return false;
   }
   return true;
}

static mongocrypt_t *
_create_mongocrypt (_mongocrypt_tester_t *tester, const char *error_on)
{
   bool ret;

   mongocrypt_t *crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1),
      crypt);
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (
         crypt,
         TEST_BSON ("{'gcp': { 'email': 'test', 'privateKey': 'AAAA'}}")),
      crypt);
   ret = mongocrypt_setopt_crypto_hooks (crypt,
                                         _aes_256_cbc_encrypt,
                                         _aes_256_cbc_decrypt,
                                         _random,
                                         _hmac_sha_512,
                                         _hmac_sha_256,
                                         _sha_256,
                                         (void *) error_on);
   ASSERT_OK (ret, crypt);
   ret = mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5 (
      crypt, _sign_rsaes_pkcs1_v1_5, (void *) error_on);
   ASSERT_OK (ret, crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   return crypt;
}


static void
_test_crypto_hooks_encryption_helper (_mongocrypt_tester_t *tester,
                                      const char *error_on)
{
   mongocrypt_t *crypt;
   bool ret;
   uint32_t bytes_written;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t iv, associated_data, key, plaintext, ciphertext;
   const char *expected_call_history =
      "call:_aes_256_cbc_encrypt\n"
      "key:" ENCRYPTION_KEY_HEX "\n"
      "iv:" IV_HEX "\n"
      "in:BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E\n"
      "ret:_aes_256_cbc_encrypt\n"
      "call:_hmac_sha_512\n"
      "key:CCD3836C8F24AC5FAAFAAA630C5C6C5D210FD03934EA1440CD67E0DCDE3F8EA6\n"
      "in:AAAA" IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E0000000000000010\n"
      "ret:_hmac_sha_512\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt (tester, error_on);

   _mongocrypt_buffer_copy_from_hex (&iv, IV_HEX);
   _mongocrypt_buffer_copy_from_hex (&associated_data, "AAAA");
   _mongocrypt_buffer_copy_from_hex (&key, KEY_HEX);
   _mongocrypt_buffer_copy_from_hex (&plaintext, "BBBB");

   _mongocrypt_buffer_init (&ciphertext);
   _mongocrypt_buffer_resize (
      &ciphertext, _mongocrypt_calculate_ciphertext_len (plaintext.len));

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_do_encryption (crypt->crypto,
                                    &iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext,
                                    &bytes_written,
                                    status);

   if (0 == strcmp (error_on, "error_on:none")) {
      ASSERT_OK_STATUS (ret, status);
      ciphertext.len = bytes_written;

      /* Check the full trace. */
      ASSERT_STREQUAL (call_history->str, expected_call_history);

      /* Check the structure of the ciphertext */
      BSON_ASSERT (
         0 == _mongocrypt_buffer_cmp_hex (
                 &ciphertext,
                 IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E" /* the "encrypted"
                                                            block which is
                                                            really plaintext.
                                                            BBBB + padding. */
                 HMAC_HEX_TAG));
   } else {
      ASSERT_FAILS_STATUS (ret, status, "error message");
   }


   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&ciphertext);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


static void
_test_crypto_hooks_encryption (_mongocrypt_tester_t *tester)
{
   _test_crypto_hooks_encryption_helper (tester, "error_on:none");
   _test_crypto_hooks_encryption_helper (tester,
                                         "error_on:aes_256_cbc_encrypt");
   _test_crypto_hooks_encryption_helper (tester, "error_on:hmac_sha512");
}


static void
_test_crypto_hooks_decryption_helper (_mongocrypt_tester_t *tester,
                                      const char *error_on)
{
   mongocrypt_t *crypt;
   bool ret;
   uint32_t bytes_written;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t associated_data, key, plaintext, ciphertext;
   const char *expected_call_history =
      "call:_hmac_sha_512\n"
      "key:" HMAC_KEY_HEX "\n"
      "in:AAAA" IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E0000000000000010\n"
      "ret:_hmac_sha_512\n"
      "call:_aes_256_cbc_decrypt\n"
      "key:" ENCRYPTION_KEY_HEX "\n"
      "iv:" IV_HEX "\n"
      "in:BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E\n"
      "ret:_aes_256_cbc_decrypt\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt (tester, error_on);

   _mongocrypt_buffer_copy_from_hex (&associated_data, "AAAA");
   _mongocrypt_buffer_copy_from_hex (&key, KEY_HEX);
   _mongocrypt_buffer_copy_from_hex (
      &ciphertext, IV_HEX "BBBB0E0E0E0E0E0E0E0E0E0E0E0E0E0E" HMAC_HEX_TAG);

   _mongocrypt_buffer_init (&plaintext);
   _mongocrypt_buffer_resize (
      &plaintext, _mongocrypt_calculate_plaintext_len (ciphertext.len));

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &plaintext,
                                    &bytes_written,
                                    status);

   if (0 == strcmp (error_on, "error_on:none")) {
      ASSERT_OK_STATUS (ret, status);
      plaintext.len = bytes_written;

      /* Check the full trace. */
      ASSERT_STREQUAL (call_history->str, expected_call_history);

      /* Check the resulting plaintext */
      BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (&plaintext, "BBBB"));
   } else {
      ASSERT_FAILS_STATUS (ret, status, "error message");
   }

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&ciphertext);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}

static void
_test_crypto_hooks_decryption (_mongocrypt_tester_t *tester)
{
   _test_crypto_hooks_decryption_helper (tester, "error_on:none");
   _test_crypto_hooks_decryption_helper (tester,
                                         "error_on:aes_256_cbc_decrypt");
   _test_crypto_hooks_decryption_helper (tester, "error_on:hmac_sha512");
}

static void
_test_crypto_hooks_iv_gen_helper (_mongocrypt_tester_t *tester, char *error_on)
{
   mongocrypt_t *crypt;
   bool ret;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t associated_data, key, plaintext, iv;
   char *expected_iv = bson_strndup (
      HMAC_HEX_TAG, 16 * 2); /* only the first 16 bytes are used for IV. */
   const char *expected_call_history = "call:_hmac_sha_512\n"
                                       "key:" IV_KEY_HEX "\n"
                                       "in:AAAA0000000000000010BBBB\n"
                                       "ret:_hmac_sha_512\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt (tester, error_on);

   _mongocrypt_buffer_copy_from_hex (&associated_data, "AAAA");
   _mongocrypt_buffer_copy_from_hex (&key, KEY_HEX);
   _mongocrypt_buffer_copy_from_hex (&plaintext, "BBBB");

   _mongocrypt_buffer_init (&iv);
   _mongocrypt_buffer_resize (&iv, MONGOCRYPT_IV_LEN);

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_calculate_deterministic_iv (
      crypt->crypto, &key, &plaintext, &associated_data, &iv, status);

   if (0 == strcmp (error_on, "error_on:none")) {
      ASSERT_OK_STATUS (ret, status);

      /* Check the full trace. */
      ASSERT_STREQUAL (call_history->str, expected_call_history);

      /* Check the resulting iv */
      BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (&iv, expected_iv));
   } else {
      ASSERT_FAILS_STATUS (ret, status, "error message");
   }

   bson_free (expected_iv);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&iv);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}

static void
_test_crypto_hooks_iv_gen (_mongocrypt_tester_t *tester)
{
   _test_crypto_hooks_iv_gen_helper (tester, "error_on:none");
   _test_crypto_hooks_iv_gen_helper (tester, "error_on:hmac_sha512");
}


static void
_test_crypto_hooks_random_helper (_mongocrypt_tester_t *tester,
                                  const char *error_on)
{
   mongocrypt_t *crypt;
   bool ret;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t random;
   const char *expected_call_history = "call:_random\n"
                                       "count:96\n"
                                       "ret:_random\n";

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt (tester, error_on);

   _mongocrypt_buffer_init (&random);
   _mongocrypt_buffer_resize (&random, 96);

   call_history = bson_string_new (NULL);

   ret = _mongocrypt_random (crypt->crypto, &random, random.len, status);

   if (0 == strcmp (error_on, "error_on:none")) {
      ASSERT_OK_STATUS (ret, status);

      /* Check the full trace. */
      ASSERT_STREQUAL (call_history->str, expected_call_history);

      /* Check the resulting iv */
      BSON_ASSERT (0 == _mongocrypt_buffer_cmp_hex (&random, RANDOM_HEX));
   } else {
      ASSERT_FAILS_STATUS (ret, status, "error message");
   }

   _mongocrypt_buffer_cleanup (&random);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}

static void
_test_crypto_hooks_random (_mongocrypt_tester_t *tester)
{
   _test_crypto_hooks_random_helper (tester, "error_on:none");
   _test_crypto_hooks_random_helper (tester, "error_on:random");
}

static void
_test_kms_request (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_ctx_t *ctx;

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt (tester, "error_on:none");
   ctx = mongocrypt_ctx_new (crypt);

   call_history = bson_string_new (NULL);

   ASSERT_OK (
      mongocrypt_ctx_setopt_masterkey_aws (ctx, "us-east-1", -1, "cmk", -1),
      ctx);
   ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);

   /* The call history includes some random data, just assert we've called our
    * hooks. */
   BSON_ASSERT (strstr (call_history->str, "call:_hmac_sha_256"));
   BSON_ASSERT (strstr (call_history->str, "call:_sha_256"));

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}


static void
_test_crypto_hooks_unset (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;

   crypt = mongocrypt_new ();
   mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1);
   ASSERT_FAILS (mongocrypt_init (crypt), crypt, "crypto hooks required");
   mongocrypt_destroy (crypt);
}


/* test a bug fix, that an error on explicit encryption in the crypto hooks sets
 * the context state */
static void
_test_crypto_hooks_explicit_err (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin, *key_id;
   char *deterministic = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";

   call_history = bson_string_new (NULL);

   /* error on something during encryption. */
   crypt = _create_mongocrypt (tester, "error_on:hmac_sha512");

   ctx = mongocrypt_ctx_new (crypt);
   key_id = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("aaaaaaaaaaaaaaaa"));

   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (
      mongocrypt_ctx_explicit_encrypt_init (ctx, TEST_BSON ("{'v': 123}")),
      ctx);

   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   bin = mongocrypt_binary_new ();
   ASSERT_FAILS (mongocrypt_ctx_finalize (ctx, bin), ctx, "error message");
   BSON_ASSERT (MONGOCRYPT_CTX_ERROR == mongocrypt_ctx_state (ctx));
   mongocrypt_binary_destroy (bin);
   mongocrypt_binary_destroy (key_id);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}

/* validate that sha256 errors are handled correctly */
static void
_test_crypto_hooks_explicit_sha256_err (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_ctx_t *ctx;

   status = mongocrypt_status_new ();
   crypt = _create_mongocrypt (tester, "error_on:sha256");
   ctx = mongocrypt_ctx_new (crypt);

   call_history = bson_string_new (NULL);

   ASSERT_OK (
      mongocrypt_ctx_setopt_masterkey_aws (ctx, "us-east-1", -1, "cmk", -1),
      ctx);
   ASSERT_FAILS (
      mongocrypt_ctx_datakey_init (ctx), ctx, "failed to create KMS message");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}

static void
_test_crypto_hook_sign_rsaes_pkcs1_v1_5 (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _create_mongocrypt (tester, "error_on:none");
   call_history = bson_string_new (NULL);

   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_setopt_key_encryption_key (
      ctx,
      TEST_BSON ("{'provider': 'gcp', 'projectId': 'test', 'location': "
                 "'global', 'keyRing': 'ring', 'keyName': 'key'}"));
   ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);

   BSON_ASSERT (strstr (call_history->str, "call:_sign_rsaes_pkcs1_v1_5"));
   BSON_ASSERT (strstr (call_history->str, "key:000000"));

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);

   /* Test error when creating a data key. */
   crypt = _create_mongocrypt (tester, "error_on:sign_rsaes_pkcs1_v1_5");
   ctx = mongocrypt_ctx_new (crypt);
   call_history = bson_string_new (NULL);

   mongocrypt_ctx_setopt_key_encryption_key (
      ctx,
      TEST_BSON ("{'provider': 'gcp', 'projectId': 'test', 'location': "
                 "'global', 'keyRing': 'ring', 'keyName': 'key'}"));
   ASSERT_FAILS (
      mongocrypt_ctx_datakey_init (ctx), ctx, "error constructing KMS message");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);

   /* Test error when encrypting. */
   crypt = _create_mongocrypt (tester, "error_on:sign_rsaes_pkcs1_v1_5");
   ctx = mongocrypt_ctx_new (crypt);
   call_history = bson_string_new (NULL);

   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/data/key-document-gcp.json")),
                 ctx,
                 "error constructing KMS message");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   bson_string_free (call_history, true);
}

void
_mongocrypt_tester_install_crypto_hooks (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_encryption, CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_decryption, CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_iv_gen, CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_random, CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_kms_request, CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_unset, CRYPTO_PROHIBITED);
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_explicit_err, CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_crypto_hooks_explicit_sha256_err,
                        CRYPTO_OPTIONAL);
   INSTALL_TEST_CRYPTO (_test_crypto_hook_sign_rsaes_pkcs1_v1_5,
                        CRYPTO_OPTIONAL);
}
