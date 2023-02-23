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
#include <mongocrypt-crypto-private.h>

#include "test-mongocrypt.h"

typedef struct {
   const char *name;
   const _mongocrypt_value_encryption_algorithm_t *algo;
   _mongocrypt_buffer_t key;
   _mongocrypt_buffer_t aad;
   _mongocrypt_buffer_t iv;
   _mongocrypt_buffer_t plaintext;
   _mongocrypt_buffer_t ciphertext;
   const char *encrypt_error;
   const char *decrypt_error;
   // Special case test for payload which decrypts to empty string.
   bool ignore_ciphertext_mismatch_on_encrypt;
} _test_mc_crypto_roundtrip_t;

static bool
_test_uses_ctr (const _test_mc_crypto_roundtrip_t *test)
{
   return (test->algo == _mcFLE2AEADAlgorithm ()) ||
          (test->algo == _mcFLE2Algorithm ());
}

#define ASSERT_BAD_DECRYPT(ret, out, test, status)                    \
   if (test->algo == _mcFLE2Algorithm ()) {                           \
      /* A bad decrypt with CTR and no MAC isn't directly visible, */ \
      /* we just get garbage data. */                                 \
      ASSERT (out.len == test->plaintext.len);                        \
      ASSERT (memcmp (out.data, test->plaintext.data, out.len) != 0); \
   } else {                                                           \
      ASSERT_FAILS_STATUS (ret, status, "HMAC validation failure");   \
   }

static void
_test_roundtrip_single (const _test_mc_crypto_roundtrip_t *test)
{
   if (!_aes_ctr_is_supported_by_os && _test_uses_ctr (test)) {
      printf ("Common Crypto with no CTR support detected. Skipping %s",
              test->name);
      return;
   }

   printf ("Begin %s...\n", test->name);

   mongocrypt_t *crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_status_t *const status = mongocrypt_status_new ();
   _mongocrypt_buffer_t out;

   // Test encrypt
   _mongocrypt_buffer_init_size (
      &out, test->algo->get_ciphertext_len (test->plaintext.len, status));
   ASSERT_OK_STATUS (true, status);
   uint32_t outlen;
   bool ret = test->algo->do_encrypt (crypt->crypto,
                                      &test->iv,
                                      &test->aad,
                                      &test->key,
                                      &test->plaintext,
                                      &out,
                                      &outlen,
                                      status);
   if (test->encrypt_error) {
      ASSERT_FAILS_STATUS (ret, status, test->encrypt_error);
      goto done;
   } else if (test->ignore_ciphertext_mismatch_on_encrypt) {
      _mongocrypt_status_reset (status);
   } else {
      ASSERT_OK_STATUS (ret, status);
      out.len = outlen;
      ASSERT_CMPBUF (out, test->ciphertext);
   }

   // Test decrypt
   const uint32_t plaintext_len =
      test->algo->get_plaintext_len (test->ciphertext.len, status);
   if (test->decrypt_error && !mongocrypt_status_ok (status)) {
      ASSERT_FAILS_STATUS (false, status, test->decrypt_error);
      goto done;
   }
   ASSERT_OK_STATUS (true, status);
   _mongocrypt_buffer_resize (&out, plaintext_len);
   ret = test->algo->do_decrypt (crypt->crypto,
                                 &test->aad,
                                 &test->key,
                                 &test->ciphertext,
                                 &out,
                                 &outlen,
                                 status);
   if (test->decrypt_error) {
      ASSERT_FAILS_STATUS (ret, status, test->decrypt_error);
      goto done;
   }
   ASSERT_OK_STATUS (ret, status);
   out.len = outlen;
   ASSERT_CMPBUF (out, test->plaintext);

   // Negative: Mutated IV
   _mongocrypt_buffer_t modified_ciphertext = {0};
   _mongocrypt_buffer_copy_to (&test->ciphertext, &modified_ciphertext);
   _mongocrypt_buffer_resize (&out, plaintext_len);
   modified_ciphertext.data[0] ^= 1;
   ret = test->algo->do_decrypt (crypt->crypto,
                                 &test->aad,
                                 &test->key,
                                 &modified_ciphertext,
                                 &out,
                                 &outlen,
                                 status);
   out.len = outlen;
   ASSERT_BAD_DECRYPT (ret, out, test, status);

   // Negative: Mutated ciphertext
   _mongocrypt_buffer_copy_to (&test->ciphertext, &modified_ciphertext);
   _mongocrypt_buffer_resize (&out, plaintext_len);
   modified_ciphertext.data[MONGOCRYPT_IV_LEN] ^= 1;
   ret = test->algo->do_decrypt (crypt->crypto,
                                 &test->aad,
                                 &test->key,
                                 &modified_ciphertext,
                                 &out,
                                 &outlen,
                                 status);
   ASSERT_BAD_DECRYPT (ret, out, test, status);

   // Negative: Mutated tag
   // Note: On algorithms without HMAC, this just repeats the mutated ciphertext
   // test in a different part of S.
   _mongocrypt_buffer_copy_to (&test->ciphertext, &modified_ciphertext);
   _mongocrypt_buffer_resize (&out, plaintext_len);
   modified_ciphertext.data[modified_ciphertext.len - 1] ^= 1;
   ret = test->algo->do_decrypt (crypt->crypto,
                                 &test->aad,
                                 &test->key,
                                 &modified_ciphertext,
                                 &out,
                                 &outlen,
                                 status);
   ASSERT_BAD_DECRYPT (ret, out, test, status);

   _mongocrypt_buffer_cleanup (&modified_ciphertext);
done:
   _mongocrypt_buffer_cleanup (&out);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);

   printf ("End %s...\n", test->name);
}

static const _mongocrypt_value_encryption_algorithm_t *
get_algo_by_name (const char *name)
{
   if (!strcmp (name, "AES-256-CBC/SHA-512-256") || !strcmp (name, "FLE1")) {
      return _mcFLE1Algorithm ();
   }
   if (!strcmp (name, "AES-256-CTR/SHA-256") || !strcmp (name, "FLE2AEAD")) {
      return _mcFLE2AEADAlgorithm ();
   }
   if (!strcmp (name, "AES-256-CTR/NONE") || !strcmp (name, "FLE2")) {
      return _mcFLE2Algorithm ();
   }
   if (!strcmp (name, "AES-256-CBC/SHA-256") || !strcmp (name, "FLE2v2")) {
      return _mcFLE2v2Algorithm ();
   }
   TEST_ERROR ("Unknown algorithm: %s", name);
}

static void
_parse_roundtrip_test (bson_iter_t *iter, _test_mc_crypto_roundtrip_t *test)
{
   while (bson_iter_next (iter)) {
      const char *field = bson_iter_key (iter);
      ASSERT (field);

      if (!strcmp (field, "algo")) {
         ASSERT_OR_PRINT_MSG (!test->algo, "Duplicate field 'algo' in test");
         ASSERT (BSON_ITER_HOLDS_UTF8 (iter));
         test->algo = get_algo_by_name (bson_iter_utf8 (iter, NULL));
      } else if (!strcmp (field, "ignore_ciphertext_mismatch_on_encrypt")) {
         ASSERT_OR_PRINT_MSG (
            !test->ignore_ciphertext_mismatch_on_encrypt,
            "Duplicate field 'ignore_ciphertext_mismatch_on_encrypt' in test");
         ASSERT (BSON_ITER_HOLDS_BOOL (iter));
         ASSERT_OR_PRINT_MSG (
            bson_iter_bool (iter),
            "value of 'ignore_ciphertext_mismatch_on_encrypt' must be true");
         test->ignore_ciphertext_mismatch_on_encrypt = true;
      }

#define STR_FIELD(Name)                                            \
   else if (!strcmp (field, #Name))                                \
   {                                                               \
      ASSERT_OR_PRINT_MSG (!test->Name,                            \
                           "Duplicate field '" #Name "' in test"); \
      ASSERT (BSON_ITER_HOLDS_UTF8 (iter));                        \
      test->Name = bson_strdup (bson_iter_utf8 (iter, NULL));      \
   }

      STR_FIELD (name)
      STR_FIELD (encrypt_error)
      STR_FIELD (decrypt_error)

#undef STR_FIELD

// If we encounter a zero-length hexit string,
// then mcb_copy_from_hex will leave the buffer unallocated.
// This complicates field detection when we want an empty plaintext.
// Similarly, mcb_init_size will not allocate a lenght of zero.
// Simplify the flow elsewhere by allocating 1 byte, then truncating.
#define HEXBUF_FIELD(Name)                                         \
   else if (!strcmp (field, #Name))                                \
   {                                                               \
      ASSERT_OR_PRINT_MSG (!test->Name.data,                       \
                           "Duplicate field '" #Name "' in test"); \
      ASSERT (BSON_ITER_HOLDS_UTF8 (iter));                        \
      const char *value = bson_iter_utf8 (iter, NULL);             \
      const size_t value_len = strlen (value);                     \
      if (value_len > 0) {                                         \
         _mongocrypt_buffer_copy_from_hex (&test->Name, value);    \
         ASSERT (strlen (value) == (test->Name.len * 2));          \
      } else {                                                     \
         _mongocrypt_buffer_init_size (&test->Name, 1);            \
         test->Name.len = 0;                                       \
      }                                                            \
   }

      HEXBUF_FIELD (key)
      HEXBUF_FIELD (aad)
      HEXBUF_FIELD (iv)
      HEXBUF_FIELD (plaintext)
      HEXBUF_FIELD (ciphertext)
#undef HEXBUF_FIELD
   }

   ASSERT_OR_PRINT_MSG (test->name, "Missing field 'name'");
   ASSERT_OR_PRINT_MSG (test->algo, "Missing field 'algo'");
   ASSERT_OR_PRINT_MSG (test->key.data, "Missing field 'key'");
   if (test->algo == _mcFLE2Algorithm ()) {
      ASSERT_OR_PRINT_MSG (
         test->aad.len == 0,
         "Unexpected value in field 'aad' for cipher without MAC");
   } else {
      ASSERT_OR_PRINT_MSG (test->aad.data, "Missing field 'aad'");
   }
   ASSERT_OR_PRINT_MSG (test->iv.data, "Missing field 'iv'");
   ASSERT_OR_PRINT_MSG (test->plaintext.data, "Missing field 'plaintext'");
   ASSERT_OR_PRINT_MSG (test->ciphertext.data || test->encrypt_error,
                        "Missing field 'ciphertext'");
}

static void
_test_mc_crypto_roundtrip_destroy (_test_mc_crypto_roundtrip_t *test)
{
   if (test->name) {
      bson_free ((void *) test->name);
   }
   _mongocrypt_buffer_cleanup (&test->key);
   _mongocrypt_buffer_cleanup (&test->aad);
   _mongocrypt_buffer_cleanup (&test->iv);
   _mongocrypt_buffer_cleanup (&test->plaintext);
   _mongocrypt_buffer_cleanup (&test->ciphertext);
   if (test->encrypt_error) {
      bson_free ((void *) test->encrypt_error);
   }
   if (test->decrypt_error) {
      bson_free ((void *) test->decrypt_error);
   }
}

static void
_test_roundtrip_set (_mongocrypt_tester_t *tester, const char *path)
{
   printf ("Loading tests from %s...\n", path);

   mongocrypt_binary_t *test_bin = TEST_FILE (path);
   if (!test_bin) {
      TEST_ERROR ("Failed loading test data file '%s'\n", path);
   }
   if (test_bin->len == 5) {
      TEST_ERROR ("Invalid JSON in file '%s'\n", path);
   }

   bson_t test_bson;
   ASSERT (bson_init_static (&test_bson, test_bin->data, test_bin->len));
   ASSERT (bson_validate (&test_bson, BSON_VALIDATE_NONE, NULL));

   bson_iter_t it;
   ASSERT (bson_iter_init (&it, &test_bson));
   while (bson_iter_next (&it)) {
      bson_iter_t docit;
      ASSERT (BSON_ITER_HOLDS_DOCUMENT (&it));
      ASSERT (bson_iter_recurse (&it, &docit));
      _test_mc_crypto_roundtrip_t test = {0};
      _parse_roundtrip_test (&docit, &test);
      _test_roundtrip_single (&test);
      _test_mc_crypto_roundtrip_destroy (&test);
   }

   printf ("Finished tests in %s\n", path);
}

static void
_test_roundtrip (_mongocrypt_tester_t *tester)
{
   _test_roundtrip_set (tester, "./test/data/roundtrip/mcgrew.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/nist.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/aes-ctr.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/fle2v2-fixed.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/fle2v2-generated.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/fle2aead-fixed.json");
   _test_roundtrip_set (tester,
                        "./test/data/roundtrip/fle2aead-generated.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/fle2aead-decrypt.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/fle2-fixed.json");
   _test_roundtrip_set (tester, "./test/data/roundtrip/fle2-generated.json");
}

typedef struct {
   const char *testname;
   const char *key;
   const char *input;
   const char *expect;
} hmac_sha_256_test_t;

void
_test_native_crypto_hmac_sha_256 (_mongocrypt_tester_t *tester)
{
   /* Test data generated with OpenSSL CLI:
   $ echo -n "test" | openssl dgst -mac hmac -macopt \
   hexkey:6bb2664e8d444377d3cd9566c005593b7ed8a35ab8eac9eb5ffa6e426854e5cc \
   -sha256
     d80a4d2271fdaa45ad4a1bf85d606fe465cb40176d1d83e69628a154c2c528ff

   Hex representation of "test" is: 74657374
   */
   hmac_sha_256_test_t tests[] = {
      {.testname = "String 'test'",
       .key = "6bb2664e8d444377d3cd9566c005593b"
              "7ed8a35ab8eac9eb5ffa6e426854e5cc",
       .input = "74657374",
       .expect = "d80a4d2271fdaa45ad4a1bf85d606fe4"
                 "65cb40176d1d83e69628a154c2c528ff"},
      {.testname = "Data larger than one block",
       .key = "6bb2664e8d444377d3cd9566c005593b"
              "7ed8a35ab8eac9eb5ffa6e426854e5cc",
       .input = "fd2368de92202a33fcaf48f9b5807fc8"
                "6b9837aa376beb6044d6db6b07347f7e"
                "2af3eedfc968218f76b588fff9ae1c91"
                "74cca2368389bf211270f0449771c260"
                "689bb59a32f0c5ae40372ecb371ec2a7"
                "2179bbe8d46260eef7d0e7c1ae679b71",
       .expect = "1985743613238e3c8c05a0274be76fa6"
                 "7821228f7b880e72dbd0f314fb63e63f"},
#include "./data/NIST-CAVP.cstructs"
      {0}};
   hmac_sha_256_test_t *test;
   mongocrypt_t *crypt;

   /* Create a mongocrypt_t to call _native_crypto_init(). */
   crypt = mongocrypt_new ();

   for (test = tests; test->testname != NULL; test++) {
      bool ret;
      _mongocrypt_buffer_t key;
      _mongocrypt_buffer_t input;
      _mongocrypt_buffer_t expect;
      _mongocrypt_buffer_t got;
      mongocrypt_status_t *status;


      printf ("Begin test '%s'.\n", test->testname);

      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&input, test->input);
      _mongocrypt_buffer_copy_from_hex (&expect, test->expect);
      _mongocrypt_buffer_init (&got);
      _mongocrypt_buffer_resize (&got, MONGOCRYPT_HMAC_SHA256_LEN);
      status = mongocrypt_status_new ();

      ret = _native_crypto_hmac_sha_256 (&key, &input, &got, status);
      ASSERT_OR_PRINT (ret, status);
      if (expect.len < got.len) {
         /* Some NIST CAVP tests expect the output tag to be truncated. */
         got.len = expect.len;
      }
      ASSERT_CMPBYTES (expect.data, expect.len, got.data, got.len);

      mongocrypt_status_destroy (status);
      _mongocrypt_buffer_cleanup (&got);
      _mongocrypt_buffer_cleanup (&expect);
      _mongocrypt_buffer_cleanup (&input);
      _mongocrypt_buffer_cleanup (&key);

      printf ("End test '%s'.\n", test->testname);
   }

   mongocrypt_destroy (crypt);
}

static bool
_hook_hmac_sha_256 (void *ctx,
                    mongocrypt_binary_t *key,
                    mongocrypt_binary_t *in,
                    mongocrypt_binary_t *out,
                    mongocrypt_status_t *status)
{
   const uint8_t *data_to_copy = (const uint8_t *) ctx;
   uint8_t *outdata = mongocrypt_binary_data (out);
   uint32_t outlen = mongocrypt_binary_len (out);

   ASSERT_CMPINT ((int) outlen, ==, 32);
   memcpy (outdata, data_to_copy, outlen);
   return true;
}

static void
_test_mongocrypt_hmac_sha_256_hook (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   _mongocrypt_crypto_t crypto = {0};
   _mongocrypt_buffer_t key = {0};
   _mongocrypt_buffer_t in = {0};
   _mongocrypt_buffer_t expect;
   _mongocrypt_buffer_t got;
   mongocrypt_status_t *status;

   /* Create a mongocrypt_t to call _native_crypto_init(). */
   crypt = mongocrypt_new ();

   status = mongocrypt_status_new ();
   _mongocrypt_buffer_resize (&key, MONGOCRYPT_MAC_KEY_LEN);
   _mongocrypt_buffer_copy_from_hex (&expect,
                                     "000102030405060708090A0B0C0D0E0F"
                                     "101112131415161718191A1B1C1D1E1F");
   _mongocrypt_buffer_init (&got);
   _mongocrypt_buffer_resize (&got, MONGOCRYPT_HMAC_SHA256_LEN);

   crypto.hooks_enabled = true;
   crypto.hmac_sha_256 = _hook_hmac_sha_256;
   crypto.ctx = expect.data;

   ASSERT_OR_PRINT (_mongocrypt_hmac_sha_256 (&crypto, &key, &in, &got, status),
                    status);

   ASSERT_CMPBYTES (expect.data, expect.len, got.data, got.len);

   _mongocrypt_buffer_cleanup (&got);
   _mongocrypt_buffer_cleanup (&expect);
   _mongocrypt_buffer_cleanup (&key);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

static void
_test_random_int64 (_mongocrypt_tester_t *tester)
{
   bool got0 = false, got1 = false, got2 = false;
   int trial;
   const int max_trials = 1000;
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   status = mongocrypt_status_new ();

   for (trial = 0; trial < max_trials; trial++) {
      int64_t got;

      ASSERT_OR_PRINT (
         _mongocrypt_random_int64 (crypt->crypto, 3, &got, status), status);
      switch (got) {
      case 0:
         got0 = true;
         break;
      case 1:
         got1 = true;
         break;
      case 2:
         got2 = true;
         break;
      default:
         TEST_ERROR (
            "Expected random number to be in range [0,3), got: %" PRId64, got);
      }
   }

   ASSERT (got0);
   ASSERT (got1);
   ASSERT (got2);

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_crypto (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_roundtrip);
   INSTALL_TEST (_test_native_crypto_hmac_sha_256);
   INSTALL_TEST_CRYPTO (_test_mongocrypt_hmac_sha_256_hook, CRYPTO_OPTIONAL);
   INSTALL_TEST (_test_random_int64);
}
