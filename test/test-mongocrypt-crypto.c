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

static void
_test_roundtrip (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key = {0}, iv = {0}, associated_data = {0},
                        plaintext = {0}, ciphertext = {0}, decrypted = {0};
   uint32_t bytes_written;
   bool ret;

   crypt = _mongocrypt_tester_mongocrypt ();
   plaintext.data = (uint8_t *) "test";
   plaintext.len = 5; /* include NULL. */

   ciphertext.len = _mongocrypt_calculate_ciphertext_len (5);
   ciphertext.data = bson_malloc (ciphertext.len);
   BSON_ASSERT (ciphertext.data);

   ciphertext.owned = true;

   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   BSON_ASSERT (decrypted.data);

   decrypted.owned = true;

   key.data = (uint8_t *) _mongocrypt_repeat_char ('k', MONGOCRYPT_KEY_LEN);
   key.len = MONGOCRYPT_KEY_LEN;
   key.owned = true;

   iv.data = (uint8_t *) _mongocrypt_repeat_char ('i', MONGOCRYPT_IV_LEN);
   iv.len = MONGOCRYPT_IV_LEN;
   iv.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (crypt->crypto,
                                    &iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);

   BSON_ASSERT (bytes_written == ciphertext.len);

   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &decrypted,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);


   BSON_ASSERT (bytes_written == plaintext.len);
   decrypted.len = bytes_written;
   BSON_ASSERT (0 == strcmp ((char *) decrypted.data, (char *) plaintext.data));

   /* Modify a bit in the ciphertext hash to ensure HMAC integrity check. */
   ciphertext.data[ciphertext.len - 1] ^= 1;

   _mongocrypt_buffer_cleanup (&decrypted);
   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   BSON_ASSERT (decrypted.data);

   decrypted.owned = true;

   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &decrypted,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (!ret);
   BSON_ASSERT (0 == strcmp (mongocrypt_status_message (status, NULL),
                             "HMAC validation failure"));
   /* undo the change (flip the bit again). Double check that decryption works
    * again. */
   ciphertext.data[ciphertext.len - 1] ^= 1;
   _mongocrypt_status_reset (status);
   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &decrypted,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);

   /* Modify parts of the key. */
   key.data[0] ^= 1; /* part of the mac key */
   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &decrypted,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (!ret);
   BSON_ASSERT (0 == strcmp (mongocrypt_status_message (status, NULL),
                             "HMAC validation failure"));
   /* undo */
   key.data[0] ^= 1;
   _mongocrypt_status_reset (status);

   /* Modify the portion of the key responsible for encryption/decryption */
   key.data[MONGOCRYPT_MAC_KEY_LEN + 1] ^= 1; /* part of the encryption key */
   ret = _mongocrypt_do_decryption (crypt->crypto,
                                    &associated_data,
                                    &key,
                                    &ciphertext,
                                    &decrypted,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (!ret);
   BSON_ASSERT (0 == strcmp (mongocrypt_status_message (status, NULL),
                             "error, ciphertext malformed padding"));

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&decrypted);
   _mongocrypt_buffer_cleanup (&ciphertext);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   mongocrypt_destroy (crypt);
}


/* From [MCGREW], see comment at the top of this file. */
static void
_test_mcgrew (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key, iv, associated_data, plaintext,
      ciphertext_expected, ciphertext_actual;
   uint32_t bytes_written;
   bool ret;

   _mongocrypt_buffer_copy_from_hex (
      &key,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1"
      "b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
      "3738393a3b3c3d3e3f"
      /* includes our additional 32 byte IV key */
      "0000000000000000000000000000000000000000000000000000000000000000");
   _mongocrypt_buffer_copy_from_hex (&iv, "1af38c2dc2b96ffdd86694092341bc04");
   _mongocrypt_buffer_copy_from_hex (
      &plaintext,
      "41206369706865722073797374656d206d757374206e6f742"
      "0626520726571756972656420746f20626520736563726574"
      "2c20616e64206974206d7573742062652061626c6520746f2"
      "066616c6c20696e746f207468652068616e6473206f662074"
      "686520656e656d7920776974686f757420696e636f6e76656"
      "e69656e6365");
   _mongocrypt_buffer_copy_from_hex (
      &associated_data,
      "546865207365636f6e64207072696e6369706c65206"
      "f662041756775737465204b6572636b686f666673");
   _mongocrypt_buffer_copy_from_hex (
      &ciphertext_expected,
      "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10f"
      "fbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e"
      "9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75"
      "c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae4"
      "96b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930"
      "930806d0703b1f64dd3b4c088a7f45c216839645b2012bf2e6269a8c56a81"
      "6dbc1b267761955bc5");

   ciphertext_actual.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext_actual.data = bson_malloc (ciphertext_actual.len);
   BSON_ASSERT (ciphertext_actual.data);

   ciphertext_actual.owned = true;

   /* Force the crypto stack to initialize with mongocrypt_new */
   crypt = _mongocrypt_tester_mongocrypt ();
   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (crypt->crypto,
                                    &iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext_actual,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);
   BSON_ASSERT (ciphertext_actual.len == ciphertext_expected.len);
   BSON_ASSERT (0 == memcmp (ciphertext_actual.data,
                             ciphertext_expected.data,
                             ciphertext_actual.len));

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&ciphertext_expected);
   _mongocrypt_buffer_cleanup (&ciphertext_actual);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

typedef struct {
   const char *testname;
   const char *key;
   const char *iv;
   const char *plaintext;
   const char *ciphertext;
} aes_256_ctr_test_t;

void
_test_native_crypto_aes_256_ctr (_mongocrypt_tester_t *tester)
{
   aes_256_ctr_test_t tests[] = {
      {.testname = "See NIST SP 800-38A section F.5.5",
       .key = "603deb1015ca71be2b73aef0857d7781"
              "1f352c073b6108d72d9810a30914dff4",
       .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
       .plaintext = "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710",
       .ciphertext = "601ec313775789a5b7a7f504bbf3d228"
                     "f443e3ca4d62b59aca84e990cacaf5c5"
                     "2b0930daa23de94ce87017ba2d84988d"
                     "dfc9c58db67aada613c2dd08457941a6"},
      {.testname = "Not 64 byte aligned input",
       .key = "603deb1015ca71be2b73aef0857d7781"
              "1f352c073b6108d72d9810a30914dff4",
       .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
       .plaintext = "AAAA",
       .ciphertext = "A175"},
      {0}};
   aes_256_ctr_test_t *test;

   for (test = tests; test->testname != NULL; test++) {
      bool ret;
      _mongocrypt_buffer_t key;
      _mongocrypt_buffer_t iv;
      _mongocrypt_buffer_t plaintext;
      _mongocrypt_buffer_t ciphertext;
      _mongocrypt_buffer_t plaintext_got;
      _mongocrypt_buffer_t ciphertext_got;
      mongocrypt_status_t *status;
      uint32_t bytes_written;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
      printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
              "remove.");
      return;
#endif
#ifdef MONGOCRYPT_ENABLE_CRYPTO_CNG
      printf ("Test requires OpenSSL. Detected CNG. Skipping. TODO: remove");
      return;
#endif

      printf ("Begin test '%s'.\n", test->testname);

      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&iv, test->iv);
      _mongocrypt_buffer_copy_from_hex (&plaintext, test->plaintext);
      _mongocrypt_buffer_copy_from_hex (&ciphertext, test->ciphertext);
      _mongocrypt_buffer_init (&plaintext_got);
      _mongocrypt_buffer_resize (&plaintext_got, plaintext.len);
      /* Allocate memory for output ciphertext. CTR mode does not use padding.
       * Use plaintext length as expected ciphertext length. */
      _mongocrypt_buffer_init (&ciphertext_got);
      _mongocrypt_buffer_resize (&ciphertext_got, plaintext.len);
      status = mongocrypt_status_new ();

      /* Test encrypt. */
      ret = _native_crypto_aes_256_ctr_encrypt (
         (aes_256_args_t){.key = &key,
                          .iv = &iv,
                          .in = &plaintext,
                          .out = &ciphertext_got,
                          .bytes_written = &bytes_written,
                          .status = status});
      ASSERT_OR_PRINT (ret, status);
      ASSERT_CMPBYTES (ciphertext.data,
                       ciphertext.len,
                       ciphertext_got.data,
                       ciphertext_got.len);
      ASSERT_CMPINT ((int) bytes_written, ==, (int) ciphertext.len);

      /* Test decrypt. */
      ret = _native_crypto_aes_256_ctr_decrypt (
         (aes_256_args_t){.key = &key,
                          .iv = &iv,
                          .in = &ciphertext,
                          .out = &plaintext_got,
                          .bytes_written = &bytes_written,
                          .status = status});
      ASSERT_OR_PRINT (ret, status);
      ASSERT_CMPBYTES (
         plaintext.data, plaintext.len, plaintext_got.data, plaintext_got.len);
      ASSERT_CMPINT ((int) bytes_written, ==, (int) plaintext.len);

      mongocrypt_status_destroy (status);
      _mongocrypt_buffer_cleanup (&ciphertext_got);
      _mongocrypt_buffer_cleanup (&plaintext_got);
      _mongocrypt_buffer_cleanup (&ciphertext);
      _mongocrypt_buffer_cleanup (&plaintext);
      _mongocrypt_buffer_cleanup (&iv);
      _mongocrypt_buffer_cleanup (&key);

      printf ("End test '%s'.\n", test->testname);
   }
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

typedef struct {
   const char *testname;
   const char *iv;
   const char *associated_data;
   const char *key;
   // TODO: consider splitting key into the following
   // const char *key_encryption;
   // const char *key_mac;
   const char *plaintext;
   const char *ciphertext;
   uint32_t bytes_written_expected;
} fle2_aead_test_t;
/* TODO: rename to fle2_aead_roundtrip_test_t. */

void
_test_fle2_aead (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   fle2_aead_test_t tests[] = {
      {.testname = "Test case 'test1'",
       .iv = "918ab83c8966995dfb528a0020d9bb10",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       // From "AEAD with CTR" document:
       // "The encryption key Ke is equal to the first 32 bytes of R while the MAC key Km is equal to the second 32 bytes of R."
       .key = "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a0000000000000000000000000000000000000000000000000000000000000000",
       .plaintext = "74657374310a",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b998387c",
       .bytes_written_expected = 54
       },

      {.testname = "Input one byte",
       .iv = "918ab83c8966995dfb528a0020d9bb10",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       // From "AEAD with CTR" document:
       // "The encryption key Ke is equal to the first 32 bytes of R while the MAC key Km is equal to the second 32 bytes of R."
       .key = "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a0000000000000000000000000000000000000000000000000000000000000000",
       .plaintext = "00",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1004b2f319e0ec466bc9d265cbf0ae6b895d4d1db028502bb4e2293780d7196af635",
       .bytes_written_expected = 49
       },
      {0}};
   fle2_aead_test_t *test;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
      printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
              "remove.");
      return;
#endif
#ifdef MONGOCRYPT_ENABLE_CRYPTO_CNG
      printf ("Test requires OpenSSL. Detected CNG. Skipping. TODO: remove");
      return;
#endif

   crypt = _mongocrypt_tester_mongocrypt ();

   for (test = tests; test->testname != NULL; test++) {
      bool ret;
      _mongocrypt_buffer_t iv;
      _mongocrypt_buffer_t associated_data;
      _mongocrypt_buffer_t key;
      _mongocrypt_buffer_t plaintext;
      _mongocrypt_buffer_t ciphertext;
      _mongocrypt_buffer_t plaintext_got;
      _mongocrypt_buffer_t ciphertext_got;
      mongocrypt_status_t *status;
      uint32_t bytes_written;

      printf ("Begin test '%s'.\n", test->testname);

      _mongocrypt_buffer_copy_from_hex (&iv, test->iv);
      _mongocrypt_buffer_copy_from_hex (&associated_data, test->associated_data);
      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&plaintext, test->plaintext);
      _mongocrypt_buffer_copy_from_hex (&ciphertext, test->ciphertext);
      _mongocrypt_buffer_init (&plaintext_got);
      _mongocrypt_buffer_resize (&plaintext_got, plaintext.len);
      _mongocrypt_buffer_init (&ciphertext_got);
      _mongocrypt_buffer_resize (&ciphertext_got, _mongocrypt_fle2_calculate_ciphertext_len (plaintext.len));
      status = mongocrypt_status_new ();

      /* Test encrypt. */
      ret = _mongocrypt_fle2_do_encryption (crypt->crypto, &iv, &associated_data, &key, &plaintext, &ciphertext_got, &bytes_written, status);
      ASSERT_OR_PRINT (ret, status);
      ASSERT_CMPBYTES (ciphertext.data,
                       ciphertext.len,
                       ciphertext_got.data,
                       ciphertext_got.len);
      ASSERT_CMPINT ((int) bytes_written, ==, (int) ciphertext.len);

      /* Test decrypt. */
      ret = _mongocrypt_fle2_do_decryption (crypt->crypto, &associated_data, &key, &ciphertext, &plaintext_got, &bytes_written, status);
      ASSERT_OR_PRINT (ret, status);
      ASSERT_CMPBYTES (
         plaintext.data, plaintext.len, plaintext_got.data, plaintext_got.len);
      ASSERT_CMPINT ((int) bytes_written, ==, (int) plaintext.len);

      mongocrypt_status_destroy (status);
      _mongocrypt_buffer_cleanup (&ciphertext_got);
      _mongocrypt_buffer_cleanup (&plaintext_got);
      _mongocrypt_buffer_cleanup (&ciphertext);
      _mongocrypt_buffer_cleanup (&plaintext);
      _mongocrypt_buffer_cleanup (&iv);
      _mongocrypt_buffer_cleanup (&associated_data);
      _mongocrypt_buffer_cleanup (&key);

      printf ("End test '%s'.\n", test->testname);
   }

   mongocrypt_destroy (crypt);
}

typedef struct {
   const char *testname;
   const char *associated_data;
   const char *key;
   const char *plaintext;
   const char *ciphertext;
   uint32_t bytes_written_expected;
   const char *expect_error;
} fle2_aead_decrypt_test_t;

void
_test_fle2_aead_decrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   fle2_aead_decrypt_test_t tests[] = {
      {.testname = "Mismatched HMAC",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       // From "AEAD with CTR" document:
       // "The encryption key Ke is equal to the first 32 bytes of R while the MAC key Km is equal to the second 32 bytes of R."
       .key = "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a0000000000000000000000000000000000000000000000000000000000000000",
       .plaintext = "74657374310a",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b9983800",
       .expect_error = "decryption error"
       },
      {.testname = "Ciphertext too small",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       // From "AEAD with CTR" document:
       // "The encryption key Ke is equal to the first 32 bytes of R while the MAC key Km is equal to the second 32 bytes of R."
       .key = "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a0000000000000000000000000000000000000000000000000000000000000000",
       .plaintext = "00",
       .ciphertext = "00",
       .expect_error = "input ciphertext too small"
       },
       {.testname = "Ciphertext is 0 bytes",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       // From "AEAD with CTR" document:
       // "The encryption key Ke is equal to the first 32 bytes of R while the MAC key Km is equal to the second 32 bytes of R."
       .key = "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ecc9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a0000000000000000000000000000000000000000000000000000000000000000",
       .plaintext = "00",
       .ciphertext = "74c1b6102bbcb96436795ccbf2703af61703e0e33de37f148490c7ed7989f31720c4ed6a24ecc01cc3622f90ed2b5500",
       .expect_error = "input ciphertext too small"
       },
      {0}};
   fle2_aead_decrypt_test_t *test;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
      printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
              "remove.");
      return;
#endif
#ifdef MONGOCRYPT_ENABLE_CRYPTO_CNG
      printf ("Test requires OpenSSL. Detected CNG. Skipping. TODO: remove");
      return;
#endif

   crypt = _mongocrypt_tester_mongocrypt ();

   for (test = tests; test->testname != NULL; test++) {
      bool ret;
      _mongocrypt_buffer_t associated_data;
      _mongocrypt_buffer_t key;
      _mongocrypt_buffer_t plaintext;
      _mongocrypt_buffer_t ciphertext;
      _mongocrypt_buffer_t plaintext_got;
      mongocrypt_status_t *status;
      uint32_t bytes_written;

      printf ("Begin test '%s'.\n", test->testname);

      _mongocrypt_buffer_copy_from_hex (&associated_data, test->associated_data);
      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&plaintext, test->plaintext);
      _mongocrypt_buffer_copy_from_hex (&ciphertext, test->ciphertext);
      _mongocrypt_buffer_init (&plaintext_got);
      _mongocrypt_buffer_resize (&plaintext_got, plaintext.len);
      status = mongocrypt_status_new ();

      ret = _mongocrypt_fle2_do_decryption (crypt->crypto, &associated_data, &key, &ciphertext, &plaintext, &bytes_written, status);
      if (test->expect_error == NULL) {
         ASSERT_OR_PRINT (ret, status);
         ASSERT_CMPBYTES (
            plaintext.data, plaintext.len, plaintext_got.data, plaintext_got.len);
         ASSERT_CMPINT ((int) bytes_written, ==, (int) plaintext.len);
      } else {
         ASSERT_FAILS_STATUS (ret, status, test->expect_error);
      }

      mongocrypt_status_destroy (status);
      _mongocrypt_buffer_cleanup (&plaintext_got);
      _mongocrypt_buffer_cleanup (&ciphertext);
      _mongocrypt_buffer_cleanup (&plaintext);
      _mongocrypt_buffer_cleanup (&key);
      _mongocrypt_buffer_cleanup (&associated_data);

      printf ("End test '%s'.\n", test->testname);
   }

   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_crypto (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_mcgrew);
   INSTALL_TEST (_test_roundtrip);
   INSTALL_TEST (_test_native_crypto_aes_256_ctr);
   INSTALL_TEST (_test_native_crypto_hmac_sha_256);
   INSTALL_TEST_CRYPTO (_test_mongocrypt_hmac_sha_256_hook, CRYPTO_OPTIONAL);
   INSTALL_TEST (_test_fle2_aead);
   INSTALL_TEST (_test_fle2_aead_decrypt);
}