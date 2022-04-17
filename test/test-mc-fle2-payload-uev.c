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
#include "mc-fle2-payload-uev-private.h"

#define TEST_UEV_HEX                                                           \
   "06abcdefab123498761234123456789012024d069564f5a05e9e3523b98f575acb153b70d" \
   "6d5f38dc752132c6928aaae8e5928e537a2ce407d847434d3d755635f9f80888371e7e1f9" \
   "e42b9b70a485"

static void
test_FLE2UnindexedEncryptedValue_parse (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   _mongocrypt_buffer_t expect_key_uuid;
   mc_FLE2UnindexedEncryptedValue_t *uev;

   /* Test successful parse. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, TEST_UEV_HEX);
      _mongocrypt_buffer_copy_from_hex (&expect_key_uuid,
                                        "ABCDEFAB123498761234123456789012");
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status), status);
      const _mongocrypt_buffer_t *got =
         mc_FLE2UnindexedEncryptedValue_get_key_uuid (uev, status);
      ASSERT_OR_PRINT (got != NULL, status);
      ASSERT_CMPBUF (expect_key_uuid, *got);
      bson_type_t got_bson_type =
         mc_FLE2UnindexedEncryptedValue_get_original_bson_type (uev, status);
      ASSERT_OR_PRINT (got_bson_type == BSON_TYPE_UTF8, status);
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      _mongocrypt_buffer_cleanup (&expect_key_uuid);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test too-short input. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, "06123456781234");
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      ASSERT_FAILS_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status),
         status,
         "expected byte length >= 17 got: 7");
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test incorrect fle_blob_subtype */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (
         &input, "05abcdefab123498761234123456789012024d069564f5a05e9e3523b98f5"
                 "75acb153b70d6d5f38dc752132c6928aaae8e5928e537a2ce407d847434d3"
                 "d755635f9f80888371e7e1f9e42b9b70a485");
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      ASSERT_FAILS_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status),
         status,
         "expected fle_blob_subtype=6 got: 5");
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test double parsing */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, TEST_UEV_HEX);
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status), status);
      ASSERT_FAILS_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status),
         status,
         "must not be called twice");
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test attempting to get key_uuid before parsing. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      const _mongocrypt_buffer_t *got =
         mc_FLE2UnindexedEncryptedValue_get_key_uuid (uev, status);
      ASSERT_FAILS_STATUS (
         got != NULL,
         status,
         "must be called after mc_FLE2UnindexedEncryptedValue_parse");
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      mongocrypt_status_destroy (status);
   }
}

static void
test_FLE2UnindexedEncryptedValue_decrypt (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   _mongocrypt_buffer_t correct_key;
   mc_FLE2UnindexedEncryptedValue_t *uev;
   _mongocrypt_buffer_t expect_key_uuid;
   _mongocrypt_buffer_t expect_plaintext;
   mongocrypt_t *crypt;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
   printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
           "remove once MONGOCRYPT-385 and MONGOCRYPT-386 are complete");
   return;
#endif
#ifdef MONGOCRYPT_ENABLE_CRYPTO_CNG
   printf ("Test requires OpenSSL. Detected CNG. Skipping. TODO: remove once "
           "MONGOCRYPT-385 and MONGOCRYPT-386 are complete");
   return;
#endif

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   _mongocrypt_buffer_copy_from_hex (&input, TEST_UEV_HEX);
   _mongocrypt_buffer_copy_from_hex (&expect_key_uuid,
                                     "abcdefab123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (
      &correct_key,
      "a7ddbc4c8be00d51f68d9d8e485f351c8edc8d2206b24d8e0e1816d005fbe520e4891250"
      "47d647b0d8684bfbdbf09c304085ed086aba6c2b2b1677ccc91ced8847a733bf5e5682c8"
      "4b3ee7969e4a5fe0e0c21e5e3ee190595a55f83147d8de2a");
   ASSERT (_mongocrypt_buffer_copy_from_data_and_size (
      &expect_plaintext, (const uint8_t *) "\x09\x00\x00\x00value123\x00", 13));

   /* Test success. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status), status);

      const _mongocrypt_buffer_t *got =
         mc_FLE2UnindexedEncryptedValue_get_key_uuid (uev, status);
      ASSERT_OR_PRINT (got != NULL, status);
      ASSERT_CMPBUF (expect_key_uuid, *got);

      got = mc_FLE2UnindexedEncryptedValue_decrypt (
         crypt->crypto, uev, &correct_key, status);
      ASSERT_OK_STATUS (got != NULL, status);
      ASSERT_CMPBUF (expect_plaintext, *got);
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      mongocrypt_status_destroy (status);
   }

   /* Test an incorrect key. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_t incorrect_key;

      _mongocrypt_buffer_init (&incorrect_key);
      _mongocrypt_buffer_copy_to (&correct_key, &incorrect_key);
      /* The middle 32 bytes of key are used to generate the mac. Change first
       * byte to make S_Key incorrect. */
      incorrect_key.data[32] = 0;
      uev = mc_FLE2UnindexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2UnindexedEncryptedValue_parse (uev, &input, status), status);
      const _mongocrypt_buffer_t *got = mc_FLE2UnindexedEncryptedValue_decrypt (
         crypt->crypto, uev, &incorrect_key, status);
      ASSERT_FAILS_STATUS (got != NULL, status, "decryption error");
      mc_FLE2UnindexedEncryptedValue_destroy (uev);
      _mongocrypt_buffer_cleanup (&incorrect_key);
      mongocrypt_status_destroy (status);
   }

   _mongocrypt_buffer_cleanup (&expect_plaintext);
   _mongocrypt_buffer_cleanup (&correct_key);
   _mongocrypt_buffer_cleanup (&expect_key_uuid);
   _mongocrypt_buffer_cleanup (&input);
   mongocrypt_destroy (crypt);
}

#undef TEST_UEV_BASE64

void
_mongocrypt_tester_install_fle2_payload_uev (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_FLE2UnindexedEncryptedValue_parse);
   INSTALL_TEST (test_FLE2UnindexedEncryptedValue_decrypt);
}
