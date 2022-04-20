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
#include "mc-fle2-insert-update-payload-private.h"

#define TEST_IUP_HEX                                                           \
   "0471010000056400200000000076fad9a57bfa6aa6686728b4f2dd1b728fed2f1d885c163" \
   "0b33fe6b62da8bac405730020000000001527a3961d1bf73ad0a8cc7a6ddd9cdf0616b166" \
   "2acbbf707e1bc3ee69a3b8120563002000000000b195d639603e5220816eb24d07a6c77e5" \
   "07f727ee9592bf058dda3c3814f78850570005000000000c743d675769ea788d5e5c440db" \
   "240df942cbc23bfc7befa83289e97c6386b3d059d2ea8f3fbc1a8b0652c07b03c79efee1b" \
   "dfe0b8436e2f6e570fe171c64bf52cb5ed6af1ce94b17b896d2ef7269baaa057500100000" \
   "000412345678123498761234123456789012107400020000000576004d00000000abcdefa" \
   "b1234987612341234567890124cd964104381e661fa1fa05c498ead216d56f9147271d68f" \
   "fadf3d6ee22741b7509f33a6e06650cfd58ce309098e3e783a9d4e23c8c17fbfbcd5de81c" \
   "f0565002000000000eb9a73f7912d86a4297e81d2f675af742874e4057e3a890fec651a23" \
   "eee3f3ec00"

static void
test_FLE2InsertUpdatePayload_parse (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   mc_FLE2InsertUpdatePayload_t iup;
   _mongocrypt_buffer_t expect_edcDerivedToken;
   _mongocrypt_buffer_t expect_escDerivedToken;
   _mongocrypt_buffer_t expect_eccDerivedToken;
   _mongocrypt_buffer_t expect_encryptedTokens;
   _mongocrypt_buffer_t expect_indexKeyId;
   bson_type_t expect_valueType = BSON_TYPE_UTF8;
   _mongocrypt_buffer_t expect_value;
   _mongocrypt_buffer_t expect_serverEncryptionToken;
   _mongocrypt_buffer_t expect_userKeyId;

   _mongocrypt_buffer_copy_from_hex (
      &expect_edcDerivedToken,
      "76fad9a57bfa6aa6686728b4f2dd1b728fed2f1d885c1630b33fe6b62da8bac4");
   _mongocrypt_buffer_copy_from_hex (
      &expect_escDerivedToken,
      "1527a3961d1bf73ad0a8cc7a6ddd9cdf0616b1662acbbf707e1bc3ee69a3b812");
   _mongocrypt_buffer_copy_from_hex (
      &expect_eccDerivedToken,
      "b195d639603e5220816eb24d07a6c77e507f727ee9592bf058dda3c3814f7885");
   _mongocrypt_buffer_copy_from_hex (
      &expect_encryptedTokens,
      "c743d675769ea788d5e5c440db240df942cbc23bfc7befa83289e97c6386b3d059d2e"
      "a8f3fbc1a8b0652c07b03c79efee1bdfe0b8436e2f6e570fe171c64bf52cb5ed6af1c"
      "e94b17b896d2ef7269baaa");
   _mongocrypt_buffer_copy_from_hex (&expect_indexKeyId,
                                     "12345678123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (
      &expect_value,
      "abcdefab1234987612341234567890124cd964104381e661fa1fa05c498ead216d56f"
      "9147271d68ffadf3d6ee22741b7509f33a6e06650cfd58ce309098e3e783a9d4e23c8"
      "c17fbfbcd5de81cf");
   _mongocrypt_buffer_copy_from_hex (
      &expect_serverEncryptionToken,
      "eb9a73f7912d86a4297e81d2f675af742874e4057e3a890fec651a23eee3f3ec");
   _mongocrypt_buffer_copy_from_hex (&expect_userKeyId,
                                     "abcdefab123498761234123456789012");

   /* Test successful parse. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, TEST_IUP_HEX);
      mc_FLE2InsertUpdatePayload_init (&iup);
      ASSERT_OK_STATUS (mc_FLE2InsertUpdatePayload_parse (&iup, &input, status),
                        status);
      ASSERT_CMPBUF (expect_edcDerivedToken, iup.edcDerivedToken);
      ASSERT_CMPBUF (expect_escDerivedToken, iup.escDerivedToken);
      ASSERT_CMPBUF (expect_eccDerivedToken, iup.eccDerivedToken);
      ASSERT_CMPBUF (expect_encryptedTokens, iup.encryptedTokens);
      ASSERT_CMPBUF (expect_indexKeyId, iup.indexKeyId);
      ASSERT (expect_valueType == iup.valueType);
      ASSERT_CMPBUF (expect_value, iup.value);
      ASSERT_CMPBUF (expect_serverEncryptionToken, iup.serverEncryptionToken);
      ASSERT_CMPBUF (expect_userKeyId, iup.userKeyId);
      mc_FLE2InsertUpdatePayload_cleanup (&iup);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   _mongocrypt_buffer_cleanup (&expect_userKeyId);
   _mongocrypt_buffer_cleanup (&expect_edcDerivedToken);
   _mongocrypt_buffer_cleanup (&expect_escDerivedToken);
   _mongocrypt_buffer_cleanup (&expect_eccDerivedToken);
   _mongocrypt_buffer_cleanup (&expect_encryptedTokens);
   _mongocrypt_buffer_cleanup (&expect_indexKeyId);
   _mongocrypt_buffer_cleanup (&expect_value);
   _mongocrypt_buffer_cleanup (&expect_serverEncryptionToken);
}

static void
test_FLE2InsertUpdatePayload_decrypt (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   mc_FLE2InsertUpdatePayload_t iup;
   _mongocrypt_buffer_t expect_plaintext;
   _mongocrypt_buffer_t correct_key;
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

   _mongocrypt_buffer_copy_from_hex (
      &correct_key,
      "a7ddbc4c8be00d51f68d9d8e485f351c8edc8d2206b24d8e0e1816d005fbe520e4891250"
      "47d647b0d8684bfbdbf09c304085ed086aba6c2b2b1677ccc91ced8847a733bf5e5682c8"
      "4b3ee7969e4a5fe0e0c21e5e3ee190595a55f83147d8de2a");
   ASSERT (_mongocrypt_buffer_copy_from_data_and_size (
      &expect_plaintext, (const uint8_t *) "\x09\x00\x00\x00value123\x00", 13));

   /* Test successful decrypt. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, TEST_IUP_HEX);
      mc_FLE2InsertUpdatePayload_init (&iup);
      ASSERT_OK_STATUS (mc_FLE2InsertUpdatePayload_parse (&iup, &input, status),
                        status);
      const _mongocrypt_buffer_t *got = mc_FLE2InsertUpdatePayload_decrypt (
         crypt->crypto, &iup, &correct_key, status);
      ASSERT_OK_STATUS (got != NULL, status);
      ASSERT_CMPBUF (expect_plaintext, *got);

      mc_FLE2InsertUpdatePayload_cleanup (&iup);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test incorrect key. */
   {
      _mongocrypt_buffer_t incorrect_key;

      _mongocrypt_buffer_init (&incorrect_key);
      _mongocrypt_buffer_copy_to (&correct_key, &incorrect_key);
      /* The middle 32 bytes of key are used to generate the mac. Change first
       * byte to make user key incorrect. */
      incorrect_key.data[32] = 0;

      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, TEST_IUP_HEX);
      mc_FLE2InsertUpdatePayload_init (&iup);
      ASSERT_OK_STATUS (mc_FLE2InsertUpdatePayload_parse (&iup, &input, status),
                        status);
      const _mongocrypt_buffer_t *got = mc_FLE2InsertUpdatePayload_decrypt (
         crypt->crypto, &iup, &incorrect_key, status);
      ASSERT_FAILS_STATUS (got != NULL, status, "decryption error");

      mc_FLE2InsertUpdatePayload_cleanup (&iup);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
      _mongocrypt_buffer_cleanup (&incorrect_key);
   }

   _mongocrypt_buffer_cleanup (&expect_plaintext);
   _mongocrypt_buffer_cleanup (&correct_key);
   mongocrypt_destroy (crypt);
}

#undef TEST_IUP_HEX

void
_mongocrypt_tester_install_fle2_payload_iup (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_FLE2InsertUpdatePayload_parse);
   INSTALL_TEST (test_FLE2InsertUpdatePayload_decrypt);
}
