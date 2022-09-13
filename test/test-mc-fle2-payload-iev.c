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
#include "mc-fle2-payload-iev-private.h"

static void
test_FLE2IndexedEqualityEncryptedValue_parse (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   _mongocrypt_buffer_t expect_S_KeyId;
   mc_FLE2IndexedEncryptedValue_t *iev;

   /* Test successful parse. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (
         &input,
         "07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a"
         "606d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca43276222581"
         "0a66a1dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac99"
         "52661f54a98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85"
         "c6cc5fbd0fdc22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd0"
         "8638c0faa47a784995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca459653"
         "6e7f339da76fc9c7c9d1c09619a77d49");
      _mongocrypt_buffer_copy_from_hex (&expect_S_KeyId,
                                        "12345678123498761234123456789012");
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status), status);
      const _mongocrypt_buffer_t *got =
         mc_FLE2IndexedEncryptedValue_get_S_KeyId (iev, status);
      ASSERT_OR_PRINT (got != NULL, status);
      ASSERT_CMPBUF (expect_S_KeyId, *got);
      bson_type_t got_bson_type =
         mc_FLE2IndexedEncryptedValue_get_original_bson_type (iev, status);
      ASSERT_OR_PRINT (got_bson_type == BSON_TYPE_UTF8, status);
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&expect_S_KeyId);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test too-short input. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (&input, "07123456781234");
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_FAILS_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status),
         status,
         "expected byte length >= 17 got: 7");
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test incorrect fle_blob_subtype */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (
         &input,
         "06123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a"
         "606d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca43276222581"
         "0a66a1dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac99"
         "52661f54a98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85"
         "c6cc5fbd0fdc22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd0"
         "8638c0faa47a784995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca459653"
         "6e7f339da76fc9c7c9d1c09619a77d49");
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_FAILS_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status),
         status,
         "expected fle_blob_subtype=7 got: 6");
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test double parsing */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (
         &input,
         "07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a"
         "606d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca43276222581"
         "0a66a1dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac99"
         "52661f54a98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85"
         "c6cc5fbd0fdc22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd0"
         "8638c0faa47a784995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca459653"
         "6e7f339da76fc9c7c9d1c09619a77d49");
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status), status);
      ASSERT_FAILS_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status),
         status,
         "must not be called twice");
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }

   /* Test attempting to get S_KeyId before parsing. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      iev = mc_FLE2IndexedEncryptedValue_new ();
      const _mongocrypt_buffer_t *got =
         mc_FLE2IndexedEncryptedValue_get_S_KeyId (iev, status);
      ASSERT_FAILS_STATUS (
         got != NULL,
         status,
         "must be called after mc_FLE2IndexedEncryptedValue_parse");
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      mongocrypt_status_destroy (status);
   }
}

static void
test_FLE2IndexedEqualityEncryptedValue_decrypt (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   _mongocrypt_buffer_t correct_S_Key;
   _mongocrypt_buffer_t correct_K_Key;
   mc_FLE2IndexedEncryptedValue_t *iev;
   _mongocrypt_buffer_t expect_S_KeyId;
   _mongocrypt_buffer_t expect_K_KeyId;
   _mongocrypt_buffer_t expect_client_value;
   mongocrypt_t *crypt;

   if (!_aes_ctr_is_supported_by_os) {
      printf ("Common Crypto with no CTR support detected. Skipping.");
      return;
   }

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   _mongocrypt_buffer_copy_from_hex (
      &input,
      "07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a606"
      "d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca432762225810a66a1"
      "dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac9952661f54a"
      "98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85c6cc5fbd0fdc"
      "22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd08638c0faa47a784"
      "995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca4596536e7f339da76fc9c7c9"
      "d1c09619a77d49");
   _mongocrypt_buffer_copy_from_hex (&expect_S_KeyId,
                                     "12345678123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (&expect_K_KeyId,
                                     "abcdefab123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (
      &correct_S_Key,
      "7dbfebc619aa68a659f64b8e23ccd21644ac326cb74a26840c3d2420176c40ae088294d0"
      "0ad6cae9684237b21b754cf503f085c25cd320bf035c3417416e1e6fe3d9219f79586582"
      "112740b2add88e1030d91926ae8afc13ee575cfb8bb965b7");
   _mongocrypt_buffer_copy_from_hex (
      &correct_K_Key,
      "a7ddbc4c8be00d51f68d9d8e485f351c8edc8d2206b24d8e0e1816d005fbe520e4891250"
      "47d647b0d8684bfbdbf09c304085ed086aba6c2b2b1677ccc91ced8847a733bf5e5682c8"
      "4b3ee7969e4a5fe0e0c21e5e3ee190595a55f83147d8de2a");
   ASSERT (_mongocrypt_buffer_copy_from_data_and_size (
      &expect_client_value,
      (const uint8_t *) "\x09\x00\x00\x00value123\x00",
      13));

   /* Test success. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status), status);

      const _mongocrypt_buffer_t *got =
         mc_FLE2IndexedEncryptedValue_get_S_KeyId (iev, status);
      ASSERT_OR_PRINT (got != NULL, status);
      ASSERT_CMPBUF (expect_S_KeyId, *got);

      ASSERT_OK_STATUS (mc_FLE2IndexedEncryptedValue_add_S_Key (
                           crypt->crypto, iev, &correct_S_Key, status),
                        status);

      got = mc_FLE2IndexedEncryptedValue_get_K_KeyId (iev, status);
      ASSERT_OR_PRINT (got != NULL, status);
      ASSERT_CMPBUF (expect_K_KeyId, *got);

      ASSERT_OK_STATUS (mc_FLE2IndexedEqualityEncryptedValue_add_K_Key (
                           crypt->crypto, iev, &correct_K_Key, status),
                        status);
      got = mc_FLE2IndexedEncryptedValue_get_ClientValue (iev, status);
      ASSERT_CMPBUF (expect_client_value, *got);
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      mongocrypt_status_destroy (status);
   }

   /* Test an incorrect S_Key. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_t incorrect_S_Key;

      _mongocrypt_buffer_init (&incorrect_S_Key);
      _mongocrypt_buffer_copy_to (&correct_S_Key, &incorrect_S_Key);
      /* The last 32 bytes of S_Key are used to generate
       * ServerDataEncryptionLevel1Token. Change last byte to make S_Key
       * incorrect. */
      incorrect_S_Key.data[incorrect_S_Key.len - 1] = 0;
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status), status);
      /* Since S_Key is used for non-AEAD encryption, decryption does not return
       * an error. The output is garbled. It fails to parse the decrypted Inner
       * struct. */
      ASSERT_FAILS_STATUS (mc_FLE2IndexedEncryptedValue_add_S_Key (
                              crypt->crypto, iev, &incorrect_S_Key, status),
                           status,
                           "expected Inner byte length");
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&incorrect_S_Key);
      mongocrypt_status_destroy (status);
   }

   /* Test an incorrect K_Key. */
   {
      _mongocrypt_buffer_t incorrect_K_Key;
      mongocrypt_status_t *status = mongocrypt_status_new ();

      _mongocrypt_buffer_init (&incorrect_K_Key);
      _mongocrypt_buffer_copy_to (&correct_K_Key, &incorrect_K_Key);
      /* The second 32 bytes of K_Key is used for the mac key. Modify one byte
       * to get a decryption error. */
      incorrect_K_Key.data[32] = 0;
      iev = mc_FLE2IndexedEncryptedValue_new ();
      ASSERT_OK_STATUS (
         mc_FLE2IndexedEncryptedValue_parse (iev, &input, status), status);
      ASSERT_OK_STATUS (mc_FLE2IndexedEncryptedValue_add_S_Key (
                           crypt->crypto, iev, &correct_S_Key, status),
                        status);
      ASSERT_FAILS_STATUS (mc_FLE2IndexedEqualityEncryptedValue_add_K_Key (
                              crypt->crypto, iev, &incorrect_K_Key, status),
                           status,
                           "decryption error");
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&incorrect_K_Key);
      mongocrypt_status_destroy (status);
   }

   _mongocrypt_buffer_cleanup (&expect_client_value);
   _mongocrypt_buffer_cleanup (&correct_K_Key);
   _mongocrypt_buffer_cleanup (&expect_K_KeyId);
   _mongocrypt_buffer_cleanup (&correct_S_Key);
   _mongocrypt_buffer_cleanup (&expect_S_KeyId);
   _mongocrypt_buffer_cleanup (&input);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_fle2_payloads (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_FLE2IndexedEqualityEncryptedValue_parse);
   INSTALL_TEST (test_FLE2IndexedEqualityEncryptedValue_decrypt);
}
