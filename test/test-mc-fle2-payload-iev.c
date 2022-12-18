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
         "expected fle_blob_subtype 7 or 9 got: 6");
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
                           "expected byte length");
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

static void
test_FLE2IndexedRangeEncryptedValue_parse (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input;
   _mongocrypt_buffer_t expect_S_KeyId;
   mc_FLE2IndexedEncryptedValue_t *iev;

   /* Test successful parse. */
   {
      mongocrypt_status_t *status = mongocrypt_status_new ();
      _mongocrypt_buffer_copy_from_hex (
         &input,
         "091234567812349876123412345678901210b0f174222d077efed93219cdb7fcadfa6"
         "be2c9d17c114c346253be6a60b7205f1d5f627f1a64594678a15b756a258a0b324d01"
         "222b74c7d61089010440fc4f7135e70b1e2dd5faae398edc446a880164c31ee43d01d"
         "530f78118d49e799aaf548700fb7e5874c9247f49b913c23214df653588ce81bf802b"
         "884e2c988f3b61dd15ed9ee40e80f1eda7f1f6f33ffa1f4d599be97d8719f8fdf6b1f"
         "20b6f705d5d3e732eb9327395dbde6c83c44f5a6d3ad1f1e3c6d18b8499eab0184e1b"
         "67a4072b377f44b9877225acb4a3ad111e6e469a37a79ef4c063bc404f50b50a09a7f"
         "ecded2bb7d1d2bf6e4e7d855be534eea2de750fc2a31dd770de3e86cd1a7f38ab715a"
         "8393b82b0f0fe0419fa26156cf1c9d9554344a9a4655f6a7f6d223d4216ee5da18613"
         "e1a7735fb2fd1e29cab13584e5cb43f50c618736f6715b3924ef7a8f89a9c0e6a5a05"
         "ff8a89872aa5cd3129a025c64345fd69e1299626c5c50ec52646857d8cc80c8c40d9d"
         "ea5cf055e9778fe57043bcce3ff6c29da16ee843f5390c3765aaec69618435fe390c5"
         "b8ae51b0a5f5f7cbd94e5aad1f6e188402f5fa7a104ccb694cea7feafadccce5e4afb"
         "749190e9101f962ab599a0f5f0f379ca3772361afb057b2b2ba7f4d435f65ebe2ce75"
         "00047143fd14e6199be078ca83c49b9e8e1387e5b36b723444c80cd18ce1454273f81"
         "5f3c7697d34f75ecae102750d50db03f530d382072fd004999cf915982b9ee8582baf"
         "e6f9a4a4df0896b8b246fd0f191858af865c2e40ddce6bb27cae92180bc83c3e2f783"
         "2518f771711acf2321ea0fabbf0b7bd256b1a3620e86f5170dcf3d5af6abb614cece5"
         "16de4536b03cb978546322f5ab55d25980a20aee6f46fefb06f4542637f607ae64688"
         "2940060e162e85c876c94e8ef55b072e2937c4e192c0851925b74cc8763e780f19956"
         "65e2896e98f3edafd3c81414e95346e3e679497263511a2090e0cd931db5412d19d7e"
         "6fb6670925dfd4e41c7a89a40eb44407bbf20f61d7e6b376fca2013201f727b0e71b6"
         "569361609f557b584c0c672b420823902a5d3fb965a1ce90887f37eed0fff358189ab"
         "f7921bb881deff1db4a0787d85e1875042e7090ea15d858e06f48594672a66cfdfd2a"
         "c67e457b639f40f47312cb71a16f7d21d3ef828b439cbdaf6b3d89345bc5aa2a1f736"
         "a483fb5efa45288a103bbabc2d7f73eda875621f1c6e2eaeb3c839cbd5b339f87cf36"
         "8d4eef413fb7d5ad5969e0cc6c557509e99cfbf7741cd92c8b5a8c26d723ac7d8c420"
         "5c9dc14f202e247f4e14af221aa4b31e1a29f61a79cfc9afc7cdf83cf8e005f646b78"
         "c3feea7a27be4f8b28a06555a80e85de397c61f15d2140309317b918141556f6912d8"
         "9bfe122c605fe780dec62eded3eacbdac1b90de2b280d745ccc73a9513be82f980326"
         "0ee7119b86f19aeef270d64241472e48aa0c5165aee80e9e522c81090531aeb957ff7"
         "0a445791043a242c1964cbd3801a24631dd6411e8ba56ef4c562d7c9085abf86671ca"
         "ce021348e7bb99490c277e4d0cc0feaacc5763bb166c6cfe6fad03585ef268c5730cf"
         "cc81a358ba5c90c44cc603776d0e5213f985c5d8e8643e7261bf38abf3bb123c0603d"
         "3124e9f4c14466ded55777f94c35a235464a9a352039d8c1a13480915cc03b69eaa90"
         "360db7c7a67a1500c179e7d191f73d16852206a1ee3787d4ff37381e4b61a7531cc08"
         "918c1176580f71e0ff05235b90d44d027ce0841842aae22aa5777c029b415f6a8eebb"
         "adf4fb08e8699ff7f3568dee78245368cd83b630f7bae1f8acc35bdcb0e3c89157d43"
         "6797845a41aaf5413f0058af7de89ae1c0346bc6752f365c5bb5af13963558864de20"
         "cbd49970d807110abc01df10e1f01bc5ef1727afed36f1be02f02e2c4bcd26d6e10bf"
         "e048bf2685e996fbad0e55b977a8382845a3e06202aa080ce594afd130a46df1642dd"
         "689ace1eb9fea08fbe92bbf5538c9093a3f5f0c8366c4d7c89b7be2dd58db2a9f4d55"
         "ef20e64be540bea405f1fda9e2b38ec96b0673b0a8c974ababd2c2b86abd78c3d1e9a"
         "ba8fadc92d4d7a4dade928293a9cc10437509c2e6c1c2d4e5935b7ba2ef0e07d0d282"
         "b993a232771b4833a57a09fc0b4cd96ba67989801c7bc6bc3b0de3af20449ca05a82e"
         "8638ce306f225ff7a46bc5cff944f1beca387ca555397430a1b64c7586dffec5cd25b"
         "31b5ab15cd52f6b7655cbfe79d8bd8ad1327381276ecccf9befb4ea5de1fc90fb08b5"
         "abee55bee2c333cbb9d41e28698aa9194659dea552e410589bd703c6032d71da178ce"
         "4a8a476ac74086ba27f8d75b185071cab5062a79d55d8a1c12ebecbf0841100dc7514"
         "555f789b70b46a0876795a66088c96aecfa0ae4a4068d2d9c1756ecde82db49d06a13"
         "c734270c85a4be5be44b7646a36e6ca5f3e9fbf35d6b849901844d9ad9c67c1d93465"
         "d16c7fa3f576bf1fbdaa71b20eae7609290c7eda5f9ec31702702fea9b3b53e9a06e0"
         "34f5058efd58d3129a78976c86ed47c849aae5a62a1c949f176133bcf7c7e1dd088f3"
         "d65b313312f822ca81ee4b9f70e4781459da6172885cb8d1c0ce5564d00aff776f09b"
         "de5f47ed030e8893db768c40775db76b29a3cfd37fd8edf7c0c686e8e13ca57a74898"
         "11a5bb0ceaf415f4fdd7725e5273cd3dcaaab00f585e877652e3566449535bfb1a2f7"
         "daff5a90dc00e0977b639560238cbe5f20c7de4014d1473c83a602c7f86a727e29776"
         "fabc87fbfe67550867084d0a34e8e3ac54bdd9134b0fbd46521591f955ccc36b4a5c1"
         "5122a7b7d022e0b2c9addbc56f0adda8af808c1515a88dcc83294dc51c36dfde69a40"
         "6e1784d6901ca2a2e80ce1b23aceba63c9091a96aab34026766647c36380dba6edc3e"
         "71e04df9481272c0793f9c0d22ea7502f53927b875be5141372820dd63bf309182cf8"
         "f31809fe4960f7008b43ebd7b6b858273d7946082e00314b06b4dc57f3227a5db42ae"
         "967a6b23efe55ed46f100a06252734519f09ed45537fc92f6334f7845ed7cd9ce584a"
         "c4f61e6e3767a7695ae28d8f93265771cfe014b6bb89c911dbc64f522830a56d252b9"
         "b0923059b9d998fe706d03618863bc40bf6056914e9eed311e9bbc32a06f7d919fd87"
         "884faa054491f3dbfcf20cfabbf4d53fdcd51f576793d3c4e78530df23ddc4bfdf7ae"
         "92f17bd6c108e9659dd9f76ea604650c6cc04ab29202c15b699a1bc1456210815b5a8"
         "ef33d8559c8c8250ab0f55e8c5d77a1017944890e44b59e1887391ffb16922169ef1f"
         "820003f92b5747bef6e6fcdcc08397db5a3345c136896c3a38ff7dbc3a2a2d0f15633"
         "612d3f7f758c304e9be67758cf6e6e0b402250b5d82");
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
      ASSERT_OR_PRINT (got_bson_type == BSON_TYPE_INT32, status);
      mc_FLE2IndexedEncryptedValue_destroy (iev);
      _mongocrypt_buffer_cleanup (&expect_S_KeyId);
      _mongocrypt_buffer_cleanup (&input);
      mongocrypt_status_destroy (status);
   }
}

void
_mongocrypt_tester_install_fle2_payloads (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_FLE2IndexedEqualityEncryptedValue_parse);
   INSTALL_TEST (test_FLE2IndexedEqualityEncryptedValue_decrypt);
   INSTALL_TEST (test_FLE2IndexedRangeEncryptedValue_parse);
}
