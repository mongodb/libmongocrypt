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

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
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
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
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
      {.testname = "Imported from server1",
       .key =
          "2078bf7187b8792860071c205a9ad88fc285232780f4ac4d77be9146b63c6ec9",
       .iv = "185405c26aca39e507a2c71572b209df",
       .plaintext =
          "d3e88a3f39bf4788a325e4b9ba829e0a768a66e66b03940c50e6fd92f0fd"
          "85be4742f183c69891fc337ea5f9f8680c86827098277e8a32e8899eb639"
          "7fc93b94627c38e36815b6a2869a8f41f2e7d4369f8831c8b07a3d39197d",
       .ciphertext =
          "e36455d10b5884911f5a5bdb4519148ca7a754fd4b54b31ecf8afaaea522"
          "f1e0cc917f49bb4869307c19bf9862171905e644fccbebbd764f0015fd36"
          "2ed33bae74811b7773987e129a3b58d339324a5415467baaacb25b4d3cc1"},
      {.testname = "Imported from server2",
       .key =
          "faf3ca75c08501664fb9c7fcf78f291fc4a63dc58c179c12c1b70c3b644f71f0",
       .iv = "9413b67c240bb84e94b7bbb716a97ea3",
       .plaintext =
          "bc561491a030e785b570bc787c0728cb123f1604ec27075c1beae9f71077"
          "23e381ecb2275047db59627d7859e48aafd7fc856a7167c25657d751963b"
          "0066f8015b06927df12c203a6e0ba795cc859b830142d3ed1ab1a64782e1"
          "d5e16b243b5063b3dc9a12d829e8be020382f36dc24bf14e8c01ce447409"
          "a63867741c10384ef6cbabbfa28a10d5dfb1392c705ab7286a278e7e8778"
          "45b3a9f1630311a8cdca3bcc388286d8af0cd366150570598a31d57a4543"
          "a3bea0394cf7fc59cf608f6ce6a21a7998ce0cdd07925895eeb4e451581b"
          "f037828088e8d30fbf29d4dfe7d77f0a7ad8f0af8074a50f161044e9bd35"
          "c56a5693c7ffc96a1a5e1f187be5c2d529c304192313152f83ee676133d6"
          "75b05b9b277634f3b4795c2b675779ea718e06053d3133d88f3d1e99df11"
          "b30ef64e88e81df513c01c89cd3bd809bcc75b244ac8bf7a0bcd0ae53d5f"
          "b23198dd0c4dca55f35f9502de834ed1801242f9d65097f360974afbd435"
          "ab97bb147f8b0055572752f99df6afee23f28fafa37b8a6bbb00b472e53f"
          "2485e47f5ed1f828a0217ff866a94672a99d9c7e76a1b2063d0f86e5854a"
          "4f465587a2cf83e73f8983a5337ee01c70675399a6c9d17b2ef12f202a10"
          "c865cd33d9becfb16e516e9e86221981a7d056f078b116702de33f4cbe1a"
          "c06df55edef0955d6313ecca3b83dc3b4b2adeed2baf86baea922599a423"
          "c1375796da6c0f4d7ca811d3153a3be19c055acc377869ad1a41bee36576"
          "59981120d0e30f053c8fa2e7657f4648733253f723098347bb5e04d7e6ec"
          "5a476a1f501f1c5ef34057d80a03e61bf8df9ef7547c9d569436738cb578"
          "d793455be3c5246f153956ce280335a15e28679d9a9a352d9fa74011a3e0"
          "85418475411db890f9dff15d78432193817af1834ba12c1a644756c74b23"
          "0db42c35300f6303363e3c63edce5da0d59e172d0af284d3261ea47259a5"
          "606485a76059cbd0565086a80c88428d1aeabbcfa914d17107296f828c13"
          "ccfaeb424de7d6a094a5b5824a4868e859d16392bb8997b56bbad3318bb9"
          "894aca6ad71ba8c07bbf7ecd25df03a71669c1f82134525e6f9cab65e6dc"
          "88c3639502bd8cf28da71e01a0d74715c2d5798cad523078d6a318e8e09a"
          "a6c5aa40a16fe985470a0d8f665cad9b32f413527fad38c0055a9fe70807"
          "db0abc74a07bf7bee957a15c6a72f019b5ea9407ed865545263c6aa5ab01"
          "9b75298520a65ef8bea2d74297202e9ad4344b6547f8bce3c659f151260a"
          "4c63d29d911cf04915e2e1390d6a8e548f5ced7dab122353969744fd87d2"
          "3415ba2d478bc1420e9507a714ee740b85a67a178ff4f446f30beab53707"
          "79d6b32c5a78d539d79e165f2b2321959aed1778a335288bf96f41645622"
          "ae3f74653c3d83442e7e1268c6fbbc037a9f3a3eb1746666078a20a156ed"
          "09abafd21c0d5d7449d73a44fb617e69c94429c2aba68ad51d56c0e1dcca"
          "a7e6d778da948e5ff7",
       .ciphertext =
          "e21d884cd383819d07e3b08df52fe31567ee7ffbf7c496d44b262eba1e6c"
          "5f94c692ad53cc07b77d04605d8e337f3e99cf96ecbcb277d7f7c8c372fe"
          "8e6de7c28769f32bf3a5348b0294e584ff2c9825a7a452aff9b6f03c1ac0"
          "5b6c6d20661eaedd11cac57bf15234c53371ffc8a3dea7de321b1e45408e"
          "3ea3b03c9731739cfc8aec30e6ecda9ed3d5dd8c665a593bf8f7adc5d8f0"
          "72f9346438ac5dddc6788243ca5c4b9301f6703b85998970af6d4cdea0c2"
          "1136b0c469bbb3fea47b9132476ee7790cf0da2a9d633f934db54e121502"
          "a0b505e55c31a9b91447b684f8a8f3de881ed4e391e6fee8d0d5775fbd2f"
          "bc482215122f3d5cc0ed91eb7fa8d20587422b898cede3f2bfb2a8090877"
          "59e254a54e2a04d476504e978fb071fc73f38ebe15e21145a58cf3bd9e18"
          "815555aeb0030158b3fb744a19050a09225d8923eee46ddd3e714b3a67a2"
          "a84e47d0de5be84df866b7c236c47b86598d978e619d9e085fa5c743c853"
          "5adcf3574e1341e6621699a56f2c4f8ee19224a862244001c44b443e32e4"
          "3abba22fc60d2b9be5d7bef3513ccbd59f8590b1a61a3302f7e495a127b2"
          "e336c4de14d735f4126c932b9c4d9096f97f79f13ea50f000490d39621a0"
          "a4edd50b90205144795926d4b3b5b1ad32a6e706a3560739fe014f151d4a"
          "d2db4a3629b3734261e4d41ada1aaff9f7a3ba9a6e602b6a7f8faa2e5721"
          "51f4de8d470f772f9dc86f5dfd343b1f55d1e414d33a208d14fffb662e05"
          "b2cfe7474087d2e6d7097a1a3c0347d0590240d6dfceecd3ab65a5edc2f8"
          "6519dbfef07e9b3c5a6fc29d18126d68efff7af18f76660ce4aecf7b8c3f"
          "c1b04fd7789b6ae28b93f13d96806f236144b36abd4cb6aed9b153ec6dfe"
          "b6c576b2a3738b9d7832b7e0a0168d8e3f6267f6c3fd6fd40be9ecc4a3a5"
          "3b5c185a33fb3f27ed42c5092ce832d8f7afe971de8ffe23f1d5f9300ba5"
          "a3ffe8bfda3302a128904ae63b0e751987d5359427de6257e329d21263bf"
          "2da500eab3cf26d67d69272f27ea9bbcfd1229deb2170912b1c367c3cc73"
          "e7ccc16e12f27b2cb0373e0608d829675b2e595c1cfb74938a854f783f4d"
          "4b43ba0ada137f64d94aa278cbe90afc7430d31f26888df0ddd431beff31"
          "62e2db29a915b4e682e673743ae40f8cf566b5dc6e189c23aa2a3c0f8b9f"
          "1aabdc1c6289c6de623b2cbff2917e96c10c632be402ef1d6e1d83553dcb"
          "4c492aa38d07444c070566ac58ab9a97b678d56d9ee4589d46fcf2ac6803"
          "3144340780ea1f1670f03095388aec797184272db78ccd77a34dcb1980ef"
          "fe2c4b898ceb022f0c78239a8624f15555ce89b2ef626aa867b3791fb350"
          "7848cf9d38a471ce7ede75b585fea4fc30ff1ed36c3e0e33a11c9e0be3b6"
          "fa069a6fe0094159a105abc7eb283ed47be88bddfffe3b5132ea4acd5fcb"
          "4fc3c5ff51a883af5e8c52f3f1a09fdcceec1115070187dd0bacce093b94"
          "1f1e63ea1941b1a9f1"},
      {.testname = "Imported from server3",
       .key =
          "b17c259ad25e022595d44b91cc1ff933d657ebf90e6e0316754eee085d6014ff",
       .iv = "3fb363e376719096eca5de9976353d45",
       .plaintext =
          "1615bf789eaea0d98adf1fc47826389080a0a6f8b0edb8d5a54b2501151d"
          "cd931a4ead010391255baa9a880825a8537ca452db906082951523123fa5"
          "cc5fcd55c920b29acc8fe1221970647c89237c73c2768521925fdbce3ee7"
          "0c6f24716d81d3ec0a4787ff104425055f4835364cbba2ff9c83055f072b"
          "a64ec8ac860ccc83d865eaf263f53ae6a62a2bf91a0e377cc7803a323d9c"
          "7be842807c07d105e53bb67ec520a403d4a3f8c04373c93fac5d029b6153"
          "db0b78e801ed7e1811ec5474c656664fbf8b3bd65217ba6cb48a300c7521"
          "01158f37e863e3ae7a8e4e1811471e36cd3f8b920d83eb2c8a419849c575"
          "b94f478f5f128b65ae1565f3747b08b7f259cfe0e26695c3e1daec6b93fa"
          "b9a8bbd395d5afc5d85234f6aa015a8d8434f4e5b83ce9778a4350b714ec"
          "7eca553b05e85ca8200555617a8ef717bbc50f370997604fd35138308f64"
          "7e44480ac26cf0d823d983e68a3903712506a602ace9d2bdc6575dc3a018"
          "0198fabeffe0fca21a3b7f6bd6903a529ddf01815b96de44f8972778f616"
          "25103cfff5ab0d7684eccecfa30d5eb515a81f60959bb32058ecfe6ea50f"
          "fc7c201c062eb24d4f421f374de306ca0caa17782f683a3e4b66a7a65474"
          "200f3a79a607947ba147767e03202a71213b74a84c95ea0d1e80e229f54a"
          "6680eb5206a881c74942bd32cad488188b377a35b7a025d45c1196fd1b3d"
          "cf15ecdf5687b3626e427c333b4a4ece00bc0c0e8ea0c49cbe3574db2097"
          "952fd86adb76b51b7f53fbad7d80ca0438b19158cb7b3067bfcdf4e40174"
          "d7e82e7318a14c7cb37a31c69945ab08b6effa926ad436cb86ae561e5d05"
          "d12df30a1f3af36b8ffcd57ec3e22d4a09ec505d2f8ec617a33436cdb299"
          "0d4e48d1b479982546b84d4c359521170aa6b54df60ce4748a604a705759"
          "7e6c2741be55912df36f10760c2f3efaed3c7e058ae15d0cf9e831e2542f"
          "1e4599e607ca93fd17ac8b1a7523637fee23a3f11e94388fa6a46148b319"
          "56eacbbdcb6291cc5b7f86ffd5e7c2d419b8da491b3980691a8d20cc1ae2"
          "40f2d829abe3fa3385c4f24e2f2df3b560e70966a553d07a8ee1dec38b36"
          "5702ccaefa121bbc7aa4abc78c43cfb22be0497b79bcde57b8a06070b8b3"
          "00f90170025fca35fe8490880be9df73cc015a0b31e32702f5a77b4dec68"
          "1e7de642ca1a0eb03e9e90a6f7a89e3e6b9c43150ca50acc8e7a6d52b4eb"
          "9132dd3bbf77eae548bbfba426f63271fa2899c42a9d775efecd07185bb2"
          "48f2957a4f5ed758a5d54f190b0062526917e3170bc6117b26d7f8692ef0"
          "b6c34050e2c32146fe5672fa90ee4f43d661727fd7919b9a68f77ce038c2"
          "398fe3a2afd7a3b1a85f5fc3c3df1e6712157b3364b38cd47aa60d80315e"
          "9fc0a36d96757632274c66382dc3b6c0a365968a4caf7257f98801a0cef5"
          "08de13856e71c735760e9d4f9d3bbe190bf3e9eb3aebf9763292cd77b730"
          "a0b166eedf54f163444bb9f30401761ca849b8d95e107ee46b86feb948b9"
          "6ec5022bbe3d2542d1361946393a999f2034d87efb75dadf44537e400d80"
          "6e0c6d9c753ed1269ceb1924e1d5cec51fb65900a304c344c24e95cb1ec1"
          "fe8ab8a03e81e2a620e1cef594876379df07c49bf70ff04a3424564438f4"
          "83af77123f931b116d9b4d1f4918ed43cb510c3330ecb49f854030d106a2"
          "9a77b80cc13c94d0fdc46cd9fa06094988df43fcbefe4aa6106c39031daa"
          "752c9a5d15d8546826fca561129d7bd0b89c20e0969e630ad79b994aab1c"
          "8a77b1b90bb3a14296db3623036dc28d44d5c30d2e25c36740312141aaf5"
          "44c662c37dc2f57fbc1c13d5d27ac1152868a90e4e864cd22314d2061baf"
          "aeeca8373d63471b756b15211907417120b94f3b523ae3486057dd60091c"
          "ce3130c98ccaad36e4cb2b97cc1dfde8ca491fc54ce5f7f8529b3b5a4f9e"
          "976f3ab30adf3673fddafc7dbf775a6ea0b9fe188db3331e66afe37b8395"
          "78f41d031e9276e7e9c83f5c17416226d417a5e982580664758e23b2f280"
          "da149d7d4cd1697f595f4279e784bfadeaa4e4b5df9f03a0d448cbf6dd41"
          "4e9e044e303565128fc0eb3d567440b44a069d53a87994f9ead9065bdfe7"
          "5c09bb96d0c1cd4c968a40d3317a6edfed36398b6da426fd24bdaa4d5c83"
          "e158901722b93ed3ae42b9c51e4b92d4bb3110c2f237f28c016713d033de"
          "06ade95434d1b6323bf7d54bfd6a8d885a089eab2156d79496721e817ef1"
          "a85e2ba9348c28eb49b9d1a076037328b37cdac3d80ba8528baccac3bf57"
          "73207a80f0294b7a20ffc0ce31462513f2d6eca92a23ac723df5d73269c6"
          "cb40991f88f846d8dd35da5a1b22fa8a2c8d30452eecbb372c49de455945"
          "2edef4bd44913122afdd49cb831c9e9867de4e9f8f3cbf96a83bb31a6ee3"
          "7e542e591289c94dc4e7846d4570c0ad2e441ad19053ce4b9968799ac150"
          "e4e3d4abece39eab179e609486ffa6643e7c9221922e37bb49f02481a9ea"
          "9b6b73f2189c7b72d243fa492a05cc303d5ab31b2bbbce3e79296297001f"
          "cb9967b3eaf1b97b7db9d3f0c99ee835f5d6fea0377361d3123ac4715916"
          "885221bb56a9dd9af4f07928e3e3e52bb27d0b68656456d1c4db727fc81a"
          "7d353eda88c574757ba46734a5f040528e215f1d57f50c8bb4b30e61187f"
          "ceb51b3e9b9191c9fb17376071c415addd139a5b06b67abb7576330381f4"
          "1538e9b02d9f2cce47a38243c26afb860d6a49e715bd8153f99d5b9de07f"
          "448cdf4e3569a9c9bb56229d9e1fa587289f0abdf0b12c415b5141facd85"
          "fbaaceae1c6b5543519d3e3189997903941dba2564dfb5ed000c4b561487"
          "189ab91f32b45782694b83e961fab3aea18a5f582baaee360a82913b637c"
          "ab89067e9ce3c9dc4c41275b7c8f8e74a860a96948beb4432ade1f1fd867"
          "69a5322efc2200d533819c5e64c36ec9f69c49f02431446038b10be2cd54"
          "5e795a34b9093b58a1a5f08670a99aac647d893ee7e8d6d228735fe8f38e"
          "0f4f6c4fdc77cbb29c3f344dcfa98297c2c3c3f343e98c9b7821f93bd357"
          "79136ddd14232c339fbd1e9d1161247a13841bf980213076d62f357c6f30"
          "9a19e1d06634850abb3318ac06f5ee04f7bcd2fba6e18b26cec6b45e9fa2"
          "e38558881317967cc6a8441e244af61f86f8c7de558106d864152f809bd6"
          "6a021792e7b78a7ada72567b1de15344f897f150f9dbd6520002d64faf95"
          "1cd91ea52d51221e56ea170a616a245923d1dc485f21a9c98e7d475ffbbf"
          "d7778332b08fd586ff19c18afb7a0bd1ebdcfc6827d5f1bcf6f047f387ca"
          "4231b580f714ffbf8685031e1726f470e853a5f065aa53d89dddb99e45e7"
          "c87f18cbe62b00af152a9c168dd84b5d12ba935dfc8e4f22685cd43be77a"
          "d1fac6f1d7c98cf8f958ff775c6c90cda5751a3531beaa3072647951a75d"
          "4f207d334d274debfa950fe3a8516f3058be2c9594d175d890a5493e22c9"
          "762e32b8ef15cf8156f8483e83c4fd5b5405d41186366fbc65686ac97ca2"
          "0998814b304c23cf38194e222203e17af4f9bf18078d8b456238e9662fa1"
          "627995bbdbf557fed074361241996238d4578abe51f0a91fb39069e66983"
          "6b430ef1847b52693a29f4e99b5f5e6a783723c703b958fd3b6663e096b4"
          "e78a2d66ebea68bafd548aa286a1b9ceddb774c8b71769f5f693e7a0d70b"
          "d9698a525e7b93aa48ca18445473830e4eab58426f04d69d6623ae9cc3e6"
          "858db45cc23386b9852df4dddcfbc8f2a9a345fc95dc379752e484f6df92"
          "54ea6f85c0f309dbec76682cc3086bc5759f9db4107f3119b1504021d9c6"
          "ca9114b5c05dff3a97aa6cb642eae3c0ba6acc83e3718ee71520220240dd"
          "d426f0785aa926767d7fd5794f0fc9ceb763738ec84d887d310c28f8abb0"
          "94f1e1fc8e029dfe37816a9a47d0a9b0b70dcb316a9df7945912eb9b26bc"
          "b110504ce7295135f6c0474c0fa558abb7ad026987be83b2f3ebea1e00dd"
          "54b267b67a237811f00f52d015307448b131138e5568659b149a5adfd7e6"
          "41d1e0086be4553a28749d8cd777ea615c34072fd43f7fe91421595730c0"
          "11f27157af52b00cd34de7ba2b6bf87377b8b92567f4fa43b9aafbb2b653"
          "355d197beda8815a8653af54eea5cda9a29578198493396100648c265400"
          "493f10f61995a4583f96e26e7ff57a91409734c9e5eb227de87c9668e68c"
          "00b8cde14c397d76eed2a312237af32417787baa30a42bb1d3115dd1d06b"
          "4d7f78fb02a2b482fc09c3bf41bc0a58d1003fd4c542fd8e6cd9d6f6c260"
          "c60771f62d2e4eb4d9231a1b69e1385e0b7c901e38941316656b63282534"
          "1eaa23642cfc63874c40a61c29d09100c884d0d4c33131dc0a60bc72b169"
          "2693762a1dc44860844625c36d24c7d8a039d95c1d3899619fcd6a52cfee"
          "fb9415f2a8bc13c2e95dc3d571d732e3387be09cfb7767f3a029b3334dfa"
          "efc08f9ed3c3aae56c898a93a0e38fcf64a2d81a7e6d1a12c5a43cd1c81c"
          "95fcb7070b3ee1f383360bf6076db9910140d3d7eda4b96e2efa051e7b7e"
          "329391d01aa3348f6a627372a209492d80755a26bc8c1582b20d884f174c"
          "8d91c54275fcb4074d9d7c0f246ea54aac53f3b3ac81206a9ff7f8fd0e30"
          "fdd21e7f843e4ddb23119bebb37d36e48d3b20f3d05d79405d5917d38fcd"
          "628b11fecee1853e9e6e97a041aace189889d0182853b25c283c2a7dceb6"
          "64da4ce77579c948744f960033767f72f7c5fe9592ec9c968e513493a267"
          "44cb0f3648a0c8657e6394ec0820430ad77520a322a1ca07e2381e880995"
          "0602f717bcd7607e7394bdc270a4b48aba187ab379753429bbe404c384c5"
          "19bcd9fc90a0ee1715ad225f8776220727359b6e7db56be944c8defb9ad4"
          "5baf8ad79b5ebdcdbca2854e5b57e277b0e0f4c39c2bf3af38757236d518"
          "8cbdc1786ff57f0fab229612061e5eab9ccb6f1eb96d0e63a7231863c55a"
          "cc4056eeaa9f290ce14203f25a5a5c892319f94d929ca9c142ba44cf668c"
          "393bcc2095c7217d1aa5cccffbd5a386912addeb29380df618b32660e001"
          "99afe586867c275ed3aa41934b2740a2453a2c826b570e70cc26d3d6259f"
          "72337c2b7c5d04248fef27ddbdbce0945613256eb1fae3adc8ce4f094e40"
          "2ea170b34db89aa1153d23f47c2c214e1395197e2d311b234fcc8ba40d95"
          "90e65fe05449d2bb0c9d84beb11335994f766e782ef55aafa65d20343669"
          "ecf499492c06cd47d89d2fd897c220ca710879d80bdc025fc21baebde345"
          "9274a16fecd0e9da64ecf14c4e1a4eb4b2a5cb562ecd078694fdd57463eb"
          "906c31d93977d43d75f1863b58944ac44ebc0b3b70715a13f86a5816d90a"
          "053289a5ca4f4be0f799f0b21cc2558e195724ee95fc44855d5c8eb32798"
          "b0ef7ec48e05882ddf4e4817cee79cbb451bdd2c720298eb925b1f010702"
          "0bc10f42553928d79905fdce432fbbbcf1c635e7083302e1d0d5bb4fbc5f"
          "2f6169cde7957377aecab747fb5fbc2c4cfa",
       .ciphertext =
          "999264c56b6cd5f1b6c01834e39a2abdc31a4b73fde183ede01d5506184d"
          "cd6fdfba2d2ac17cd54bca45d6f7800f695cca8f1e365f33bc6fee82c7f6"
          "9285b5720107f7b63881e25ead1bb7be4abc7bee14b81da8f655e999a383"
          "6d1eb1f4af171fdb49bd0540efd351ba13b624158222a07642becd3a0cce"
          "57108ac577fcdd138dd20bf92c65b78cf6a36871f2bc08b7af6e9bc21994"
          "f7f860e9a0bb97cda16a7b849cc922bd37683cafeb6b198a3f6a1f884500"
          "80cf5a1ec3e2dac5f2581aab59de3f4b212fbb8e07f7b754122abefc6fc8"
          "e09d0fa5bc6a8ac32af418a2f6325678d0f0f0d3861e8aa0a29e80698269"
          "8c2b6a58eb171a426594fe5c6347794ad4435c1de1f9224d387d95f3b773"
          "033f5c96069f49613276f3ba8b2c3f24d7ff523d13266e84b9c753da33cc"
          "f21c97d9a120efaca36aafafc940835dc62a7f0b4ae0a9a7842b4eaeb195"
          "73a9b332b540d74a2e2a2e714808f293144bfec2d3735b2bc4d9b6510c97"
          "2c477adfe67e3055ed10bfaebba217153eec70c28c21b4e8b57b3a238685"
          "54777dc268d1d1f11084b130f68fefb0a94fc58ee536256ae4f103e2a3ff"
          "7953f54a62868213bf4b68f7542c00accb5bdbfc4b592533b86e0e7834b8"
          "818b1527de9cc93f98941b7672c6de788bc518e45369ad937c93075e6a94"
          "8c630fdbce333a138201a9f6c50dd7caa1dba1f3416015f23c7a6e1f712f"
          "e13ce86c8a0b8681fa8b82dcab827670d8e912820efb1d329ea5ddc9cef4"
          "d16ad664a11f1c8080aad3de9a5c79207732bbb5bef9f06419b2fad7de90"
          "54cd25f91b7773e6b307e2b259c70f258929acf02966190027142d1c46bb"
          "3058cd1b2510188f25189af92df419426557a1b16a70b08d45a51df48884"
          "a207ee0b987c8ca17a1a671bb78a5548dbb020b80d5f73bb3bec4986ba18"
          "58f097621377a15746efd8c2c59231624c10d8268865c0f4b58dce54fc71"
          "446fbb67935b4a67b0b8f837c92b43850fbf7d7311896515672143f1a2d1"
          "c5374fe8d564eb8436817cbc52faa9751002e02295e1e4e53f3070b6de63"
          "23a450783bc0ea08b36c215ecb341b86dca0dfc13b8f129bf3599d2de73d"
          "774243dc04cbe60fbc0abb1ee77a3af112edd659954ddc50b965226bf93f"
          "b04cdb3f8da1e48bf473d1c131fb1f80b123f381ea8b5d3f471ba09f8de6"
          "5111bc95abdbd77e369719aaa1a9d1949f38ce8abeedd14e8b0624c25de1"
          "9106e281742a8771c03fda9010a9d598ae91e8eed61e8422da3a94fe157b"
          "25fdef8518fedf0ee3a56af2d3801b6baecf38e4dc4dd74f03c7a94a338c"
          "cb6188664d0be62feab0dd226fd7dfe5e27427a4ae1df9310a134113bdbb"
          "8b61f9e343632537550ac2204e2d3e1cbe82f10825dbb40e08bf9d2a0f68"
          "25e260c3a123995356b6c667404c8f42d3e24580cf1d57a0d7d66a4ea35e"
          "6d932b909960b488a6a4a017ceb04123bf54dbe64803d54478d303fe9e44"
          "4dd4dfd713e5195fbd710a7af60dcee39b38cd24d48504e895c357965ca1"
          "0157319e70e64019ca831019637ffd458aba4242b18c483e42b1ee9b6328"
          "43344a632a8491ffcb1e30e1ae0ddedf29957185ada4891521d9d2f381a4"
          "d4cee31362e1b9b5c4e2e034d7274a3b32af150910d7a30522e4b02b99db"
          "e0a9d9b54efa8663801b4d1a5a9db4d6efdd81447289c67dcac1557b33a0"
          "4a030ee65e07624f1cb931b302882ac04ccc1ca258f092cb41c70441ab85"
          "0b590c0aec31241937a427399e78b8c4b7a653f9f9440728b0747200466c"
          "088cb378350a48ae088ff50670ba37b7b791a0e8ea9b845628a84910a36b"
          "117d2927d6635fbe93bbe4bdbc70c0469239621fb30097bcca92c56ee7cd"
          "2bb949fe74b7c4a81df28cb4b2dc0d26c7b01dc2ec7c095972bcd7d86da5"
          "7c936a1aa8d6c07ce58a3361034658e21eff8246201e8c6edd482cfd4f24"
          "c1986f8c9320dda7ed01646f2a567191fd41b559fd677d037bc2e24f82d3"
          "08dfd4038ee4d1c5c82e05361d9c089ed1926ce25a296db23c6c92e95a60"
          "06129dc38c6aa5c85f9fce44548f0bd0a7c321226f2042d1594f4e2026c5"
          "1085f103433c50b0b183027d426a79b54187701a7c0dcd90c1413399acfe"
          "7f06ddfc8e6fba6df15c147811035f11097b82d4f75f296f2b1570f35cca"
          "8c5bafdb1edf495bc0e88de303f57267f25f678ef6613e952ae4999bdff8"
          "f5413956ca34aabc1d740d75a1b8c4da528fa1c83ef10bd9fd66df75f0cd"
          "94f92d29b82ee5d0fcbb3908a91d2b0e84805a5bbf4f629db29ca6aa6696"
          "5dd602abae69cc4107e18551bca1e1bcee8da0be2cbd3e1c009dfdd8ba1c"
          "628f4c0456750794517fbb5226577892e46bcc326accb6201d85301a9720"
          "e28b7b531b24fa485fbeb758d06b1f4a732ad44b249d593e73cb15325344"
          "5d26a5c57db620445627bcb7d20b82350ff32c8f4abc29e24ef3e21b8ded"
          "8d88c2962f2f494025a659d1889a32d3afbd2875ab46252c6fc93ad62a89"
          "175db177da985993bf569dc52c3fa53cfe215bd536515358d5937a683dcc"
          "de9f9a98ad35b228ebb567a63bdc06f839ba5d5c5fbe7dcd29cdd50a9c66"
          "d477ca318d8ab3ecaff0e167d242d052998630cbac10af3864f3545b8a6c"
          "1c6314527a70b46f9cc0f08f3d194053858f7213736702bf3984b7a91453"
          "ea18f8c6fab86244dba6b1a0e98a18695752114ac054ab47dc452ff0b94e"
          "a9b92798f30680bf4a9f05311ee01e5dbecba47cb442d32513ffd3dded6c"
          "1083b98b81f509fd4a8325dfa83d9c3787b06d4f1a564e7f4fb9ea586b68"
          "ad11180b721b180715a3e644b687ec84ba37a8ffd1987fb9003ca3fbde0b"
          "7ad1239881979a7546ebb31b5b535e4367ea52f591c78535479863b75a5b"
          "4cde7e9fd19181cc4648980d617f124ea3584259d245b6fbc36eef4dc4c4"
          "5b22e2d8b1b76775d3d7e8bddabdd375be0511b22d42dd7ac3450a7a5bff"
          "67c29081823a31daf43aff862e90d2afed570550399432691c2beccee99f"
          "f2d42425fffad201a70976c4048472fd87e9ea9b899cc32446f597f9a4e7"
          "63dab0da02c7f0283b26696142d1371006f219935a1cfaef4db6c1e91d9f"
          "f3b51567a85f202159fcc19db1c6f8d687bfcc3aa60c429fa605d61fe3d3"
          "74eb1fcc50ac3a69094412a0dcfdd312c40358ac259e6d027452d12b65b9"
          "1c75c029db49f3c7605882686de6ffdc492593960ec9354e7e834fd1e7a5"
          "d7f94f0c88433897b63ddb1691e2e9a6f41c03d449ee9acc4b9769a58a7f"
          "1991071d5360a63a39b85b4c38b5f06ae62187fdf0220f20db673946675f"
          "a7be4c67d19eb6140e2f4606fe961a49526f3e40806416f67289cebdbae1"
          "b4f8239cd5aa9d7afb9ee1b3f446b0b2b97f8be9020735950b157b739915"
          "38286f55322e9531a41e7f47cc855479af3b9858397a9672af3e03d0471b"
          "00048f51005411c3b968c41c50fcff0735c083244e06946371228bf2b638"
          "5d1a43e2c724ab086e0f0739e392b914e86dc0450e89d55a571c7a37bcd2"
          "5baaead8e2a49fabd9c05a061c348ca805b7ef089a71b06f4cf4617a285e"
          "51e74e9433a66d2dcaae94b944d27d9a9caca7a06e5795eb48ed5ddff471"
          "bd534374845dba3455232bbcd2644ed1bd7e6ed22b566f1b250795b6f82d"
          "4eb7a0170be792f76d5fe96a86803e92b5c58446e656cbc2e13fecdca44a"
          "83af48f70e620ac34d7fbd2bac610a10a010287a67ea40285a85a2c91a04"
          "95c5e47d4ea363dec1d69f587975fbe64d70e3423c75cde86602369aa383"
          "59dd410c1dad185cabcf161bac22c434b27da6e8f25907307a8c273c37ae"
          "bfb4f38c06ed145fa13f1e47585cb2070c363a106d0e0f5d9602f7bf1b0e"
          "4001e89a59210b3cbf01a1497498548b8948e286bf73b9afda48e0105e07"
          "a05cbbd79c66066e74c6480f78dfad23d57d61313d978f08143ac8c77e7c"
          "28c0397bdba32b5bf33d2c71606e71c196dac449b3bb03e733b7036ebf0b"
          "73e277e135452b2a1338222aa259b1448fc629805483eb15f591639756a2"
          "0b57d590904ba17b4e3e6b965a8ba7f20f5ab89cd47aece129870507ddc4"
          "3e2c829c64d93e36883943d3da458b8955a3b1f8b92fac4564e7c219d743"
          "bc39331c18d22fe27ead16219a61d82a2c18755bf6bcc553ad5b0683ac6a"
          "bb5b92e79cddfee4b92d9dbcc6626979c358a4e1a8f37b651241faabb4e1"
          "e460110b2db5254971fef2b9877498feb6107f1c5adcc763ed6de820943b"
          "703249bdd796adffd76c7cc6046d3baf57a13ff5f55ad589396298c6b0e2"
          "30da90a0b9230f457eb5db8962b9bb0ae406f29feab529c827117e39c757"
          "c2eed15b9b72576605ebbab9b632024bce65a759e17975182d50c04bdee6"
          "b8fca4fc488ed2a386fa226c5ce8366f67ec3eba883ceefed963bf29c0de"
          "829b406b02a6850f953a430e70fdbaa2998095daf93366819e3df71260b6"
          "6d035b1c908b20ba62c0d83c27b24cfb9c3b4a5a35316ae8703245f47323"
          "e15ff775b41d2953633865f1d6861a9cab887635aae8b80efe7dcd0cfbeb"
          "3ffa6aa4a31a0550b0a9b0f6517c83f0247529bf8cfbdbe5c0092c6d4fd1"
          "a8c5539704619d28300ac53a9fcd0266fd65ff4e8fd350f3d128eb001312"
          "b1ffeacef11d5dde1b7dcf3282eae4c206d76d38a2f22a8fee2d0666ed36"
          "012ae4857b75171694e1a89a849007f4dce1f769d465055abfdcdb72e9ea"
          "b8670b5a359e8d6b18d226ef24af5f72f79b00b4f3473737f65732865970"
          "752c6a1efcd03d9846c41403ba3cb9a8e50d89ca49201e899c61ad7acc87"
          "b69b9e28f86f9f44fc3400202dd6c010848b3daeea2c3ca54886ce8e11cf"
          "5ecef01589f65032cb901f051d291e5dc85d1a72f49bd549c3fb1fc1f08a"
          "bf0d35fa1eaf3d60b44621e757825963f9407b80ba1a310979fa303ded3e"
          "73c34089ab2764143976b002af7ce663ee367a3824951bc7a87e16169db3"
          "d65fec5acd329db54fc30ae9f1e65aef750474e3283c858b7f325734b711"
          "2206e1992e6db244ef867e1179d544da3dccdbaa79ffd19adb7340b5af3e"
          "3de55040734ae354fbcb12efbd02cd1ed6cbbd9057977a60f3440488d26e"
          "68cf0e07cfbd65026bb57bba20bb69e53fe87228420cf08e73f12dab7b4a"
          "e87e00cb38a010a8368d8c8db225317c60a2cf2a01acbb6de8adee370e62"
          "ca4e8c6cf5fa976f45ec62421f084d19c5f724135020fa1c01578fecc381"
          "83454911d67ea34ff0bae3ebe29c1d12d14f5f561ff960f770cfc3cdd9f7"
          "16c5a12e8fedb6928f2f7bdf80d05c7cee7e12d1510eae13bcd1619be41f"
          "eb16a5f4070563a28b2d59d8ca92be92297910ba63d827b1174cdcac6ce6"
          "4af153a773945bbb293d8e5c6603684f24a8dfdea742e07ff312f912fa96"
          "1863d8a665ca68a7875be7a09ee5920bf442767fbcd245b5300e1479f8b0"
          "82ca2e3adffa4680fd1adea93ea83ecba4d6deca41d07573ed2098862dd3"
          "185d651d42c1420de3f64f15c7f246a06fbc"},
      {0}};
   aes_256_ctr_test_t *test;

   mongocrypt_t *crypt;
   crypt = mongocrypt_new ();

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
              "remove once MONGOCRYPT-385 is complete");
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

   mongocrypt_destroy (crypt);
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
   /* key is a 96 byte Data Encryption Key (DEK).
    * The first 32 bytes are the encryption key. The second 32 bytes are the mac
    * key. The last 32 bytes are unused. See [AEAD with
    * CTR](https://docs.google.com/document/d/1eCU7R8Kjr-mdyz6eKvhNIDVmhyYQcAaLtTfHeK7a_vE/).
    */
   const char *key;
   const char *plaintext;
   const char *ciphertext;
   uint32_t bytes_written_expected;
   const char *expect_encrypt_error;
} fle2_aead_roundtrip_test_t;

void
_test_fle2_aead_roundtrip (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   fle2_aead_roundtrip_test_t tests[] = {
      {.testname = "Plaintext is 'test1'",
       .iv = "918ab83c8966995dfb528a0020d9bb10",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ec"
          "c9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a00000000"
          "00000000000000000000000000000000000000000000000000000000",
       .plaintext = "74657374310a",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd"
                     "57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b998387c",
       .bytes_written_expected = 54},

      {.testname = "Plaintext is one byte",
       .iv = "918ab83c8966995dfb528a0020d9bb10",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ec"
          "c9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a00000000"
          "00000000000000000000000000000000000000000000000000000000",
       .plaintext = "00",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1004b2f319e0ec466bc9d265cbf"
                     "0ae6b895d4d1db028502bb4e2293780d7196af635",
       .bytes_written_expected = 49},
      {.testname = "Plaintext is zero bytes",
       .iv = "918ab83c8966995dfb528a0020d9bb10",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ec"
          "c9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a00000000"
          "00000000000000000000000000000000000000000000000000000000",
       .plaintext = "",
       .ciphertext = "",
       .expect_encrypt_error = "input plaintext too small"},
#include "data/fle2-aead.cstructs"
      {0}};
   fle2_aead_roundtrip_test_t *test;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
   printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
           "remove once MONGOCRYPT-385 is complete");
   return;
#endif

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

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
      _mongocrypt_buffer_copy_from_hex (&associated_data,
                                        test->associated_data);
      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&plaintext, test->plaintext);
      _mongocrypt_buffer_copy_from_hex (&ciphertext, test->ciphertext);
      _mongocrypt_buffer_init (&plaintext_got);
      if (plaintext.len > 0) {
         _mongocrypt_buffer_resize (&plaintext_got, plaintext.len);
      }
      _mongocrypt_buffer_init (&ciphertext_got);
      _mongocrypt_buffer_resize (
         &ciphertext_got,
         _mongocrypt_fle2aead_calculate_ciphertext_len (plaintext.len));
      status = mongocrypt_status_new ();

      /* Test encrypt. */
      ret = _mongocrypt_fle2aead_do_encryption (crypt->crypto,
                                                &iv,
                                                &associated_data,
                                                &key,
                                                &plaintext,
                                                &ciphertext_got,
                                                &bytes_written,
                                                status);

      if (NULL == test->expect_encrypt_error) {
         ASSERT_OR_PRINT (ret, status);
         ASSERT_CMPBYTES (ciphertext.data,
                          ciphertext.len,
                          ciphertext_got.data,
                          ciphertext_got.len);
         ASSERT_CMPINT ((int) bytes_written, ==, (int) ciphertext.len);

         /* Test decrypt. */
         ret = _mongocrypt_fle2aead_do_decryption (crypt->crypto,
                                                   &associated_data,
                                                   &key,
                                                   &ciphertext,
                                                   &plaintext_got,
                                                   &bytes_written,
                                                   status);
         ASSERT_OR_PRINT (ret, status);
         ASSERT_CMPBYTES (plaintext.data,
                          plaintext.len,
                          plaintext_got.data,
                          plaintext_got.len);
         ASSERT_CMPINT ((int) bytes_written, ==, (int) plaintext.len);
      } else {
         ASSERT_FAILS_STATUS (ret, status, test->expect_encrypt_error);
      }

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
   /* key is a 96 byte Data Encryption Key (DEK).
    * The first 32 bytes are the encryption key. The second 32 bytes are the mac
    * key. The last 32 bytes are unused. See [AEAD with
    * CTR](https://docs.google.com/document/d/1eCU7R8Kjr-mdyz6eKvhNIDVmhyYQcAaLtTfHeK7a_vE/).
    */
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
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ec"
          "c9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a00000000"
          "00000000000000000000000000000000000000000000000000000000",
       .plaintext = "74657374310a",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1070cead40b081ee0cbfe7265dd"
                     "57a84f6c331421b7fe6a9c8375748b46acbed1ec7a1b9983800",
       .expect_error = "decryption error"},
      {.testname = "Ciphertext too small",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ec"
          "c9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a00000000"
          "00000000000000000000000000000000000000000000000000000000",
       .plaintext = "",
       .ciphertext = "00",
       .expect_error = "input ciphertext too small"},
      {.testname = "Ciphertext symmetric cipher output is 0 bytes",
       .associated_data = "99f05406f40d1af74cc737a96c1932fdec90",
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e50ec"
          "c9c6c1a6277ad951f729b3cc6446e21b4024345088a0edda82231a46ca9a00000000"
          "00000000000000000000000000000000000000000000000000000000",
       .plaintext = "",
       .ciphertext = "74c1b6102bbcb96436795ccbf2703af61703e0e33de37f148490c7ed7"
                     "989f31720c4ed6a24ecc01cc3622f90ed2b5500",
       .expect_error = "input ciphertext too small"},
      {0}};
   fle2_aead_decrypt_test_t *test;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
   printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
           "remove once MONGOCRYPT-385 is complete");
   return;
#endif

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

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

      _mongocrypt_buffer_copy_from_hex (&associated_data,
                                        test->associated_data);
      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&plaintext, test->plaintext);
      _mongocrypt_buffer_copy_from_hex (&ciphertext, test->ciphertext);
      _mongocrypt_buffer_init (&plaintext_got);
      if (plaintext.len > 0) {
         _mongocrypt_buffer_resize (&plaintext_got, plaintext.len);
      }
      status = mongocrypt_status_new ();

      ret = _mongocrypt_fle2aead_do_decryption (crypt->crypto,
                                                &associated_data,
                                                &key,
                                                &ciphertext,
                                                &plaintext,
                                                &bytes_written,
                                                status);
      if (test->expect_error == NULL) {
         ASSERT_OR_PRINT (ret, status);
         ASSERT_CMPBYTES (plaintext.data,
                          plaintext.len,
                          plaintext_got.data,
                          plaintext_got.len);
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

typedef struct {
   const char *testname;
   const char *iv;
   /* key is a 32 encryption key. */
   const char *key;
   const char *plaintext;
   const char *ciphertext;
   uint32_t bytes_written_expected;
   const char *expect_encrypt_error;
} fle2_encrypt_roundtrip_test_t;

void
_test_fle2_roundtrip (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   fle2_aead_roundtrip_test_t tests[] = {
      {.testname = "Plaintext is 'test1'",
       .iv = "918ab83c8966995dfb528a0020d9bb10",
       .key =
          "c0b091fd93dfbb2422e53553f971d8127f3731058ba67f32b1549c53fce4120e",
       .plaintext = "7465737431",
       .ciphertext = "918ab83c8966995dfb528a0020d9bb1070cead40b0",
       .bytes_written_expected = 22},
#include "data/fle2.cstructs"
      {0}};
   fle2_aead_roundtrip_test_t *test;

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
   printf ("Test requires OpenSSL. Detected Common Crypto. Skipping. TODO: "
           "remove once MONGOCRYPT-385 is complete");
   return;
#endif

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   for (test = tests; test->testname != NULL; test++) {
      bool ret;
      _mongocrypt_buffer_t iv;
      _mongocrypt_buffer_t key;
      _mongocrypt_buffer_t plaintext;
      _mongocrypt_buffer_t ciphertext;
      _mongocrypt_buffer_t plaintext_got;
      _mongocrypt_buffer_t ciphertext_got;
      mongocrypt_status_t *status;
      uint32_t bytes_written;

      printf ("Begin test '%s'.\n", test->testname);

      _mongocrypt_buffer_copy_from_hex (&iv, test->iv);
      _mongocrypt_buffer_copy_from_hex (&key, test->key);
      _mongocrypt_buffer_copy_from_hex (&plaintext, test->plaintext);
      _mongocrypt_buffer_copy_from_hex (&ciphertext, test->ciphertext);
      _mongocrypt_buffer_init (&plaintext_got);
      if (plaintext.len > 0) {
         _mongocrypt_buffer_resize (&plaintext_got, plaintext.len);
      }
      _mongocrypt_buffer_init (&ciphertext_got);
      _mongocrypt_buffer_resize (
         &ciphertext_got,
         _mongocrypt_fle2_calculate_ciphertext_len (plaintext.len));
      status = mongocrypt_status_new ();

      /* Test encrypt. */
      ret = _mongocrypt_fle2_do_encryption (crypt->crypto,
                                            &iv,
                                            &key,
                                            &plaintext,
                                            &ciphertext_got,
                                            &bytes_written,
                                            status);

      if (NULL == test->expect_encrypt_error) {
         ASSERT_OR_PRINT (ret, status);
         ASSERT_CMPBYTES (ciphertext.data,
                          ciphertext.len,
                          ciphertext_got.data,
                          ciphertext_got.len);
         ASSERT_CMPINT ((int) bytes_written, ==, (int) ciphertext.len);

         /* Test decrypt. */
         ret = _mongocrypt_fle2_do_decryption (crypt->crypto,
                                               &key,
                                               &ciphertext,
                                               &plaintext_got,
                                               &bytes_written,
                                               status);
         ASSERT_OR_PRINT (ret, status);
         ASSERT_CMPBYTES (plaintext.data,
                          plaintext.len,
                          plaintext_got.data,
                          plaintext_got.len);
         ASSERT_CMPINT ((int) bytes_written, ==, (int) plaintext.len);
      } else {
         ASSERT_FAILS_STATUS (ret, status, test->expect_encrypt_error);
      }

      mongocrypt_status_destroy (status);
      _mongocrypt_buffer_cleanup (&ciphertext_got);
      _mongocrypt_buffer_cleanup (&plaintext_got);
      _mongocrypt_buffer_cleanup (&ciphertext);
      _mongocrypt_buffer_cleanup (&plaintext);
      _mongocrypt_buffer_cleanup (&iv);
      _mongocrypt_buffer_cleanup (&key);

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
   INSTALL_TEST (_test_fle2_aead_roundtrip);
   INSTALL_TEST (_test_fle2_aead_decrypt);
   INSTALL_TEST (_test_fle2_roundtrip);
}
