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
#include "mc-tokens-private.h"
#include "test-mongocrypt.h"

static void
_test_mc_tokens (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   mongocrypt_t *crypt;
   _mongocrypt_buffer_t RootKey;
   _mongocrypt_buffer_t expected;
   _mongocrypt_buffer_t v;
   uint64_t u = 1234567890;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   _mongocrypt_buffer_copy_from_hex (
      &RootKey,
      "6eda88c8496ec990f5d5518dd2ad6f3d9c33b6055904b120f12de82911fbd933");
   _mongocrypt_buffer_copy_from_hex (
      &v, "c07c0df51257948e1a0fc70dd4568e3af99b23b3434c9858237ca7db62db9766");

   mc_CollectionsLevel1Token_t *CollectionsLevel1Token =
      mc_CollectionsLevel1Token_new (crypt->crypto, &RootKey, status);
   ASSERT_OR_PRINT (CollectionsLevel1Token, status);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "ff2103ff205a36f39704f643c270c129919f008c391d9589a6d2c86a7429d0d3");
   ASSERT_CMPBUF (*mc_CollectionsLevel1Token_get (CollectionsLevel1Token),
                  expected);

   mc_ServerDataEncryptionLevel1Token_t *ServerDataEncryptionLevel1Token =
      mc_ServerDataEncryptionLevel1Token_new (crypt->crypto, &RootKey, status);
   ASSERT_OR_PRINT (ServerDataEncryptionLevel1Token, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "d915ccc1eb81687fb5fc5b799f48c99fbe17e7a011a46a48901b9ae3d790656b");
   ASSERT_CMPBUF (
      *mc_ServerDataEncryptionLevel1Token_get (ServerDataEncryptionLevel1Token),
      expected);

   mc_ServerTokenDerivationLevel1Token_t *ServerTokenDerivationLevel1Token =
      mc_ServerTokenDerivationLevel1Token_new (crypt->crypto, &RootKey, status);
   ASSERT_OR_PRINT (ServerTokenDerivationLevel1Token, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "1adc114b462741e6ac9f52eacf3dcb8cbca19827693c571d9418fda570c29d82");
   ASSERT_CMPBUF (*mc_ServerTokenDerivationLevel1Token_get (
                     ServerTokenDerivationLevel1Token),
                  expected);

   mc_EDCToken_t *EDCToken =
      mc_EDCToken_new (crypt->crypto, CollectionsLevel1Token, status);
   ASSERT_OR_PRINT (EDCToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "167d2d2ff8e4144df37ff759db593fde0ecc7d9636f96d62dacad672eccad349");
   ASSERT_CMPBUF (*mc_EDCToken_get (EDCToken), expected);

   mc_ESCToken_t *ESCToken =
      mc_ESCToken_new (crypt->crypto, CollectionsLevel1Token, status);
   ASSERT_OR_PRINT (ESCToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "bfd480f1658f49f48985734737bc07d0bc36b88210277605c55ff3c9c3ef50b0");
   ASSERT_CMPBUF (*mc_ESCToken_get (ESCToken), expected);

   mc_ECCToken_t *ECCToken =
      mc_ECCToken_new (crypt->crypto, CollectionsLevel1Token, status);
   ASSERT_OR_PRINT (ECCToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "9d34f9c182d75a5a3347c2f903e3e647105c651d52cf9555c9420ba07ddd3aa2");
   ASSERT_CMPBUF (*mc_ECCToken_get (ECCToken), expected);

   mc_ECOCToken_t *ECOCToken =
      mc_ECOCToken_new (crypt->crypto, CollectionsLevel1Token, status);
   ASSERT_OR_PRINT (ECOCToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "e354e3b05e81e08b970ca061cb365163fd33dec2f982ddf9440e742ed288a8f8");
   ASSERT_CMPBUF (*mc_ECOCToken_get (ECOCToken), expected);

   mc_EDCDerivedFromDataToken_t *EDCDerivedFromDataToken =
      mc_EDCDerivedFromDataToken_new (crypt->crypto, EDCToken, &v, status);
   ASSERT_OR_PRINT (EDCDerivedFromDataToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "53eaa4c23a3ff65e6b7c7dbc4b1389cf0a6151b1ede5383a0673ff9c67855ff9");
   ASSERT_CMPBUF (*mc_EDCDerivedFromDataToken_get (EDCDerivedFromDataToken),
                  expected);

   mc_ESCDerivedFromDataToken_t *ESCDerivedFromDataToken =
      mc_ESCDerivedFromDataToken_new (crypt->crypto, ESCToken, &v, status);
   ASSERT_OR_PRINT (ESCDerivedFromDataToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "acb3fab332131bbeaf112814f29ae0f2b10e97dc94b62db56c594661248e7467");
   ASSERT_CMPBUF (*mc_ESCDerivedFromDataToken_get (ESCDerivedFromDataToken),
                  expected);

   mc_ECCDerivedFromDataToken_t *ECCDerivedFromDataToken =
      mc_ECCDerivedFromDataToken_new (crypt->crypto, ECCToken, &v, status);
   ASSERT_OR_PRINT (ECCDerivedFromDataToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "826cfd35c35dcc7d4fbe13f33a3520749853bd1ea4c47919482252fba3a70cec");
   ASSERT_CMPBUF (*mc_ECCDerivedFromDataToken_get (ECCDerivedFromDataToken),
                  expected);

   mc_ServerDerivedFromDataToken_t *ServerDerivedFromDataToken =
      mc_ServerDerivedFromDataToken_new (
         crypt->crypto, ServerTokenDerivationLevel1Token, &v, status);
   ASSERT_OR_PRINT (ServerDerivedFromDataToken, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "4a671dbf25d68b6c040a077dabb4e63869e03f4d466803609233b16356ec6d66");
   ASSERT_CMPBUF (
      *mc_ServerDerivedFromDataToken_get (ServerDerivedFromDataToken),
      expected);

   mc_EDCDerivedFromDataTokenAndCounter_t *EDCDerivedFromDataTokenAndCounter =
      mc_EDCDerivedFromDataTokenAndCounter_new (
         crypt->crypto, EDCDerivedFromDataToken, u, status);
   ASSERT_OR_PRINT (EDCDerivedFromDataTokenAndCounter, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "70fb9a3f760996f2f1438c5bf2a4d52bcba01b0badc3596276f49ffb2f0b136e");
   ASSERT_CMPBUF (*mc_EDCDerivedFromDataTokenAndCounter_get (
                     EDCDerivedFromDataTokenAndCounter),
                  expected);

   mc_ESCDerivedFromDataTokenAndCounter_t *ESCDerivedFromDataTokenAndCounter =
      mc_ESCDerivedFromDataTokenAndCounter_new (
         crypt->crypto, ESCDerivedFromDataToken, u, status);
   ASSERT_OR_PRINT (ESCDerivedFromDataTokenAndCounter, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "7076c7b05fb4be4fe585eed930b852a6d088a0c55f3c96b50069e8a26ebfb347");
   ASSERT_CMPBUF (*mc_ESCDerivedFromDataTokenAndCounter_get (
                     ESCDerivedFromDataTokenAndCounter),
                  expected);

   mc_ECCDerivedFromDataTokenAndCounter_t *ECCDerivedFromDataTokenAndCounter =
      mc_ECCDerivedFromDataTokenAndCounter_new (
         crypt->crypto, ECCDerivedFromDataToken, u, status);
   ASSERT_OR_PRINT (ECCDerivedFromDataTokenAndCounter, status);
   _mongocrypt_buffer_cleanup (&expected);
   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");
   ASSERT_CMPBUF (*mc_ECCDerivedFromDataTokenAndCounter_get (
                     ECCDerivedFromDataTokenAndCounter),
                  expected);

   _mongocrypt_buffer_cleanup (&expected);
   mc_ECCDerivedFromDataTokenAndCounter_destroy (
      ECCDerivedFromDataTokenAndCounter);
   mc_ESCDerivedFromDataTokenAndCounter_destroy (
      ESCDerivedFromDataTokenAndCounter);
   mc_EDCDerivedFromDataTokenAndCounter_destroy (
      EDCDerivedFromDataTokenAndCounter);
   mc_ECCDerivedFromDataToken_destroy (ECCDerivedFromDataToken);
   mc_ESCDerivedFromDataToken_destroy (ESCDerivedFromDataToken);
   mc_EDCDerivedFromDataToken_destroy (EDCDerivedFromDataToken);
   mc_ECOCToken_destroy (ECOCToken);
   mc_ECCToken_destroy (ECCToken);
   mc_ESCToken_destroy (ESCToken);
   mc_EDCToken_destroy (EDCToken);
   mc_ServerTokenDerivationLevel1Token_destroy (
      ServerTokenDerivationLevel1Token);
   mc_ServerDataEncryptionLevel1Token_destroy (ServerDataEncryptionLevel1Token);
   mc_CollectionsLevel1Token_destroy (CollectionsLevel1Token);
   _mongocrypt_buffer_cleanup (&v);
   _mongocrypt_buffer_cleanup (&RootKey);
   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}

static void
_test_mc_tokens_error (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   mongocrypt_t *crypt;
   _mongocrypt_buffer_t RootKey;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   /* RootKey is incorrect length. */
   _mongocrypt_buffer_copy_from_hex (&RootKey, "AAAA");

   mc_CollectionsLevel1Token_t *CollectionsLevel1Token =
      mc_CollectionsLevel1Token_new (crypt->crypto, &RootKey, status);
   ASSERT_FAILS_STATUS (CollectionsLevel1Token != NULL,
                        status,
                        "invalid hmac_sha_256 key length");

   mc_CollectionsLevel1Token_destroy (CollectionsLevel1Token);
   _mongocrypt_buffer_cleanup (&RootKey);
   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}

static void
_test_mc_tokens_raw_buffer (_mongocrypt_tester_t *tester)
{
   mc_ServerDataEncryptionLevel1Token_t *token;
   _mongocrypt_buffer_t test_input;
   _mongocrypt_buffer_t expected;

   _mongocrypt_buffer_copy_from_hex (
      &test_input,
      "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");

   /* Make a token from a raw buffer */
   token = mc_ServerDataEncryptionLevel1Token_new_from_buffer (&test_input);

   /* Assert new_from_buffer did not steal ownership. */
   ASSERT (test_input.owned);
   ASSERT (test_input.len == MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_copy_from_hex (
      &expected,
      "6c6a349956c19f9c5e638e612011a71fbb71921edb540310c17cd0208b7f548b");

   ASSERT_CMPBUF (*mc_ServerDataEncryptionLevel1Token_get (token), expected);

   /* Assert new_from_buffer references original buffer instead of a copy. */
   test_input.data[0] = '0';
   expected.data[0] = '0';
   ASSERT_CMPBUF (*mc_ServerDataEncryptionLevel1Token_get (token), expected);

   _mongocrypt_buffer_cleanup (&test_input);
   _mongocrypt_buffer_cleanup (&expected);
   mc_ServerDataEncryptionLevel1Token_destroy (token);
}

void
_mongocrypt_tester_install_mc_tokens (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_mc_tokens);
   INSTALL_TEST (_test_mc_tokens_error);
   INSTALL_TEST (_test_mc_tokens_raw_buffer);
}
