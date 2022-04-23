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

/* Test option preconditions of all context functions. */

#include <stdarg.h>

#include "test-mongocrypt.h"
#include "mongocrypt-binary-private.h"

/* An orphaned UTF-8 continuation byte (10xxxxxx) is malformed UTF-8. */
static char invalid_utf8[] = {(char) 0x80, (char) 0x00};

/* Convenience macros for setting options */
#define MASTERKEY_AWS_OK(region, region_len, cmk, cmk_len) \
   ASSERT_OK (mongocrypt_ctx_setopt_masterkey_aws (        \
                 ctx, region, region_len, cmk, cmk_len),   \
              ctx);
#define MASTERKEY_AWS_FAILS(region, region_len, cmk, cmk_len, msg) \
   ASSERT_FAILS (mongocrypt_ctx_setopt_masterkey_aws (             \
                    ctx, region, region_len, cmk, cmk_len),        \
                 ctx,                                              \
                 msg);

#define MASTERKEY_LOCAL_OK \
   ASSERT_OK (mongocrypt_ctx_setopt_masterkey_local (ctx), ctx);
#define MASTERKEY_LOCAL_FAILS(msg) \
   ASSERT_FAILS (mongocrypt_ctx_setopt_masterkey_local (ctx), ctx, msg);

#define KEY_ENCRYPTION_KEY_OK(bin) \
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (ctx, bin), ctx);
#define KEY_ENCRYPTION_KEY_FAILS(bin, msg) \
   ASSERT_FAILS (mongocrypt_ctx_setopt_key_encryption_key (ctx, bin), ctx, msg);

#define KEY_ID_OK(key_id) \
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
#define KEY_ID_FAILS(key_id, msg) \
   ASSERT_FAILS (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx, msg);

#define KEY_ALT_NAME_OK(key_alt_name) \
   ASSERT_OK (mongocrypt_ctx_setopt_key_alt_name (ctx, key_alt_name), ctx);
#define KEY_ALT_NAME_FAILS(key_alt_name, msg) \
   ASSERT_FAILS (                             \
      mongocrypt_ctx_setopt_key_alt_name (ctx, key_alt_name), ctx, msg);

#define KEY_MATERIAL_OK(key_material) \
   ASSERT_OK (mongocrypt_ctx_setopt_key_material (ctx, key_material), ctx);
#define KEY_MATERIAL_FAILS(key_material, msg) \
   ASSERT_FAILS (                             \
      mongocrypt_ctx_setopt_key_material (ctx, key_material), ctx, msg);

#define ALGORITHM_OK(algo, algo_len) \
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, algo, algo_len), ctx);
#define ALGORITHM_FAILS(algo, algo_len, msg) \
   ASSERT_FAILS (                            \
      mongocrypt_ctx_setopt_algorithm (ctx, algo, algo_len), ctx, msg);

#define ENDPOINT_OK(endpoint, endpoint_len)                  \
   ASSERT_OK (mongocrypt_ctx_setopt_masterkey_aws_endpoint ( \
                 ctx, endpoint, endpoint_len),               \
              ctx);
#define ENDPOINT_FAILS(endpoint, endpoint_len, msg)             \
   ASSERT_FAILS (mongocrypt_ctx_setopt_masterkey_aws_endpoint ( \
                    ctx, endpoint, endpoint_len),               \
                 ctx,                                           \
                 msg);

#define DATAKEY_INIT_OK ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
#define DATAKEY_INIT_FAILS(msg) \
   ASSERT_FAILS (mongocrypt_ctx_datakey_init (ctx), ctx, msg);

#define ENCRYPT_INIT_OK(db, db_len, cmd) \
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, db, db_len, cmd), ctx);
#define ENCRYPT_INIT_FAILS(db, db_len, cmd, msg) \
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (ctx, db, db_len, cmd), ctx, msg);

#define EX_ENCRYPT_INIT_OK(bin) \
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, bin), ctx);
#define EX_ENCRYPT_INIT_FAILS(bin, msg) \
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, bin), ctx, msg);

#define DECRYPT_INIT_OK(bin) \
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, bin), ctx);
#define DECRYPT_INIT_FAILS(bin, msg) \
   ASSERT_FAILS (mongocrypt_ctx_decrypt_init (ctx, bin), ctx, msg);

#define EX_DECRYPT_INIT_OK(bin) \
   ASSERT_OK (mongocrypt_ctx_explicit_decrypt_init (ctx, bin), ctx);
#define EX_DECRYPT_INIT_FAILS(bin, msg) \
   ASSERT_FAILS (mongocrypt_ctx_explicit_decrypt_init (ctx, bin), ctx, msg);

#define REFRESH                  \
   mongocrypt_ctx_destroy (ctx); \
   ctx = mongocrypt_ctx_new (crypt);

#define DET "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
#define RAND "AEAD_AES_256_CBC_HMAC_SHA_512-Random"

/* Test valid and invalid options */
static void
_test_setopt_masterkey_aws (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   REFRESH;
   MASTERKEY_AWS_FAILS (NULL, 0, "cmk", 3, "invalid region");
   REFRESH;
   MASTERKEY_AWS_FAILS ("region", 6, NULL, 0, "invalid cmk");
   REFRESH;
   MASTERKEY_AWS_FAILS ("region", 0, "cmk", 0, "invalid region");
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   REFRESH;
   MASTERKEY_AWS_FAILS ("region", -2, "cmk", -1, "invalid region");
   REFRESH;
   MASTERKEY_AWS_FAILS ("region", -1, "cmk", -2, "invalid cmk");

   /* Test invalid UTF 8 */
   REFRESH;
   MASTERKEY_AWS_FAILS (invalid_utf8, -1, "cmk", -2, "invalid region");

   /* Test double setting. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   MASTERKEY_AWS_FAILS ("region", -1, "cmk", -1, "master key already set");

   /* Cannot be set with local masterkey. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   MASTERKEY_LOCAL_FAILS ("master key already set");

   /* Cannot be set after entering error state. */
   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   MASTERKEY_AWS_FAILS ("region", -1, "cmk", -1, "test");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_masterkey_local (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Test double setting. */
   REFRESH;
   MASTERKEY_LOCAL_OK;
   MASTERKEY_LOCAL_FAILS ("master key already set");

   /* Cannot be set with aws masterkey. */
   REFRESH;
   MASTERKEY_LOCAL_OK;
   MASTERKEY_AWS_FAILS ("region", -1, "cmk", -1, "master key already set");

   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   MASTERKEY_LOCAL_FAILS ("test");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_setopt_key_encryption_key_azure (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Test double setting. */
   REFRESH;
   KEY_ENCRYPTION_KEY_OK (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                     "'keyVaultEndpoint': 'example.com' }"));
   KEY_ENCRYPTION_KEY_FAILS (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                        "'keyVaultEndpoint': 'example.com' }"),
                             "key encryption key already set");

   /* Cannot be set when another masterkey is set. */
   REFRESH;
   MASTERKEY_LOCAL_OK;
   KEY_ENCRYPTION_KEY_FAILS (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                        "'keyVaultEndpoint': 'example.com' }"),
                             "key encryption key already set");

   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   KEY_ENCRYPTION_KEY_FAILS (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                        "'keyVaultEndpoint': 'example.com' }"),
                             "test");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_setopt_key_encryption_key_gcp (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Test double setting. */
   REFRESH;
   KEY_ENCRYPTION_KEY_OK (
      TEST_BSON ("{'provider': 'gcp', 'projectId': 'proj', 'location': "
                 "'google.com', 'keyRing': 'ring', 'keyName': 'key' }"));
   KEY_ENCRYPTION_KEY_FAILS (
      TEST_BSON ("{'provider': 'gcp', 'projectId': 'proj', 'location': "
                 "'google.com', 'keyRing': 'ring', 'keyName': 'key' }"),
      "key encryption key already set");

   /* Cannot be set when another masterkey is set. */
   REFRESH;
   MASTERKEY_LOCAL_OK;
   KEY_ENCRYPTION_KEY_FAILS (
      TEST_BSON ("{'provider': 'gcp', 'projectId': 'proj', 'location': "
                 "'google.com', 'keyRing': 'ring', 'keyName': 'key' }"),
      "key encryption key already set");

   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   KEY_ENCRYPTION_KEY_FAILS (
      TEST_BSON ("{'provider': 'gcp', 'projectId': 'proj', 'location': "
                 "'google.com', 'keyRing': 'ring', 'keyName': 'key' }"),
      "test");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_key_id (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Test double setting. */
   REFRESH;
   KEY_ID_OK (TEST_BIN (16));
   KEY_ID_FAILS (TEST_BIN (16), "option already set");

   /* Test NULL/empty input */
   REFRESH;
   KEY_ID_FAILS (NULL, "option must be non-NULL");

   REFRESH;
   KEY_ID_FAILS (TEST_BIN (0), "option must be non-NULL");

   /* Test wrong length */
   REFRESH;
   KEY_ID_FAILS (TEST_BIN (5), "expected 16 byte UUID");

   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   KEY_ID_FAILS (TEST_BIN (16), "test");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_key_alt_name (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Test double setting - actually succeeds since multiple key alt names
    * allowed for data keys. */
   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'def'}"));

   /* Test NULL/empty input */
   REFRESH;
   KEY_ALT_NAME_FAILS (NULL, "option must be non-NULL");

   REFRESH;
   KEY_ALT_NAME_FAILS (TEST_BIN (0), "option must be non-NULL");

   /* Test wrong type */
   REFRESH;
   REFRESH;
   KEY_ALT_NAME_FAILS (TEST_BSON ("{'keyAltName': 1}"),
                       "keyAltName expected to be UTF8");

   /* Test missing key */
   REFRESH;
   KEY_ALT_NAME_FAILS (TEST_BSON ("{'keyAltNames': 'abc'}"),
                       "keyAltName must have field 'keyAltName'");

   /* Test extra key */
   REFRESH;
   KEY_ALT_NAME_FAILS (TEST_BSON ("{'keyAltName': 'abc', 'extra': 1}"),
                       "unrecognized field");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_key_material (_mongocrypt_tester_t *tester)
{
   /* "0123456789abcef", repeated 6 times. */
   const char *const material =
      "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1"
      "Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm";
   const char *const pattern =
      "{'keyMaterial': {'$binary': {'base64': '%s', 'subType': '00'}}%s}";
   mongocrypt_binary_t *const valid = TEST_BSON (pattern, material, "");

   mongocrypt_t *crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *ctx = NULL;

   /* Test double setting. */
   REFRESH;
   KEY_MATERIAL_OK (valid);
   KEY_MATERIAL_FAILS (valid, "keyMaterial already set");

   /* Test NULL input. */
   REFRESH;
   KEY_MATERIAL_FAILS (NULL, "option must be non-NULL");

   /* Test empty input. */
   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BIN (0), "option must be non-NULL");

   /* Test empty key material. */
   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BSON (pattern, "", ""),
                       "keyMaterial should have length 96, but has length 0");

   /* Test too short key material. */
   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BSON (pattern,
                                  "dG9vc2hvcnQ=", /* "tooshort" */
                                  ""),
                       "keyMaterial should have length 96, but has length 8");

   /* Test too long key material. */
   REFRESH;
   KEY_MATERIAL_FAILS (
      TEST_BSON (
         pattern,
         /* "0123456789abcdef", repeated 6 times, followed by "toolong". */
         "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyM"
         "zQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmdG9vbG9uZw"
         "==",
         ""),
      "keyMaterial should have length 96, but has length 103");

   /* Test invalid keyMaterial options. */
   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BSON ("{}"), "invalid bson");

   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BSON ("{'a': 1}"),
                       "keyMaterial must have field 'keyMaterial'");

   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BSON ("{'keyMaterial': 1}"),
                       "keyMaterial must be binary data");

   /* Test extra key. */
   REFRESH;
   KEY_MATERIAL_FAILS (TEST_BSON (pattern, material, ", 'a': 1"),
                       "unrecognized field, only keyMaterial expected");

   /* Test error propagation. */
   REFRESH;
   ASSERT (!_mongocrypt_ctx_fail_w_msg (ctx, "test"));
   KEY_MATERIAL_FAILS (valid, "test");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_algorithm (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   REFRESH;
   ALGORITHM_FAILS (DET, -2, "invalid algorithm length");

   REFRESH;
   ALGORITHM_OK (DET, 43);

   REFRESH;
   ALGORITHM_FAILS (DET, 42, "unsupported algorithm");

   /* Check for prior bug. It's "Random", not "Randomized" */
   REFRESH;
   ALGORITHM_FAILS (RAND "ized", -1, "unsupported algorithm");

   /* Test double setting. */
   REFRESH;
   ALGORITHM_OK (DET, -1);
   ALGORITHM_FAILS (DET, -1, "already set algorithm");

   /* Test NULL input */
   REFRESH;
   ALGORITHM_FAILS (NULL, 0, "passed null algorithm");

   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   ALGORITHM_FAILS (RAND, -1, "test")

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


/* Test required and prohibited options on a datakey context. */
static void
_test_setopt_for_datakey (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_binary_t *uuid;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   uuid = TEST_BIN (16);

   /* Test required and prohibited options. */
   REFRESH;
   DATAKEY_INIT_FAILS ("master key required");

   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   DATAKEY_INIT_OK;

   REFRESH;
   KEY_ENCRYPTION_KEY_OK (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                     "'keyVaultEndpoint': 'example.com' }"));
   DATAKEY_INIT_OK;

   /* Test optional key alt names. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   DATAKEY_INIT_OK;

   /* Multiple key alt names are okay. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'def'}"));
   DATAKEY_INIT_OK;

   /* But duplicates are not. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   KEY_ALT_NAME_FAILS (TEST_BSON ("{'keyAltName': 'abc'}"),
                       "duplicate keyAltNames found");

   /* Key Material is okay. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   KEY_MATERIAL_OK (
      TEST_BSON ("{'keyMaterial': {'$binary': {'base64': "
                 "'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJj"
                 "ZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5Y"
                 "WJjZGVm', 'subType': '00'}}}"));
   DATAKEY_INIT_OK;

   /* Test each prohibited option. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   KEY_ID_OK (uuid);
   DATAKEY_INIT_FAILS ("key id and alt name prohibited");

   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   ALGORITHM_OK ("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
   DATAKEY_INIT_FAILS ("algorithm prohibited");

   /* Test setting options after init. */
   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   DATAKEY_INIT_OK;
   MASTERKEY_AWS_FAILS (
      "region", -1, "cmk", -1, "cannot set options after init");

   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   ENDPOINT_OK ("example.com:80", -1);
   DATAKEY_INIT_OK;

   REFRESH;
   MASTERKEY_LOCAL_OK;
   ENDPOINT_FAILS ("example.com:80", -1, "endpoint prohibited");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_for_encrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_binary_t *uuid, *cmd;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   cmd = TEST_FILE ("./test/example/cmd.json");
   uuid = TEST_BIN (16);

   /* Test required and prohibited options. */
   REFRESH;
   ENCRYPT_INIT_OK ("a", -1, cmd);

   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "master key prohibited");

   REFRESH;
   MASTERKEY_LOCAL_OK;
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "master key prohibited");

   REFRESH;
   KEY_ENCRYPTION_KEY_OK (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                     "'keyVaultEndpoint': 'example.com' }"));
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "master key prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "key id and alt name prohibited");

   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "key id and alt name prohibited");

   REFRESH;
   KEY_MATERIAL_OK (
      TEST_BSON ("{'keyMaterial': {'$binary': {'base64': "
                 "'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJj"
                 "ZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5Y"
                 "WJjZGVm', 'subType': '00'}}}"));
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "key material prohibited");

   REFRESH;
   ALGORITHM_OK (DET, -1);
   ENCRYPT_INIT_FAILS ("a", -1, cmd, "algorithm prohibited");

   REFRESH;
   ENCRYPT_INIT_FAILS ("a", -1, NULL, "invalid command");

   /* Test setting options after init. */
   REFRESH;
   ENCRYPT_INIT_OK ("a", -1, cmd);
   MASTERKEY_LOCAL_FAILS ("cannot set options after init");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_for_explicit_encrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_binary_t *bson, *uuid;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   uuid = TEST_BIN (16);
   bson = TEST_BSON ("{'v': 'hello'}");

   /* Test required and prohibited options. */
   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (RAND, -1);
   EX_ENCRYPT_INIT_OK (bson);

   /* Just keyAltName is ok */
   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   ALGORITHM_OK (RAND, -1);
   EX_ENCRYPT_INIT_OK (bson);

   /* Two keyAltNames is invalid */
   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'def'}"));
   ALGORITHM_OK (RAND, -1);
   EX_ENCRYPT_INIT_FAILS (bson, "must not specify multiple key alt names");

   /* Both keyAltName and keyId is invalid */
   REFRESH;
   KEY_ID_OK (uuid);
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   ALGORITHM_OK (RAND, -1);
   EX_ENCRYPT_INIT_FAILS (bson, "cannot have both key id and key alt name");

   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (RAND, -1);
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   EX_ENCRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   ALGORITHM_OK (RAND, -1);
   KEY_MATERIAL_OK (
      TEST_BSON ("{'keyMaterial': {'$binary': {'base64': "
                 "'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJj"
                 "ZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5Y"
                 "WJjZGVm', 'subType': '00'}}}"));
   EX_ENCRYPT_INIT_FAILS (bson, "key material prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (RAND, -1);
   MASTERKEY_LOCAL_OK;
   EX_ENCRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (RAND, -1);
   KEY_ENCRYPTION_KEY_OK (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                     "'keyVaultEndpoint': 'example.com' }"));
   EX_ENCRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   EX_ENCRYPT_INIT_FAILS (bson, "algorithm or index type required");

   REFRESH;
   ALGORITHM_OK (RAND, -1);
   EX_ENCRYPT_INIT_FAILS (bson, "key id or key alt name required")

   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (DET, -1);
   EX_ENCRYPT_INIT_OK (bson);

   /* Just key alt name is ok */
   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   ALGORITHM_OK (RAND, -1);
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   EX_ENCRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (DET, -1);
   EX_ENCRYPT_INIT_OK (bson);

   /* Test setting options after init. */
   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_OK (RAND, -1);
   EX_ENCRYPT_INIT_OK (bson);
   ALGORITHM_FAILS (RAND, -1, "cannot set options after init");

   /* Test that an option failure validated at the time of 'setopt' persists
    * upon init. */
   REFRESH;
   KEY_ID_OK (uuid);
   ALGORITHM_FAILS ("bad-algo", -1, "unsupported algorithm");
   EX_ENCRYPT_INIT_FAILS (bson, "unsupported algorithm");

   /* It is an error to set the FLE 1 keyAltName option with any of the FLE 2
    * options (index_type, index_key_id, or contention_factor). */
   {
      REFRESH
      KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
      ASSERT_OK (
         mongocrypt_ctx_setopt_index_type (ctx, MONGOCRYPT_INDEX_TYPE_NONE),
         ctx);
      EX_ENCRYPT_INIT_FAILS (bson,
                             "cannot set both key alt name and index type");

      REFRESH
      KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
      ASSERT_OK (mongocrypt_ctx_setopt_index_key_id (ctx, uuid), ctx);
      EX_ENCRYPT_INIT_FAILS (bson,
                             "cannot set both key alt name and index key id");

      REFRESH
      KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
      ASSERT_OK (mongocrypt_ctx_setopt_contention_factor (ctx, 123), ctx);
      EX_ENCRYPT_INIT_FAILS (
         bson, "cannot set both key alt name and contention factor");

      REFRESH
      KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
      ASSERT_OK (
         mongocrypt_ctx_setopt_query_type (ctx, MONGOCRYPT_QUERY_TYPE_EQUALITY),
         ctx);
      EX_ENCRYPT_INIT_FAILS (bson,
                             "cannot set both key alt name and query type");
   }

   /* It is an error to set the FLE 1 algorithm option with any of the FLE 2
    * options (index_type, index_key_id, contention_factor, or query_type). */
   {
      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      ALGORITHM_OK (RAND, -1);
      ASSERT_OK (
         mongocrypt_ctx_setopt_index_type (ctx, MONGOCRYPT_INDEX_TYPE_NONE),
         ctx);
      EX_ENCRYPT_INIT_FAILS (bson, "cannot set both algorithm and index type");

      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      ALGORITHM_OK (RAND, -1);
      ASSERT_OK (mongocrypt_ctx_setopt_index_key_id (ctx, uuid), ctx);
      EX_ENCRYPT_INIT_FAILS (bson,
                             "cannot set both algorithm and index key id");

      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      ALGORITHM_OK (RAND, -1);
      ASSERT_OK (mongocrypt_ctx_setopt_contention_factor (ctx, 123), ctx);
      EX_ENCRYPT_INIT_FAILS (bson,
                             "cannot set both algorithm and contention factor");
      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      ALGORITHM_OK (RAND, -1);
      ASSERT_OK (
         mongocrypt_ctx_setopt_query_type (ctx, MONGOCRYPT_QUERY_TYPE_EQUALITY),
         ctx);
      EX_ENCRYPT_INIT_FAILS (bson, "cannot set both algorithm and query type");
   }

   /* Require either index_type or algorithm */
   {
      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      EX_ENCRYPT_INIT_FAILS (bson, "algorithm or index type required");
   }

   /* It is an error to set contention_factor with index_type ==
    * MONGOCRYPT_INDEX_TYPE_NONE */
   {
      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      ASSERT_OK (mongocrypt_ctx_setopt_contention_factor (ctx, 0), ctx);
      ASSERT_OK (
         mongocrypt_ctx_setopt_index_type (ctx, MONGOCRYPT_INDEX_TYPE_NONE),
         ctx);
      EX_ENCRYPT_INIT_FAILS (bson,
                             "cannot set contention factor with no index type");
   }

   /* It is an error to set query_type with index_type ==
    * MONGOCRYPT_INDEX_TYPE_NONE */
   {
      REFRESH
      /* Set key ID to get past the 'either key id or key alt name required'
       * error */
      KEY_ID_OK (uuid);
      ASSERT_OK (
         mongocrypt_ctx_setopt_query_type (ctx, MONGOCRYPT_QUERY_TYPE_EQUALITY),
         ctx);
      ASSERT_OK (
         mongocrypt_ctx_setopt_index_type (ctx, MONGOCRYPT_INDEX_TYPE_NONE),
         ctx);
      EX_ENCRYPT_INIT_FAILS (bson, "cannot set query type with no index type");
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_for_decrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_binary_t *bson, *uuid;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   uuid = TEST_BIN (16);
   bson = TEST_BSON ("{'a': 1}");

   /* Test required and prohibited options. */
   REFRESH;
   DECRYPT_INIT_OK (bson);

   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   DECRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   MASTERKEY_LOCAL_OK;
   DECRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ENCRYPTION_KEY_OK (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                     "'keyVaultEndpoint': 'example.com' }"));
   DECRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   DECRYPT_INIT_FAILS (bson, "key id and alt name prohibited");

   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   DECRYPT_INIT_FAILS (bson, "key id and alt name prohibited");

   REFRESH;
   KEY_MATERIAL_OK (
      TEST_BSON ("{'keyMaterial': {'$binary': {'base64': "
                 "'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJj"
                 "ZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5Y"
                 "WJjZGVm', 'subType': '00'}}}"));
   DECRYPT_INIT_FAILS (bson, "key material prohibited");

   REFRESH;
   ALGORITHM_OK (DET, -1);
   DECRYPT_INIT_FAILS (bson, "algorithm prohibited");

   /* Test setting options after init. */
   REFRESH;
   DECRYPT_INIT_OK (bson);
   MASTERKEY_LOCAL_FAILS ("cannot set options after init");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_for_explicit_decrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_binary_t *bson, *uuid;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   uuid = TEST_BIN (16);
   bson = TEST_FILE ("./test/data/explicit-decryption-input.json");

   /* Test required and prohibited options. */
   REFRESH;
   EX_DECRYPT_INIT_OK (bson);

   REFRESH;
   MASTERKEY_AWS_OK ("region", -1, "cmk", -1);
   EX_DECRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   MASTERKEY_LOCAL_OK;
   EX_DECRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ENCRYPTION_KEY_OK (TEST_BSON ("{'provider': 'azure', 'keyName': '', "
                                     "'keyVaultEndpoint': 'example.com' }"));
   EX_DECRYPT_INIT_FAILS (bson, "master key prohibited");

   REFRESH;
   KEY_ID_OK (uuid);
   EX_DECRYPT_INIT_FAILS (bson, "key id and alt name prohibited");

   REFRESH;
   KEY_ALT_NAME_OK (TEST_BSON ("{'keyAltName': 'abc'}"));
   DECRYPT_INIT_FAILS (bson, "key id and alt name prohibited");

   REFRESH;
   KEY_MATERIAL_OK (
      TEST_BSON ("{'keyMaterial': {'$binary': {'base64': "
                 "'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJj"
                 "ZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5Y"
                 "WJjZGVm', 'subType': '00'}}}"));
   DECRYPT_INIT_FAILS (bson, "key material prohibited");

   REFRESH;
   ALGORITHM_OK (DET, -1);
   EX_DECRYPT_INIT_FAILS (bson, "algorithm prohibited");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_setopt_failure_uninitialized (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_status_t *status;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   status = mongocrypt_status_new ();

   REFRESH;
   KEY_ALT_NAME_FAILS (TEST_BSON ("{'fake': 'abc'}"),
                       "keyAltName must have field 'keyAltName'");
   /* Though mongocrypt_ctx_t is uninitialized, we should still get failure
    * status. */
   ASSERT_FAILS_STATUS (mongocrypt_ctx_status (ctx, status),
                        status,
                        "keyAltName must have field 'keyAltName'");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}


static void
_test_setopt_endpoint (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx = NULL;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   REFRESH;
   ENDPOINT_FAILS ("example.com", -2, "Invalid endpoint");

   REFRESH;
   ENDPOINT_OK ("example.com", -1);
   BSON_ASSERT (0 == strcmp (ctx->opts.kek.provider.aws.endpoint->host_and_port,
                             "example.com"));

   /* Including a port is ok. */
   REFRESH;
   ENDPOINT_OK ("example.com:80", -1);
   BSON_ASSERT (0 == strcmp (ctx->opts.kek.provider.aws.endpoint->host_and_port,
                             "example.com:80"));

   /* Test double setting. */
   REFRESH;
   ENDPOINT_OK ("example.com", -1);
   ENDPOINT_FAILS ("example.com", -1, "already set masterkey endpoint");

   /* Test NULL input */
   REFRESH;
   ENDPOINT_FAILS (NULL, 0, "Invalid endpoint");

   REFRESH;
   _mongocrypt_ctx_fail_w_msg (ctx, "test");
   ENDPOINT_FAILS (RAND, -1, "test")

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_options (_mongocrypt_tester_t *tester)
{
   /* Test individual options */
   _test_setopt_masterkey_aws (tester);
   _test_setopt_masterkey_local (tester);
   _test_setopt_key_id (tester);
   _test_setopt_algorithm (tester);
   _test_setopt_key_alt_name (tester);
   _test_setopt_key_material (tester);
   _test_setopt_endpoint (tester);
   _test_setopt_key_encryption_key_azure (tester);
   _test_setopt_key_encryption_key_gcp (tester);

   /* Test options on different contexts */
   _test_setopt_for_datakey (tester);
   _test_setopt_for_encrypt (tester);
   _test_setopt_for_explicit_encrypt (tester);
   _test_setopt_for_decrypt (tester);
   _test_setopt_for_explicit_decrypt (tester);

   /* Test that failure to set an option on an uninitialized context is returned
    * through mongocrypt_ctx_status */
   _test_setopt_failure_uninitialized (tester);
}


void
_mongocrypt_tester_install_ctx_setopt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_options);
}
