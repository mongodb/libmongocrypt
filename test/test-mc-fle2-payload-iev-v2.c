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
#include "mc-fle2-payload-iev-private-v2.h"

typedef struct {
   _mongocrypt_buffer_t payload;
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t S_Key;
   _mongocrypt_buffer_t K_KeyId;
   _mongocrypt_buffer_t K_Key;
   uint8_t bson_value_type;
   _mongocrypt_buffer_t bson_value;
} _mc_fle2_ieevv2_test;

static void
_mc_fle2_ieevv2_test_destroy (_mc_fle2_ieevv2_test *test)
{
   _mongocrypt_buffer_cleanup (&test->payload);
   _mongocrypt_buffer_cleanup (&test->S_KeyId);
   _mongocrypt_buffer_cleanup (&test->S_Key);
   _mongocrypt_buffer_cleanup (&test->K_KeyId);
   _mongocrypt_buffer_cleanup (&test->K_Key);
   _mongocrypt_buffer_cleanup (&test->bson_value);
}

static bool
_mc_fle2_ieevv2_test_parse (_mc_fle2_ieevv2_test *test, bson_iter_t *iter)
{
   while (bson_iter_next (iter)) {
      const char *field = bson_iter_key (iter);
      ASSERT (field);

#define HEXBUF_FIELD(Name)                                         \
   if (!strcmp (field, #Name)) {                                   \
      ASSERT_OR_PRINT_MSG (!test->Name.data,                       \
                           "Duplicate field '" #Name "' in test"); \
      ASSERT (BSON_ITER_HOLDS_UTF8 (iter));                        \
      const char *value = bson_iter_utf8 (iter, NULL);             \
      _mongocrypt_buffer_copy_from_hex (&test->Name, value);       \
      ASSERT (strlen (value) == (test->Name.len * 2));             \
   } else
      HEXBUF_FIELD (payload)
      HEXBUF_FIELD (S_KeyId)
      HEXBUF_FIELD (S_Key)
      HEXBUF_FIELD (K_KeyId)
      HEXBUF_FIELD (K_Key)
      HEXBUF_FIELD (bson_value)
#undef HEXBUF_FIELD
      /* else */ if (!strcmp (field, "bson_value_type")) {
         ASSERT_OR_PRINT_MSG (!test->bson_value_type,
                              "Duplicate field 'bson_value_type'");
         ASSERT (BSON_ITER_HOLDS_INT32 (iter) || BSON_ITER_HOLDS_INT64 (iter));
         int64_t value = bson_iter_as_int64 (iter);
         ASSERT_OR_PRINT_MSG ((value > 0) && (value < 128),
                              "Field 'bson_value_type' must be 1..127");
         test->bson_value_type = (uint8_t) value;
      } else {
         TEST_ERROR ("Unknown field '%s'", field);
      }
   }

#define CHECK_HAS(Name) \
   ASSERT_OR_PRINT_MSG (test->Name.data, "Missing field '" #Name "'")
   CHECK_HAS (payload);
   CHECK_HAS (S_KeyId);
   CHECK_HAS (S_Key);
   CHECK_HAS (K_KeyId);
   CHECK_HAS (K_Key);
   CHECK_HAS (bson_value);
#undef CHECK_HAS
   ASSERT_OR_PRINT_MSG (test->bson_value_type,
                        "Missing field 'bson_value_type'");

   return true;
}

static void
_mc_fle2_ieevv2_test_run (_mongocrypt_tester_t *tester,
                          _mc_fle2_ieevv2_test *test)
{
   mongocrypt_status_t *status = mongocrypt_status_new ();
   mongocrypt_t *crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   mc_FLE2IndexedEqualityEncryptedValueV2_t *iev =
      mc_FLE2IndexedEqualityEncryptedValueV2_new ();

   // Parse payload.
   ASSERT_OK_STATUS (mc_FLE2IndexedEqualityEncryptedValueV2_parse (
                        iev, &test->payload, status),
                     status);

   // Validate S_KeyId as parsed.
   const _mongocrypt_buffer_t *S_KeyId =
      mc_FLE2IndexedEqualityEncryptedValueV2_get_S_KeyId (iev, status);
   ASSERT_OK_STATUS (S_KeyId, status);
   ASSERT_CMPBUF (*S_KeyId, test->S_KeyId);

   // Validate bson_value_type as parsed.
   bson_type_t bson_value_type =
      mc_FLE2IndexedEqualityEncryptedValueV2_get_bson_value_type (iev, status);
   ASSERT_OK_STATUS (bson_value_type, status);
   ASSERT_CMPINT (bson_value_type, ==, test->bson_value_type);

   // Decrypt ServerEncryptedValue.
   ASSERT_OK_STATUS (mc_FLE2IndexedEqualityEncryptedValueV2_add_S_Key (
                        crypt->crypto, iev, &test->S_Key, status),
                     status);

   // Validate K_KeyId as decrypted.
   const _mongocrypt_buffer_t *K_KeyId =
      mc_FLE2IndexedEqualityEncryptedValueV2_get_K_KeyId (iev, status);
   ASSERT_OK_STATUS (K_KeyId, status);
   ASSERT_CMPBUF (*K_KeyId, test->K_KeyId);

   // Decrypt ClientEncryptedValue.
   ASSERT_OK_STATUS (mc_FLE2IndexedEqualityEncryptedValueV2_add_K_Key (
                        crypt->crypto, iev, &test->K_Key, status),
                     status);

   // Validate decrypted value.
   const _mongocrypt_buffer_t *bson_value =
      mc_FLE2IndexedEqualityEncryptedValueV2_get_ClientValue (iev, status);
   ASSERT_OK_STATUS (bson_value, status);
   ASSERT_CMPBUF (*bson_value, test->bson_value);

   // All done!
   mc_FLE2IndexedEqualityEncryptedValueV2_destroy (iev);
   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}

static void
test_fle2_ieevv2_test (_mongocrypt_tester_t *tester, const char *path)
{
   printf ("Loading test from %s...\n", path);

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

   _mc_fle2_ieevv2_test test = {{0}};
   bson_iter_t iter;
   ASSERT (bson_iter_init (&iter, &test_bson));
   ASSERT (_mc_fle2_ieevv2_test_parse (&test, &iter));
   _mc_fle2_ieevv2_test_run (tester, &test);
   _mc_fle2_ieevv2_test_destroy (&test);
}

static void
test_fle2_ieevv2 (_mongocrypt_tester_t *tester)
{
   // Producted by Server test: (FLECrudTest, insertOneV2)
   test_fle2_ieevv2_test (tester,
                          "test/data/ieev-v2/FLECrudTest-insertOneV2.json");
}

void
_mongocrypt_tester_install_fle2_ieevv2_payloads (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_fle2_ieevv2);
}
