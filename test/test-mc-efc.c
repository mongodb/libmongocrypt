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

#include "mc-efc-private.h"

static void
_load_test_file (_mongocrypt_tester_t *tester, const char *path, bson_t *out)
{
   mongocrypt_binary_t *bin = TEST_FILE (path);
   ASSERT (bson_init_static (
      out, mongocrypt_binary_data (bin), mongocrypt_binary_len (bin)));
}

static void
_test_efc (_mongocrypt_tester_t *tester)
{
   bson_t efc_bson;
   mc_EncryptedFieldConfig_t efc;
   mc_EncryptedField_t *ptr;
   mongocrypt_status_t *status = mongocrypt_status_new ();
   _mongocrypt_buffer_t expect_keyId1;
   _mongocrypt_buffer_t expect_keyId2;

   _mongocrypt_buffer_copy_from_hex (&expect_keyId1,
                                     "12345678123498761234123456789012");
   _mongocrypt_buffer_copy_from_hex (&expect_keyId2,
                                     "abcdefab123498761234123456789012");

   {
      _load_test_file (tester, "./test/data/efc/efc-oneField.json", &efc_bson);
      ASSERT_OK_STATUS (mc_EncryptedFieldConfig_parse (&efc, &efc_bson, status),
                        status);
      ptr = efc.fields;
      ASSERT (ptr);
      ASSERT_STREQUAL (ptr->path, "firstName");
      ASSERT_CMPBUF (expect_keyId1, ptr->keyId);
      ASSERT (ptr->next == NULL);
      mc_EncryptedFieldConfig_cleanup (&efc);
   }

   {
      _load_test_file (
         tester, "./test/data/efc/efc-extraField.json", &efc_bson);
      ASSERT_OK_STATUS (mc_EncryptedFieldConfig_parse (&efc, &efc_bson, status),
                        status);
      ptr = efc.fields;
      ASSERT (ptr);
      ASSERT_STREQUAL (ptr->path, "firstName");
      ASSERT_CMPBUF (expect_keyId1, ptr->keyId);
      ASSERT (ptr->next == NULL);
      mc_EncryptedFieldConfig_cleanup (&efc);
   }

   {
      _load_test_file (tester, "./test/data/efc/efc-twoFields.json", &efc_bson);
      ASSERT_OK_STATUS (mc_EncryptedFieldConfig_parse (&efc, &efc_bson, status),
                        status);
      ptr = efc.fields;
      ASSERT (ptr);
      ASSERT_STREQUAL (ptr->path, "lastName");
      ASSERT_CMPBUF (expect_keyId2, ptr->keyId);
      ASSERT (ptr->next != NULL);
      ptr = ptr->next;
      ASSERT_STREQUAL (ptr->path, "firstName");
      ASSERT_CMPBUF (expect_keyId1, ptr->keyId);
      ASSERT (ptr->next == NULL);
      mc_EncryptedFieldConfig_cleanup (&efc);
   }

   {
      _load_test_file (
         tester, "./test/data/efc/efc-missingKeyId.json", &efc_bson);
      ASSERT_FAILS_STATUS (
         mc_EncryptedFieldConfig_parse (&efc, &efc_bson, status),
         status,
         "unable to find 'keyId' in 'field' document");
      mc_EncryptedFieldConfig_cleanup (&efc);
   }

   _mongocrypt_buffer_cleanup (&expect_keyId2);
   _mongocrypt_buffer_cleanup (&expect_keyId1);
   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_efc (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_efc);
}
