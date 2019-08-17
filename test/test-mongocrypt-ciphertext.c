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

#include "mongocrypt-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-marking-private.h"

#include "test-mongocrypt.h"


/* From BSON Binary subtype 6 specification:
struct fle_blob {
 uint8  fle_blob_subtype = (1 or 2);
 uint8  key_uuid[16];
 uint8  original_bson_type;
 uint8  ciphertext[ciphertext_length];
}
*/
static void
_test_ciphertext_serialization (_mongocrypt_tester_t *tester)
{
   _mongocrypt_ciphertext_t original, returned;
   _mongocrypt_buffer_t serialized;
   char *expected = "\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
                    "\x0D\x0E\x0F\x02\x00\x01";
   mongocrypt_status_t *status;

   _mongocrypt_ciphertext_init (&original);
   _mongocrypt_ciphertext_init (&returned);
   _mongocrypt_buffer_init (&serialized);
   status = mongocrypt_status_new ();

   original.blob_subtype = 1;
   original.original_bson_type = 2;
   _mongocrypt_tester_fill_buffer (&original.data, 2);
   _mongocrypt_tester_fill_buffer (&original.key_id, 16);

   BSON_ASSERT (_mongocrypt_serialize_ciphertext (&original, &serialized));
   BSON_ASSERT (0 == memcmp (expected, serialized.data, serialized.len));

   /* Now parse it back, should get the same ciphertext. */
   BSON_ASSERT (
      _mongocrypt_ciphertext_parse_unowned (&serialized, &returned, status));
   BSON_ASSERT (original.blob_subtype == returned.blob_subtype);
   BSON_ASSERT (original.original_bson_type == returned.original_bson_type);
   BSON_ASSERT (0 ==
                _mongocrypt_buffer_cmp (&original.key_id, &returned.key_id));
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp (&original.data, &returned.data));

   _mongocrypt_ciphertext_cleanup (&original);
   _mongocrypt_ciphertext_cleanup (&returned);
   _mongocrypt_buffer_cleanup (&serialized);
   mongocrypt_status_destroy (status);
}


static void
_test_malformed_ciphertext (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t serialized;
   _mongocrypt_ciphertext_t returned;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   /* the minimum size for a ciphertext is 19 bytes. */
   _mongocrypt_tester_fill_buffer (&serialized, 18);

   BSON_ASSERT (
      !_mongocrypt_ciphertext_parse_unowned (&serialized, &returned, status));
   BSON_ASSERT (0 ==
                strcmp (status->message, "malformed ciphertext, too small"));
   _mongocrypt_buffer_cleanup (&serialized);

   _mongocrypt_tester_fill_buffer (&serialized, 19);
   /* give a valid blob_subtype. */
   serialized.data[0] = 1;
   BSON_ASSERT (
      _mongocrypt_ciphertext_parse_unowned (&serialized, &returned, status));

   /* now an invalid blob_subtype. */
   serialized.data[0] = 16;
   BSON_ASSERT (
      !_mongocrypt_ciphertext_parse_unowned (&serialized, &returned, status));
   BSON_ASSERT (
      0 == strcmp (status->message,
                   "malformed ciphertext, expected blob subtype of 1 or 2"));

   _mongocrypt_ciphertext_cleanup (&returned);
   _mongocrypt_buffer_cleanup (&serialized);
   mongocrypt_status_destroy (status);
}


void
_test_ciphertext_algorithm (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_status_t status;
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_buffer_t zeros;
   _mongocrypt_ciphertext_t type1_valueA, type1_valueA_again, type2_valueA,
      type1_valueB;
   _mongocrypt_marking_t marking = {0};
   bson_iter_t a_iter, b_iter;
   bson_t *bson;
   bool res;

   _mongocrypt_ciphertext_init (&type1_valueA);
   _mongocrypt_ciphertext_init (&type1_valueA_again);
   _mongocrypt_ciphertext_init (&type2_valueA);
   _mongocrypt_ciphertext_init (&type1_valueB);

   _mongocrypt_buffer_init (&zeros);
   _mongocrypt_buffer_resize (&zeros, MONGOCRYPT_IV_LEN);
   memset (zeros.data, 0, MONGOCRYPT_IV_LEN);

   crypt = _mongocrypt_tester_mongocrypt ();
   /* use a mongocrypt_ctx_t to get a key broker */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (
                 ctx, "test", -1, TEST_FILE ("./test/example/cmd.json")),
              ctx);

   _mongocrypt_buffer_from_binary (&marking.key_id, TEST_BIN (16));
   marking.key_id.subtype = BSON_SUBTYPE_UUID;
   kb = &ctx->kb;
   _mongocrypt_key_broker_add_test_key (kb, &marking.key_id);

   bson = BCON_NEW ("v", "a", "v", "b");
   bson_iter_init (&a_iter, bson);
   bson_iter_next (&a_iter);
   bson_iter_init (&b_iter, bson);
   bson_iter_next (&b_iter);
   bson_iter_next (&b_iter);

   /* Marking type = 1, plaintext = a */
   marking.algorithm = 1;
   memcpy (&marking.v_iter, &a_iter, sizeof (bson_iter_t));
   res = _mongocrypt_marking_to_ciphertext (
      (void *) kb, &marking, &type1_valueA, &status);
   ASSERT_OR_PRINT (res, &status);

   /* Marking type = 1, plaintext = a */
   marking.algorithm = 1;
   memcpy (&marking.v_iter, &a_iter, sizeof (bson_iter_t));
   res = _mongocrypt_marking_to_ciphertext (
      (void *) kb, &marking, &type1_valueA_again, &status);
   ASSERT_OR_PRINT (res, &status);

   /* Marking type = 2, plaintext = a */
   marking.algorithm = 2;
   memcpy (&marking.v_iter, &a_iter, sizeof (bson_iter_t));
   res = _mongocrypt_marking_to_ciphertext (
      (void *) kb, &marking, &type2_valueA, &status);
   ASSERT_OR_PRINT (res, &status);

   /* Marking type = 1, plaintext = b */
   marking.algorithm = 1;
   memcpy (&marking.v_iter, &b_iter, sizeof (bson_iter_t));
   res = _mongocrypt_marking_to_ciphertext (
      (void *) kb, &marking, &type1_valueB, &status);
   ASSERT_OR_PRINT (res, &status);

   /* Shorten all buffers to their IV length's */
   type1_valueA.data.len = MONGOCRYPT_IV_LEN;
   type1_valueA_again.data.len = MONGOCRYPT_IV_LEN;
   type2_valueA.data.len = MONGOCRYPT_IV_LEN;
   type1_valueB.data.len = MONGOCRYPT_IV_LEN;


   BSON_ASSERT (0 != _mongocrypt_buffer_cmp (&type1_valueA.data, &zeros));
   BSON_ASSERT (0 != _mongocrypt_buffer_cmp (&type1_valueA_again.data, &zeros));
   BSON_ASSERT (0 != _mongocrypt_buffer_cmp (&type2_valueA.data, &zeros));
   BSON_ASSERT (0 != _mongocrypt_buffer_cmp (&type1_valueB.data, &zeros));

   /* Type 1 IV should be repeatable for same plaintext. */
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp (&type1_valueA.data,
                                             &type1_valueA_again.data));
   /* Type 1 IV should differ from type 2 random IV. */
   BSON_ASSERT (
      0 != _mongocrypt_buffer_cmp (&type1_valueA.data, &type2_valueA.data));
   /* Type 1 IV should differ if plaintext differs. */
   BSON_ASSERT (
      0 != _mongocrypt_buffer_cmp (&type1_valueA.data, &type1_valueB.data));


   _mongocrypt_ciphertext_cleanup (&type1_valueA);
   _mongocrypt_ciphertext_cleanup (&type1_valueA_again);
   _mongocrypt_ciphertext_cleanup (&type2_valueA);
   _mongocrypt_ciphertext_cleanup (&type1_valueB);
   _mongocrypt_buffer_cleanup (&zeros);
   _mongocrypt_marking_cleanup (&marking);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   bson_destroy (bson);
}


void
_test_ciphertext_serialize_associated_data (_mongocrypt_tester_t *tester)
{
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t serialized;
   /* Expected associated data is:
    * One byte for blob subtype for deterministic encryption:
    * \x01
    * Followed by 16 byte UUID, a repeating 123 pattern:
    * \x01\x02\x03\x01\x02\x03\x01\x02\x03\x01\x02\x03\x01\x02\x03\x01
    * Followed by the BSON type for UTF8
    * \x02
    */
   char *expected = "\x01\x01\x02\x03\x01\x02\x03\x01\x02\x03\x01\x02\x03\x01"
                    "\x02\x03\x01\x02";

   _mongocrypt_ciphertext_init (&ciphertext);
   _mongocrypt_buffer_init (&serialized);

   /* Create a UUID */
   _mongocrypt_buffer_from_binary (&ciphertext.key_id, TEST_BIN (16));
   ciphertext.key_id.subtype = BSON_SUBTYPE_UUID;

   ciphertext.original_bson_type = BSON_TYPE_UTF8;
   ciphertext.blob_subtype = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;

   BSON_ASSERT (_mongocrypt_ciphertext_serialize_associated_data (&ciphertext,
                                                                  &serialized));
   BSON_ASSERT (serialized.len == 18);
   BSON_ASSERT (0 == memcmp (serialized.data, expected, strlen (expected)));

   _mongocrypt_ciphertext_cleanup (&ciphertext);
   _mongocrypt_buffer_cleanup (&serialized);
}


void
_mongocrypt_tester_install_ciphertext (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_malformed_ciphertext);
   INSTALL_TEST (_test_ciphertext_serialization);
   INSTALL_TEST (_test_ciphertext_algorithm);
   INSTALL_TEST (_test_ciphertext_serialize_associated_data);
}
