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
#include "mongocrypt-crypto-private.h"

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
_test_ciphertext_serialization (_mongocrypt_tester_t* tester)
{
   _mongocrypt_ciphertext_t original, returned;
   _mongocrypt_buffer_t serialized;
   char *expected = "\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
                    "\x0D\x0E\x0F\x02\x00\x01";
   mongocrypt_status_t *status;

   _mongocrypt_buffer_init (&serialized);
   status = mongocrypt_status_new ();

   original.blob_subtype = 1;
   original.original_bson_type = 2;
   _mongocrypt_tester_fill_buffer (&original.data, 2);
   _mongocrypt_tester_fill_buffer (&original.key_id, 16);

   _test_mongocrypt_serialize_ciphertext (&original, &serialized);
   BSON_ASSERT (0 == memcmp (expected, serialized.data, serialized.len));

   /* Now parse it back, should get the same ciphertext. */
   BSON_ASSERT (_test_mongocrypt_ciphertext_parse_unowned (&serialized, &returned, status));
   BSON_ASSERT (original.blob_subtype == returned.blob_subtype);
   BSON_ASSERT (original.original_bson_type == returned.original_bson_type);
   BSON_ASSERT (0 ==
                _mongocrypt_buffer_cmp (&original.key_id, &returned.key_id));
   BSON_ASSERT (0 == _mongocrypt_buffer_cmp (&original.data, &returned.data));

   _mongocrypt_buffer_cleanup (&original.data);
   _mongocrypt_buffer_cleanup (&original.key_id);
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

   BSON_ASSERT (!_test_mongocrypt_ciphertext_parse_unowned (
      &serialized, &returned, status));
   BSON_ASSERT (0 ==
                strcmp (status->message, "malformed ciphertext, too small"));
   _mongocrypt_buffer_cleanup (&serialized);

   _mongocrypt_tester_fill_buffer (&serialized, 19);
   /* give a valid blob_subtype. */
   serialized.data[0] = 1;
   BSON_ASSERT (_test_mongocrypt_ciphertext_parse_unowned (
      &serialized, &returned, status));

   /* now an invalid blob_subtype. */
   serialized.data[0] = 16;
   BSON_ASSERT (!_test_mongocrypt_ciphertext_parse_unowned (
      &serialized, &returned, status));
   BSON_ASSERT (
      0 == strcmp (status->message,
                   "malformed ciphertext, expected blob subtype of 1 or 2"));

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
  _mongocrypt_buffer_t iv = {0};
  _mongocrypt_ciphertext_t ciphertext = {{0}};
  _mongocrypt_marking_t marking = {0};
  bson_iter_t iter;
  bson_t *bson;
  bool res;

  crypt = _mongocrypt_tester_mongocrypt ();
  ctx = mongocrypt_ctx_new (crypt);
  ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN("test.test")), ctx);

  _mongocrypt_buffer_resize (&marking.key_id, MONGOCRYPT_ENC_KEY_LEN);
  BSON_ASSERT (_crypto_random (&marking.key_id, &status, MONGOCRYPT_ENC_KEY_LEN));
  kb = &ctx->kb;
  BSON_ASSERT (_mongocrypt_key_broker_add_test_key (kb, &marking.key_id));

  bson = BCON_NEW ("v", "hello");
  bson_iter_init_find (&iter, bson, "v");
  memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));

  /* Seed the marking's iv with anything */
  _mongocrypt_buffer_resize (&marking.iv, MONGOCRYPT_IV_LEN);
  BSON_ASSERT (_crypto_random (&marking.iv, &status, MONGOCRYPT_IV_LEN));

  /* Use a marking with type 1, make sure iv is our original iv */
  marking.algorithm = 1;
  res = _marking_to_ciphertext ((void *)kb, &marking, &ciphertext, &status);
  ASSERT_OR_PRINT (res, &status);
  BSON_ASSERT (res);
  iv.data = ciphertext.data.data;
  iv.len = MONGOCRYPT_IV_LEN;
  BSON_ASSERT (_mongocrypt_buffer_cmp (&iv, &marking.iv) == 0);
  _mongocrypt_buffer_cleanup (&ciphertext.data);

  /* Use a marking with type 2, make sure iv is random */
  marking.algorithm = 2;
  res = _marking_to_ciphertext ((void *)kb, &marking, &ciphertext, &status);
  BSON_ASSERT (res);
  iv.data = ciphertext.data.data;
  iv.len = MONGOCRYPT_IV_LEN;
  BSON_ASSERT (_mongocrypt_buffer_cmp (&iv, &marking.iv) != 0);

  _mongocrypt_marking_cleanup (&marking);
  _mongocrypt_buffer_cleanup (&ciphertext.data);
  mongocrypt_ctx_destroy (ctx);
  mongocrypt_destroy (crypt);
  bson_destroy (bson);
}

void
_mongocrypt_tester_install_ciphertext (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_malformed_ciphertext);
   INSTALL_TEST (_test_ciphertext_serialization);
   INSTALL_TEST (_test_ciphertext_algorithm);
}
