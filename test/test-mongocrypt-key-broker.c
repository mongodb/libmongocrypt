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

#include "mongocrypt.h"
#include "mongocrypt-key-broker-private.h"
#include "test-mongocrypt.h"


/* Create an example 16 byte UUID. Use first_byte to distinguish. */
static void
_gen_uuid (uint8_t first_byte, _mongocrypt_buffer_t *out)
{
   _mongocrypt_tester_fill_buffer (out, 16);
   out->subtype = BSON_SUBTYPE_UUID;
   out->data[0] = first_byte;
}


/* Create an example 16 byte UUID and a corresponding key document with the same
 * _id as the UUID. */
static void
_gen_uuid_and_key (_mongocrypt_tester_t *tester,
                   uint8_t first_byte,
                   _mongocrypt_buffer_t *id,
                   _mongocrypt_buffer_t *doc)
{
   mongocrypt_binary_t *key_doc;
   bson_t as_bson, copied;

   _gen_uuid (first_byte, id);
   key_doc =
      _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   _mongocrypt_binary_to_bson (key_doc, &as_bson);
   bson_init (&copied);
   bson_copy_to_excluding_noinit (&as_bson, &copied, "_id", NULL);
   _mongocrypt_buffer_append (id, &copied, "_id", 3);
   _mongocrypt_buffer_steal_from_bson (doc, &copied);
   mongocrypt_binary_destroy (key_doc);
}


static void
_test_key_broker_get_key_filter (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key_id1, key_id2;
   mongocrypt_binary_t *filter;
   _mongocrypt_key_broker_t key_broker;
   bson_t as_bson;
   bson_t *expected;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   _gen_uuid (1, &key_id1);
   _gen_uuid (2, &key_id2);

   /* Multiple different key ids. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id2),
              &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   _mongocrypt_binary_to_bson (filter, &as_bson);
   expected = BCON_NEW ("_id",
                        "{",
                        "$in",
                        "[",
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id2.data, key_id2.len),
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id1.data, key_id1.len),
                        "]",
                        "}");
   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

   /* Duplicate key ids. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   _mongocrypt_binary_to_bson (filter, &as_bson);
   expected = BCON_NEW ("_id",
                        "{",
                        "$in",
                        "[",
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id1.data, key_id1.len),
                        "]",
                        "}");
   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

   /* No keys. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   BSON_ASSERT (!filter->data);
   mongocrypt_binary_destroy (filter);
   _mongocrypt_key_broker_cleanup (&key_broker);

   _mongocrypt_buffer_cleanup (&key_id1);
   _mongocrypt_buffer_cleanup (&key_id2);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_broker_add_key (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key_id1, key_id2, key_doc1, key_doc2, malformed_buf;
   bson_t *malformed;
   _mongocrypt_key_broker_t key_broker;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   _gen_uuid_and_key (tester, 1, &key_id1, &key_doc1);
   _gen_uuid_and_key (tester, 2, &key_id2, &key_doc2);

   /* Valid key documents. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_done_adding_docs (&key_broker),
              &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Malformed key document. */
   malformed = BCON_NEW ("abc", BCON_INT32 (123));
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   _mongocrypt_buffer_from_bson (&malformed_buf, malformed);
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, &malformed_buf),
                 &key_broker,
                 "invalid key");
   _mongocrypt_key_broker_cleanup (&key_broker);
   bson_destroy (malformed);

   /* NULL key document. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   _mongocrypt_key_broker_add_id (&key_broker, &key_id1);
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, NULL),
                 &key_broker,
                 "invalid key");
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Unmatched key document. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2),
                 &key_broker,
                 "no key matching passed ID");
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Calling done before supplying all keys. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_FAILS (_mongocrypt_key_broker_done_adding_docs (&key_broker),
                 &key_broker,
                 "client did not provide all keys");
   _mongocrypt_key_broker_cleanup (&key_broker);

   _mongocrypt_buffer_cleanup (&key_id1);
   _mongocrypt_buffer_cleanup (&key_id2);
   _mongocrypt_buffer_cleanup (&key_doc1);
   _mongocrypt_buffer_cleanup (&key_doc2);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_broker_add_decrypted_key (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key_id1, key_id2, key_doc1, key_doc2;
   _mongocrypt_key_broker_t key_broker;
   mongocrypt_kms_ctx_t *kms;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   _gen_uuid_and_key (tester, 1, &key_id1, &key_doc1);
   _gen_uuid_and_key (tester, 2, &key_id2, &key_doc2);

   /* Success. */
   _mongocrypt_key_broker_init (&key_broker, &crypt->opts, &crypt->cache_key);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_id (&key_broker, &key_id2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_done_adding_docs (&key_broker),
              &key_broker);
   kms = _mongocrypt_key_broker_next_kms (&key_broker);
   BSON_ASSERT (kms);
   _mongocrypt_tester_satisfy_kms (tester, kms);
   kms = _mongocrypt_key_broker_next_kms (&key_broker);
   BSON_ASSERT (kms);
   _mongocrypt_tester_satisfy_kms (tester, kms);
   BSON_ASSERT (!_mongocrypt_key_broker_next_kms (&key_broker));
   ASSERT_OK (_mongocrypt_key_broker_kms_done (&key_broker), &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);


   _mongocrypt_buffer_cleanup (&key_id1);
   _mongocrypt_buffer_cleanup (&key_id2);
   _mongocrypt_buffer_cleanup (&key_doc1);
   _mongocrypt_buffer_cleanup (&key_doc2);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


void
_mongocrypt_tester_install_key_broker (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_key_broker_get_key_filter);
   INSTALL_TEST (_test_key_broker_add_key);
   INSTALL_TEST (_test_key_broker_add_decrypted_key);
}