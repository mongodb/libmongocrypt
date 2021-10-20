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
#include "mongocrypt-key-private.h"
#include "test-mongocrypt.h"

/* Given a string, populate a bson_value_t for that string */
static void
_bson_value_from_string (char *string, bson_value_t *value)
{
   bson_t *bson;
   bson_iter_t iter;

   bson = BCON_NEW ("key", string);
   BSON_ASSERT (bson_iter_init_find (&iter, bson, "key"));
   bson_value_copy (bson_iter_value (&iter), value);

   bson_destroy (bson);
}

static void
_key_broker_add_name (_mongocrypt_key_broker_t *kb, char *string)
{
   bson_value_t key_name;

   _bson_value_from_string (string, &key_name);
   ASSERT_OK (_mongocrypt_key_broker_request_name (kb, (void *) &key_name), kb);
   bson_value_destroy (&key_name);
}

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
_gen_uuid_and_key_and_altname (_mongocrypt_tester_t *tester,
                               char *altname,
                               uint8_t first_byte,
                               _mongocrypt_buffer_t *id,
                               _mongocrypt_buffer_t *doc)
{
   bson_t as_bson, copied;

   _gen_uuid (first_byte, id);
   BSON_ASSERT (_mongocrypt_binary_to_bson (
      TEST_FILE ("./test/example/key-document.json"), &as_bson));
   bson_init (&copied);
   bson_copy_to_excluding_noinit (
      &as_bson, &copied, "_id", "keyAltNames", NULL);
   BSON_ASSERT (_mongocrypt_buffer_append (id, &copied, "_id", 3));
   if (altname) {
      bson_t child;
      bson_append_array_begin (&copied, "keyAltNames", -1, &child);
      bson_append_utf8 (&child, "0", -1, altname, -1);
      bson_append_array_end (&copied, &child);
   }
   _mongocrypt_buffer_steal_from_bson (doc, &copied);
}

static void
_gen_uuid_and_key (_mongocrypt_tester_t *tester,
                   uint8_t first_byte,
                   _mongocrypt_buffer_t *id,
                   _mongocrypt_buffer_t *doc)
{
   _gen_uuid_and_key_and_altname (tester, NULL, first_byte, id, doc);
}


static uint32_t
_key_broker_num_satisfied (_mongocrypt_key_broker_t *kb)
{
   key_request_t *req;
   uint32_t count;

   count = 0;
   for (req = kb->key_requests; NULL != req; req = req->next) {
      if (req->satisfied) {
         count++;
      }
   }
   return count;
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
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id2),
              &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   BSON_ASSERT (_mongocrypt_binary_to_bson (filter, &as_bson));

   expected = BCON_NEW ("$or",
                        "[",
                        "{",
                        "_id",
                        "{",
                        "$in",
                        "[",
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id2.data, key_id2.len),
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id1.data, key_id1.len),
                        "]",
                        "}",
                        "}",
                        "{",
                        "keyAltNames",
                        "{",
                        "$in",
                        "[",
                        "]",
                        "}",
                        "}",
                        "]");

   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

   /* Duplicate key ids. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   BSON_ASSERT (_mongocrypt_binary_to_bson (filter, &as_bson));

   expected = BCON_NEW ("$or",
                        "[",
                        "{",
                        "_id",
                        "{",
                        "$in",
                        "[",
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id1.data, key_id1.len),
                        "]",
                        "}",
                        "}",
                        "{",
                        "keyAltNames",
                        "{",
                        "$in",
                        "[",
                        "]",
                        "}",
                        "}",
                        "]");

   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

   /* No key requests made. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   filter = mongocrypt_binary_new ();
   ASSERT_FAILS (_mongocrypt_key_broker_filter (&key_broker, filter),
                 &key_broker,
                 "in wrong state");
   mongocrypt_binary_destroy (filter);
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Both key ids and keyAltName */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   _key_broker_add_name (&key_broker, "Miriam");
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   BSON_ASSERT (_mongocrypt_binary_to_bson (filter, &as_bson));

   expected = BCON_NEW ("$or",
                        "[",
                        "{",
                        "_id",
                        "{",
                        "$in",
                        "[",
                        BCON_BIN (BSON_SUBTYPE_UUID, key_id1.data, key_id1.len),
                        "]",
                        "}",
                        "}",
                        "{",
                        "keyAltNames",
                        "{",
                        "$in",
                        "[",
                        BCON_UTF8 ("Miriam"),
                        "]",
                        "}",
                        "}",
                        "]");

   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

   /* Keys with only keyAltName */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   _key_broker_add_name (&key_broker, "Sharlene");
   _key_broker_add_name (&key_broker, "Emily");
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   BSON_ASSERT (_mongocrypt_binary_to_bson (filter, &as_bson));

   expected = BCON_NEW ("$or",
                        "[",
                        "{",
                        "_id",
                        "{",
                        "$in",
                        "[",
                        "]",
                        "}",
                        "}",
                        "{",
                        "keyAltNames",
                        "{",
                        "$in",
                        "[",
                        BCON_UTF8 ("Emily"),
                        BCON_UTF8 ("Sharlene"),
                        "]",
                        "}",
                        "}",
                        "]");

   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

   /* Duplicate alt names */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   _key_broker_add_name (&key_broker, "Jackie");
   _key_broker_add_name (&key_broker, "Jackie");
   _key_broker_add_name (&key_broker, "Jackie");
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   filter = mongocrypt_binary_new ();
   ASSERT_OK (_mongocrypt_key_broker_filter (&key_broker, filter), &key_broker);
   BSON_ASSERT (_mongocrypt_binary_to_bson (filter, &as_bson));

   expected = BCON_NEW ("$or",
                        "[",
                        "{",
                        "_id",
                        "{",
                        "$in",
                        "[",
                        "]",
                        "}",
                        "}",
                        "{",
                        "keyAltNames",
                        "{",
                        "$in",
                        "[",
                        BCON_UTF8 ("Jackie"),
                        "]",
                        "}",
                        "}",
                        "]");

   BSON_ASSERT (0 == bson_compare (expected, &as_bson));
   bson_destroy (expected);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_binary_destroy (filter);

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
   _mongocrypt_buffer_t key_id1, key_id2, key_doc1, key_doc2, malformed_buf,
      key_buf_x, key_buf_y, key_doc_names;
   _mongocrypt_buffer_t *id_x;
   _mongocrypt_key_doc_t *key_x;
   bson_t key_bson_x;
   bson_t *malformed;
   _mongocrypt_key_broker_t key_broker;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   _gen_uuid_and_key (tester, 1, &key_id1, &key_doc1);
   _gen_uuid_and_key (tester, 2, &key_id2, &key_doc2);

   /* Valid key documents. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_docs_done (&key_broker), &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Valid document with a key name. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   _key_broker_add_name (&key_broker, "Kasey");
   _mongocrypt_buffer_from_binary (
      &key_doc_names,
      TEST_FILE ("./test/data/key-document-with-alt-name.json"));
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc_names),
              &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Malformed key document. */
   malformed = BCON_NEW ("abc", BCON_INT32 (123));
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   _mongocrypt_buffer_from_bson (&malformed_buf, malformed);
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, &malformed_buf),
                 &key_broker,
                 "unrecognized field");
   _mongocrypt_key_broker_cleanup (&key_broker);
   bson_destroy (malformed);

   /* NULL key document. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   BSON_ASSERT (_mongocrypt_key_broker_request_id (&key_broker, &key_id1));
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, NULL),
                 &key_broker,
                 "invalid key");
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Unmatched key document. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2),
                 &key_broker,
                 "unexpected key returned");
   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Two key documents with the same keyAltName and
      different key ids. In order to test this, we need
      to add a name X and an id Y to the broker, then
      add a document with name X and id Z (succeeds) and
      afterwards add a doc with name X and id Y (fails). */
   key_x = _mongocrypt_key_new ();
   _mongocrypt_key_broker_init (&key_broker, crypt);

   _mongocrypt_buffer_from_binary (
      &key_buf_x, TEST_FILE ("./test/data/key-document-with-alt-name.json"));
   _mongocrypt_buffer_from_binary (
      &key_buf_y,
      TEST_FILE ("./test/data/key-document-with-alt-name-duplicate-id.json"));

   BSON_ASSERT (_mongocrypt_buffer_to_bson (&key_buf_x, &key_bson_x));
   ASSERT_OR_PRINT (_mongocrypt_key_parse_owned (&key_bson_x, key_x, status),
                    status);
   id_x = &key_x->id;

   /* Configure the key broker so it contains:
      - { id : X }
      - { name : "Sharlene" } */
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, id_x),
              &key_broker);
   _key_broker_add_name (&key_broker, "Sharlene");
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);

   /* Add { id : Y, name : "Sharlene" }, should pass. */
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_buf_y),
              &key_broker);

   /* Add { id : X, name : "Sharlene" }, should fail, it shares an alt name. */
   ASSERT_FAILS (_mongocrypt_key_broker_add_doc (&key_broker, &key_buf_x),
                 &key_broker,
                 "duplicate keyAltNames");

   _mongocrypt_key_broker_cleanup (&key_broker);

   /* Calling done before supplying all keys. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);

   bson_destroy (&key_bson_x);
   _mongocrypt_key_destroy (key_x);
   _mongocrypt_buffer_cleanup (&key_doc_names);
   _mongocrypt_buffer_cleanup (&key_id1);
   _mongocrypt_buffer_cleanup (&key_id2);
   _mongocrypt_buffer_cleanup (&key_doc1);
   _mongocrypt_buffer_cleanup (&key_doc2);
   _mongocrypt_buffer_cleanup (&key_buf_x);
   _mongocrypt_buffer_cleanup (&key_buf_y);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

static void
_test_key_broker_add_decrypted_key (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key_id1, key_id2, key_doc1, key_doc2, key_doc_names,
      key_id_names;
   _mongocrypt_key_broker_t key_broker;
   mongocrypt_kms_ctx_t *kms;
   bson_iter_t iter;
   bson_t key_doc_names_bson;

   status = mongocrypt_status_new ();
   _gen_uuid_and_key (tester, 1, &key_id1, &key_doc1);
   _gen_uuid_and_key (tester, 2, &key_id2, &key_doc2);

   /* Success. With key ids. */
   crypt = _mongocrypt_tester_mongocrypt ();
   _mongocrypt_key_broker_init (&key_broker, crypt);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc1),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_docs_done (&key_broker), &key_broker);
   kms = _mongocrypt_key_broker_next_kms (&key_broker);
   BSON_ASSERT (kms);
   _mongocrypt_tester_satisfy_kms (tester, kms);
   kms = _mongocrypt_key_broker_next_kms (&key_broker);
   BSON_ASSERT (kms);
   _mongocrypt_tester_satisfy_kms (tester, kms);
   BSON_ASSERT (!_mongocrypt_key_broker_next_kms (&key_broker));
   ASSERT_OK (_mongocrypt_key_broker_kms_done (&key_broker), &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_destroy (crypt); /* destroy crypt to reset cache. */

   /* Success. With key alt names. */
   crypt = _mongocrypt_tester_mongocrypt ();
   _mongocrypt_key_broker_init (&key_broker, crypt);
   _key_broker_add_name (&key_broker, "Sharlene");
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);

   _mongocrypt_buffer_from_binary (
      &key_doc_names,
      TEST_FILE ("./test/data/key-document-with-alt-name.json"));
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc_names),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_docs_done (&key_broker), &key_broker);
   kms = _mongocrypt_key_broker_next_kms (&key_broker);
   BSON_ASSERT (kms);

   _mongocrypt_tester_satisfy_kms (tester, kms);
   BSON_ASSERT (!_mongocrypt_key_broker_next_kms (&key_broker));
   ASSERT_OK (_mongocrypt_key_broker_kms_done (&key_broker), &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_destroy (crypt); /* destroy crypt to reset cache. */

   /* With both key ids and key alt names, some referring to the same key */
   crypt = _mongocrypt_tester_mongocrypt ();
   _mongocrypt_key_broker_init (&key_broker, crypt);
   BSON_ASSERT (
      _mongocrypt_buffer_to_bson (&key_doc_names, &key_doc_names_bson));
   BSON_ASSERT (bson_iter_init_find (&iter, &key_doc_names_bson, "_id"));
   BSON_ASSERT (_mongocrypt_buffer_from_binary_iter (&key_id_names, &iter));
   BSON_ASSERT (key_id_names.subtype == BSON_SUBTYPE_UUID);
   ASSERT_OK (_mongocrypt_key_broker_request_id (&key_broker, &key_id_names),
              &key_broker);
   _key_broker_add_name (&key_broker, "Sharlene");
   _key_broker_add_name (&key_broker, "Kasey");
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc_names),
              &key_broker);
   ASSERT_OK (_mongocrypt_key_broker_docs_done (&key_broker), &key_broker);
   kms = _mongocrypt_key_broker_next_kms (&key_broker);
   BSON_ASSERT (kms);
   _mongocrypt_tester_satisfy_kms (tester, kms);
   BSON_ASSERT (!_mongocrypt_key_broker_next_kms (&key_broker));
   ASSERT_OK (_mongocrypt_key_broker_kms_done (&key_broker), &key_broker);
   _mongocrypt_key_broker_cleanup (&key_broker);

   bson_destroy (&key_doc_names_bson);
   _mongocrypt_buffer_cleanup (&key_id_names);
   _mongocrypt_buffer_cleanup (&key_id1);
   _mongocrypt_buffer_cleanup (&key_id2);
   _mongocrypt_buffer_cleanup (&key_doc1);
   _mongocrypt_buffer_cleanup (&key_doc2);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_broker_wrong_subtype (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key_id, key_doc;
   _mongocrypt_key_broker_t key_broker;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   _gen_uuid_and_key (tester, 1, &key_id, &key_doc);

   /* Valid key documents. */
   _mongocrypt_key_broker_init (&key_broker, crypt);
   key_id.subtype = 0;
   ASSERT_FAILS (_mongocrypt_key_broker_request_id (&key_broker, &key_id),
                 &key_broker,
                 "expected UUID");

   _mongocrypt_buffer_cleanup (&key_id);
   _mongocrypt_buffer_cleanup (&key_doc);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_broker_multi_match (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_t key_broker;
   status = mongocrypt_status_new ();
   _mongocrypt_buffer_t key_id1, key_id2, key_doc1, key_doc2;

   _gen_uuid_and_key_and_altname (tester, "alt1", 1, &key_id1, &key_doc1);
   _gen_uuid_and_key_and_altname (tester, "alt2", 2, &key_id2, &key_doc2);


   crypt = _mongocrypt_tester_mongocrypt ();
   _mongocrypt_key_broker_init (&key_broker, crypt);

   /* Add two ids and two alt names */
   BSON_ASSERT (_mongocrypt_key_broker_request_id (&key_broker, &key_id1));
   _key_broker_add_name (&key_broker, "alt1");
   BSON_ASSERT (_mongocrypt_key_broker_request_id (&key_broker, &key_id2));
   _key_broker_add_name (&key_broker, "alt2");
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&key_broker), &key_broker);

   /* Should be zero satisfied */
   BSON_ASSERT (0 == _key_broker_num_satisfied (&key_broker));

   /* Add one doc, should satisfy two requests. */
   BSON_ASSERT (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc1));
   BSON_ASSERT (2 == _key_broker_num_satisfied (&key_broker));

   /* Add other doc, should satisfy all. */
   BSON_ASSERT (_mongocrypt_key_broker_add_doc (&key_broker, &key_doc2));
   BSON_ASSERT (4 == _key_broker_num_satisfied (&key_broker));

   _mongocrypt_buffer_cleanup (&key_id1);
   _mongocrypt_buffer_cleanup (&key_doc1);
   _mongocrypt_buffer_cleanup (&key_id2);
   _mongocrypt_buffer_cleanup (&key_doc2);
   _mongocrypt_key_broker_cleanup (&key_broker);
   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}


/*
<RequestMessage tag="0x420078" type="Structure">
 <RequestHeader tag="0x420077" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="0"/>
  </ProtocolVersion>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </RequestHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <RequestPayload tag="0x420079" type="Structure">
   <UniqueIdentifier tag="0x420094" type="TextString"
value="ywxrSj5TLjswd1G4oGFJ6hwWgtTsQip0"/>
  </RequestPayload>
 </BatchItem>
</RequestMessage>
*/
static const uint8_t EXPECTED_GET_REQUEST[] = {
   0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x88, 0x42, 0x00, 0x77, 0x01,
   0x00, 0x00, 0x00, 0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
   0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
   0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0d, 0x02,
   0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
   0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x40, 0x42, 0x00, 0x5c, 0x05,
   0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
   0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x28, 0x42, 0x00, 0x94, 0x07,
   0x00, 0x00, 0x00, 0x20, 0x79, 0x77, 0x78, 0x72, 0x53, 0x6a, 0x35, 0x54,
   0x4c, 0x6a, 0x73, 0x77, 0x64, 0x31, 0x47, 0x34, 0x6f, 0x47, 0x46, 0x4a,
   0x36, 0x68, 0x77, 0x57, 0x67, 0x74, 0x54, 0x73, 0x51, 0x69, 0x70, 0x30};

/*
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2021-10-03T17:39:52-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <ObjectType tag="0x420057" type="Enumeration" value="7"/>
   <UniqueIdentifier tag="0x420094" type="TextString"
value="ywxrSj5TLjswd1G4oGFJ6hwWgtTsQip0"/>
   <SecretData tag="0x420085" type="Structure">
    <SecretDataType tag="0x420086" type="Enumeration" value="2"/>
    <KeyBlock tag="0x420040" type="Structure">
     <KeyFormatType tag="0x420042" type="Enumeration" value="1"/>
     <KeyValue tag="0x420045" type="Structure">
      <KeyMaterial tag="0x420043" type="ByteString"
value="0c2ea7297180f82a984b2fd47d6327ce226f62e9017b91dc6e5d6dfd98747d97e89f17bf0926cfcc0afb24e69b7c00121dda12d0158c4375c31084abf7f2e6044edc2f92802ba3f676d470d2cbc4e33a2a8e53dced7828dd8a35f268437ff141"/>
     </KeyValue>
    </KeyBlock>
   </SecretData>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>
*/
static const uint8_t SUCCESS_GET_RESPONSE[] = {
   0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x01, 0x58, 0x42, 0x00, 0x7a, 0x01, 0x00,
   0x00, 0x00, 0x48, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00,
   0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00,
   0x00, 0x00, 0x00, 0x61, 0x59, 0xea, 0xe8, 0x42, 0x00, 0x0d, 0x02, 0x00, 0x00,
   0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
   0x01, 0x00, 0x00, 0x01, 0x00, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, 0x00,
   0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
   0x7c, 0x01, 0x00, 0x00, 0x00, 0xd8, 0x42, 0x00, 0x57, 0x05, 0x00, 0x00, 0x00,
   0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x94, 0x07,
   0x00, 0x00, 0x00, 0x20, 0x79, 0x77, 0x78, 0x72, 0x53, 0x6a, 0x35, 0x54, 0x4c,
   0x6a, 0x73, 0x77, 0x64, 0x31, 0x47, 0x34, 0x6f, 0x47, 0x46, 0x4a, 0x36, 0x68,
   0x77, 0x57, 0x67, 0x74, 0x54, 0x73, 0x51, 0x69, 0x70, 0x30, 0x42, 0x00, 0x85,
   0x01, 0x00, 0x00, 0x00, 0x98, 0x42, 0x00, 0x86, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x40, 0x01, 0x00,
   0x00, 0x00, 0x80, 0x42, 0x00, 0x42, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
   0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x45, 0x01, 0x00, 0x00, 0x00,
   0x68, 0x42, 0x00, 0x43, 0x08, 0x00, 0x00, 0x00, 0x60, 0x0c, 0x2e, 0xa7, 0x29,
   0x71, 0x80, 0xf8, 0x2a, 0x98, 0x4b, 0x2f, 0xd4, 0x7d, 0x63, 0x27, 0xce, 0x22,
   0x6f, 0x62, 0xe9, 0x01, 0x7b, 0x91, 0xdc, 0x6e, 0x5d, 0x6d, 0xfd, 0x98, 0x74,
   0x7d, 0x97, 0xe8, 0x9f, 0x17, 0xbf, 0x09, 0x26, 0xcf, 0xcc, 0x0a, 0xfb, 0x24,
   0xe6, 0x9b, 0x7c, 0x00, 0x12, 0x1d, 0xda, 0x12, 0xd0, 0x15, 0x8c, 0x43, 0x75,
   0xc3, 0x10, 0x84, 0xab, 0xf7, 0xf2, 0xe6, 0x04, 0x4e, 0xdc, 0x2f, 0x92, 0x80,
   0x2b, 0xa3, 0xf6, 0x76, 0xd4, 0x70, 0xd2, 0xcb, 0xc4, 0xe3, 0x3a, 0x2a, 0x8e,
   0x53, 0xdc, 0xed, 0x78, 0x28, 0xdd, 0x8a, 0x35, 0xf2, 0x68, 0x43, 0x7f, 0xf1,
   0x41};

static const uint8_t EXPECTED_SECRETDATA[] = {
   0x94, 0x82, 0x4f, 0x44, 0xbe, 0xb2, 0x20, 0x73, 0x14, 0xad, 0x8b, 0x36,
   0x38, 0xaf, 0x01, 0x45, 0xa5, 0x13, 0x80, 0x84, 0x44, 0x57, 0xdf, 0xde,
   0x9f, 0xb6, 0x7b, 0xfb, 0xf9, 0x21, 0xf9, 0x00, 0xb2, 0x00, 0x9e, 0x07,
   0xcf, 0x04, 0xc3, 0x5b, 0x9a, 0x98, 0x3b, 0xa9, 0x22, 0x83, 0x3d, 0x7a,
   0x07, 0xc5, 0x90, 0x84, 0xe7, 0x63, 0xf0, 0x47, 0xf0, 0x1a, 0x4b, 0xfe,
   0x03, 0xbc, 0xe3, 0x82, 0x96, 0x95, 0x88, 0xb8, 0x18, 0x63, 0x33, 0x15,
   0x73, 0x95, 0xe2, 0xb1, 0x38, 0xde, 0x6c, 0x13, 0xf8, 0x98, 0x43, 0xbe,
   0x3f, 0x85, 0x83, 0xd0, 0x11, 0x88, 0xb8, 0x0f, 0xb5, 0x8c, 0x2a, 0x1c};

static void
_test_key_broker_kmip (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_t kb;
   bson_t keydoc_bson;
   bson_iter_t iter;
   _mongocrypt_buffer_t id;
   _mongocrypt_buffer_t keydoc;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_binary_t *msg;
   _mongocrypt_buffer_t secretdata;

   crypt = _mongocrypt_tester_mongocrypt ();
   status = mongocrypt_status_new ();
   _mongocrypt_key_broker_init (&kb, crypt);
   _load_json_as_bson ("./test/data/key-document-kmip.json", &keydoc_bson);

   ASSERT_OR_PRINT_MSG (bson_iter_init_find (&iter, &keydoc_bson, "_id"),
                        "could not find _id in key-document-kmip.json");
   BSON_ASSERT (_mongocrypt_buffer_from_binary_iter (&id, &iter));
   ASSERT_OK (_mongocrypt_key_broker_request_id (&kb, &id), &kb);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&kb), &kb);

   /* Add the key document. */
   _mongocrypt_buffer_from_bson (&keydoc, &keydoc_bson);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&kb, &keydoc), &kb);
   ASSERT_OK (_mongocrypt_key_broker_docs_done (&kb), &kb);

   /* There should be exactly one KMS request for KMIP. */
   kms = _mongocrypt_key_broker_next_kms (&kb);
   ASSERT_OR_PRINT_MSG (kms, "expected KMS context returned, got none");

   msg = mongocrypt_binary_new ();
   mongocrypt_kms_ctx_message (kms, msg);
   ASSERT_CMPBYTES (EXPECTED_GET_REQUEST,
                    sizeof (EXPECTED_GET_REQUEST),
                    mongocrypt_binary_data (msg),
                    mongocrypt_binary_len (msg));

   ASSERT_OK (kms_ctx_feed_all (
                 kms, SUCCESS_GET_RESPONSE, sizeof (SUCCESS_GET_RESPONSE)),
              kms);
   ASSERT_OK (_mongocrypt_key_broker_kms_done (&kb), &kb);

   BSON_ASSERT (
      _mongocrypt_key_broker_decrypted_key_by_id (&kb, &id, &secretdata));
   ASSERT_CMPBYTES (secretdata.data,
                    secretdata.len,
                    EXPECTED_SECRETDATA,
                    sizeof (EXPECTED_SECRETDATA));

   _mongocrypt_buffer_cleanup (&secretdata);
   mongocrypt_binary_destroy (msg);
   _mongocrypt_buffer_cleanup (&keydoc);
   _mongocrypt_buffer_cleanup (&id);
   bson_destroy (&keydoc_bson);
   _mongocrypt_key_broker_cleanup (&kb);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

/*
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2021-10-01T14:43:13-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="1"/>
  <ResultReason tag="0x42007e" type="Enumeration" value="1"/>
  <ResultMessage tag="0x42007d" type="TextString"
value="ResultReasonItemNotFound"/>
 </BatchItem>
</ResponseMessage>
*/
static const uint8_t ERROR_GET_RESPOSE_NOTFOUND[] = {
   0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x00, 0xa8, 0x42, 0x00, 0x7a, 0x01, 0x00,
   0x00, 0x00, 0x48, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00,
   0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00,
   0x00, 0x00, 0x00, 0x61, 0x57, 0x1e, 0x81, 0x42, 0x00, 0x0d, 0x02, 0x00, 0x00,
   0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
   0x01, 0x00, 0x00, 0x00, 0x50, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, 0x00,
   0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
   0x7e, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x7d, 0x07, 0x00, 0x00, 0x00, 0x18, 0x52, 0x65, 0x73, 0x75,
   0x6c, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x49, 0x74, 0x65, 0x6d, 0x4e,
   0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64};

static void
_test_key_broker_kmip_notfound (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_t kb;
   bson_t keydoc_bson;
   bson_iter_t iter;
   _mongocrypt_buffer_t id;
   _mongocrypt_buffer_t keydoc;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_binary_t *msg;

   crypt = _mongocrypt_tester_mongocrypt ();
   status = mongocrypt_status_new ();
   _mongocrypt_key_broker_init (&kb, crypt);
   _load_json_as_bson ("./test/data/key-document-kmip.json", &keydoc_bson);

   ASSERT_OR_PRINT_MSG (bson_iter_init_find (&iter, &keydoc_bson, "_id"),
                        "could not find _id in key-document-kmip.json");
   BSON_ASSERT (_mongocrypt_buffer_from_binary_iter (&id, &iter));
   ASSERT_OK (_mongocrypt_key_broker_request_id (&kb, &id), &kb);
   ASSERT_OK (_mongocrypt_key_broker_requests_done (&kb), &kb);

   /* Add the key document. */
   _mongocrypt_buffer_from_bson (&keydoc, &keydoc_bson);
   ASSERT_OK (_mongocrypt_key_broker_add_doc (&kb, &keydoc), &kb);
   ASSERT_OK (_mongocrypt_key_broker_docs_done (&kb), &kb);

   /* There should be exactly one KMS request for KMIP. */
   kms = _mongocrypt_key_broker_next_kms (&kb);
   ASSERT_OR_PRINT_MSG (kms, "expected KMS context returned, got none");

   msg = mongocrypt_binary_new ();
   mongocrypt_kms_ctx_message (kms, msg);
   ASSERT_CMPBYTES (EXPECTED_GET_REQUEST,
                    sizeof (EXPECTED_GET_REQUEST),
                    mongocrypt_binary_data (msg),
                    mongocrypt_binary_len (msg));

   ASSERT_FAILS (kms_ctx_feed_all (kms,
                                   ERROR_GET_RESPOSE_NOTFOUND,
                                   sizeof (ERROR_GET_RESPOSE_NOTFOUND)),
                 kms,
                 "ResultReasonItemNotFound");

   mongocrypt_binary_destroy (msg);
   _mongocrypt_buffer_cleanup (&keydoc);
   _mongocrypt_buffer_cleanup (&id);
   bson_destroy (&keydoc_bson);
   _mongocrypt_key_broker_cleanup (&kb);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_key_broker (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_key_broker_get_key_filter);
   INSTALL_TEST (_test_key_broker_add_key);
   INSTALL_TEST (_test_key_broker_add_decrypted_key);
   INSTALL_TEST (_test_key_broker_wrong_subtype);
   INSTALL_TEST (_test_key_broker_multi_match);
   INSTALL_TEST (_test_key_broker_kmip);
   INSTALL_TEST (_test_key_broker_kmip_notfound);
}
