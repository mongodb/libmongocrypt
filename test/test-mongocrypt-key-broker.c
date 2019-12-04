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

void
_mongocrypt_tester_install_key_broker (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_key_broker_get_key_filter);
   INSTALL_TEST (_test_key_broker_add_key);
   INSTALL_TEST (_test_key_broker_add_decrypted_key);
   INSTALL_TEST (_test_key_broker_wrong_subtype);
   INSTALL_TEST (_test_key_broker_multi_match);
}
