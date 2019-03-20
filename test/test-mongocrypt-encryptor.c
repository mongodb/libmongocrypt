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
#include <mongocrypt-encryptor-private.h>
#include <mongocrypt-decryptor-private.h>
#include <mongocrypt-key-broker-private.h>

#include "test-mongocrypt.h"

/* Run the encryptor state machine on example data until hitting stop_state or a
 * terminal state. */
void
_mongocrypt_tester_run_encryptor_to (_mongocrypt_tester_t *tester,
                                     mongocrypt_encryptor_t *encryptor,
                                     mongocrypt_encryptor_state_t stop_state)
{
   mongocrypt_encryptor_state_t state;
   mongocrypt_binary_t *bin;
   mongocrypt_key_broker_t *key_broker;

   state = mongocrypt_encryptor_state (encryptor);
   while (state != stop_state) {
      switch (state) {
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS:
         state = mongocrypt_encryptor_add_ns (encryptor, "test.test");
         break;
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA:
         bin = _mongocrypt_tester_file (tester,
                                        "./test/example/collection-info.json");
         state = mongocrypt_encryptor_add_collection_info (encryptor, bin);
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS:
         bin = _mongocrypt_tester_file (
            tester, "./test/example/mongocryptd-reply.json");
         state = mongocrypt_encryptor_add_markings (encryptor, bin);
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS:
         key_broker = mongocrypt_encryptor_get_key_broker (encryptor);
         _mongocrypt_tester_satisfy_key_broker (tester, key_broker);
         state = mongocrypt_encryptor_key_broker_done (encryptor);
         break;
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION:
         state = mongocrypt_encryptor_encrypt (encryptor);
         break;
      case MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED:
      case MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED:
      case MONGOCRYPT_ENCRYPTOR_STATE_ERROR:
         BSON_ASSERT (state == stop_state);
         return;
      }
   }
   BSON_ASSERT (state == stop_state);
}


/* Test individual encryptor states. */
static void
_test_encryptor_need_ns (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_encryptor_state_t state;

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new (NULL);
   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   encryptor = mongocrypt_encryptor_new (crypt);
   state = mongocrypt_encryptor_add_ns (encryptor, "test.test");
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);

   /* Invalid namespace. */
   encryptor = mongocrypt_encryptor_new (crypt);
   state = mongocrypt_encryptor_add_ns (encryptor, "invalid-namespace");
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("invalid namespace");
   mongocrypt_encryptor_destroy (encryptor);

   /* NULL namespace. */
   encryptor = mongocrypt_encryptor_new (crypt);
   state = mongocrypt_encryptor_add_ns (encryptor, NULL);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("invalid namespace");
   mongocrypt_encryptor_destroy (encryptor);

   /* Wrong state. */
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);
   state = mongocrypt_encryptor_add_ns (encryptor, "test.test");
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("Expected state");
   mongocrypt_encryptor_destroy (encryptor);

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_encryptor_need_schema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_encryptor_state_t state;
   mongocrypt_binary_t *collinfo;

   status = mongocrypt_status_new ();

   /* Success. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   state = mongocrypt_encryptor_add_collection_info (encryptor, collinfo);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with no schema. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);
   collinfo = _mongocrypt_tester_file (
      tester, "./test/example/collection-info-no-schema.json");
   state = mongocrypt_encryptor_add_collection_info (encryptor, collinfo);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with no schema. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);
   state = mongocrypt_encryptor_add_collection_info (encryptor, NULL);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   state = mongocrypt_encryptor_add_collection_info (encryptor, NULL);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("Expected state");
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt);

   mongocrypt_status_destroy (status);
}


static void
_test_encryptor_need_markings (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_encryptor_state_t state;
   mongocrypt_binary_t *markings;

   status = mongocrypt_status_new ();

   /* Success. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   markings =
      _mongocrypt_tester_file (tester, "./test/example/mongocryptd-reply.json");
   state = mongocrypt_encryptor_add_markings (encryptor, markings);
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No placeholders. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/example/mongocryptd-reply-no-markings.json");
   state = mongocrypt_encryptor_add_markings (encryptor, markings);
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No encryption in schema. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/example/mongocryptd-reply-no-encryption-needed.json");
   state = mongocrypt_encryptor_add_markings (encryptor, markings);
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Invalid marking. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/example/mongocryptd-reply-invalid.json");
   state = mongocrypt_encryptor_add_markings (encryptor, markings);
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("no 'v'");
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* NULL markings. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   state = mongocrypt_encryptor_add_markings (encryptor, NULL);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("invalid markings");
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   state = mongocrypt_encryptor_add_markings (encryptor, markings);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("Expected state");
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt);

   mongocrypt_status_destroy (status);
}


/* TODO CDRIVER-3014, test cases of key broker. */
static void
_test_encryptor_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_encryptor_state_t state;
   mongocrypt_key_broker_t *key_broker;

   status = mongocrypt_status_new ();

   /* Success. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS);
   key_broker = mongocrypt_encryptor_get_key_broker (encryptor);
   _mongocrypt_tester_satisfy_key_broker (tester, key_broker);
   state = mongocrypt_encryptor_key_broker_done (encryptor);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Unsatisfied key broker. */
   crypt = mongocrypt_new (NULL);
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS);
   key_broker = mongocrypt_encryptor_get_key_broker (encryptor);
   state = mongocrypt_encryptor_key_broker_done (encryptor);
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_encryptor_status (encryptor, status));
   ASSERT_STATUS_CONTAINS ("client did not provide all keys");
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   mongocrypt_status_destroy (status);
}


static void
_test_encryptor_need_encryption (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_encryptor_state_t state;
   mongocrypt_binary_t *encrypted_cmd;
   _mongocrypt_buffer_t ciphertext_buf;
   _mongocrypt_ciphertext_t ciphertext;
   bson_t as_bson;
   bson_iter_t iter;
   bool ret;

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new (NULL);
   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (
      tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION);
   state = mongocrypt_encryptor_encrypt (encryptor);
   BSON_ASSERT (mongocrypt_encryptor_status (encryptor, status));
   BSON_ASSERT (state == MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED);

   /* check that the encrypted command has a valid ciphertext. */
   encrypted_cmd = mongocrypt_encryptor_encrypted_cmd (encryptor);
   _mongocrypt_binary_to_bson (encrypted_cmd, &as_bson);
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   _mongocrypt_buffer_from_iter (&ciphertext_buf, &iter);
   ret = _mongocrypt_decryptor_parse_ciphertext_unowned (
      &ciphertext_buf, &ciphertext, status);
   ASSERT_OR_PRINT (ret, status);
   mongocrypt_binary_destroy (encrypted_cmd);
   mongocrypt_encryptor_destroy (encryptor);

   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}


void
_mongocrypt_tester_install_encryptor (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_encryptor_need_ns);
   INSTALL_TEST (_test_encryptor_need_schema);
   INSTALL_TEST (_test_encryptor_need_markings);
   INSTALL_TEST (_test_encryptor_need_keys);
   INSTALL_TEST (_test_encryptor_need_encryption);
}