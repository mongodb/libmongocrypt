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
#include <mongocrypt-decryptor-private.h>
#include <mongocrypt-key-broker-private.h>

#include "test-mongocrypt.h"


/* Run the decryptor state machine on example data until hitting stop_state or a
 * terminal state. */
void
_mongocrypt_tester_run_decryptor_to (_mongocrypt_tester_t *tester,
                                     mongocrypt_decryptor_t *decryptor,
                                     mongocrypt_decryptor_state_t stop_state)
{
   mongocrypt_decryptor_state_t state;
   mongocrypt_binary_t *bin;
   mongocrypt_key_broker_t *key_broker;

   state = mongocrypt_decryptor_state (decryptor);
   while (state != stop_state) {
      switch (state) {
      case MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC:
         bin = _mongocrypt_tester_encrypted_doc (tester);
         state = mongocrypt_decryptor_add_doc (decryptor, bin);
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS:
         key_broker = mongocrypt_decryptor_get_key_broker (decryptor);
         _mongocrypt_tester_satisfy_key_broker (tester, key_broker);
         state = mongocrypt_decryptor_key_broker_done (decryptor);
         break;
      case MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION:
         state = mongocrypt_decryptor_decrypt (decryptor);
         break;
      case MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED:
      case MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED:
      case MONGOCRYPT_DECRYPTOR_STATE_ERROR:
         BSON_ASSERT (state == stop_state);
         return;
      }
   }
   BSON_ASSERT (state == stop_state);
}


/* Test individual decryptor states. */
static void
_test_decryptor_need_doc (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_decryptor_t *decryptor;
   mongocrypt_decryptor_state_t state;
   mongocrypt_binary_t *encrypted;

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new (NULL, status);
   encrypted = _mongocrypt_tester_encrypted_doc (tester);
   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   decryptor = mongocrypt_decryptor_new (crypt);
   state = mongocrypt_decryptor_add_doc (decryptor, encrypted);
   BSON_ASSERT (state == MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);
   BSON_ASSERT (mongocrypt_decryptor_status (decryptor, status));
   mongocrypt_decryptor_destroy (decryptor);

   /* NULL document. */
   decryptor = mongocrypt_decryptor_new (crypt);
   state = mongocrypt_decryptor_add_doc (decryptor, NULL);
   BSON_ASSERT (state == MONGOCRYPT_DECRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_decryptor_status (decryptor, status));
   ASSERT_STATUS_CONTAINS ("malformed document");
   mongocrypt_decryptor_destroy (decryptor);

   /* Wrong state. */
   decryptor = mongocrypt_decryptor_new (crypt);
   _mongocrypt_tester_run_decryptor_to (
      tester, decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);
   state = mongocrypt_decryptor_add_doc (decryptor, encrypted);
   BSON_ASSERT (state == MONGOCRYPT_DECRYPTOR_STATE_ERROR);
   BSON_ASSERT (!mongocrypt_decryptor_status (decryptor, status));
   ASSERT_STATUS_CONTAINS ("Expected state");
   mongocrypt_decryptor_destroy (decryptor);

   mongocrypt_binary_destroy (encrypted);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_decryptor_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_decryptor_t *decryptor;
   mongocrypt_decryptor_state_t state;
   mongocrypt_key_broker_t *key_broker;

   status = mongocrypt_status_new ();

   /* Success. */
   crypt = mongocrypt_new (NULL, status);
   decryptor = mongocrypt_decryptor_new (crypt);
   _mongocrypt_tester_run_decryptor_to (
      tester, decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);
   key_broker = mongocrypt_decryptor_get_key_broker (decryptor);
   _mongocrypt_tester_satisfy_key_broker (tester, key_broker);
   state = mongocrypt_decryptor_key_broker_done (decryptor);
   BSON_ASSERT (state == MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION);
   BSON_ASSERT (mongocrypt_decryptor_status (decryptor, status));
   mongocrypt_decryptor_destroy (decryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Unsatisfied key broker (not an error). */
   crypt = mongocrypt_new (NULL, status);
   decryptor = mongocrypt_decryptor_new (crypt);
   _mongocrypt_tester_run_decryptor_to (
      tester, decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);
   key_broker = mongocrypt_decryptor_get_key_broker (decryptor);
   state = mongocrypt_decryptor_key_broker_done (decryptor);
   BSON_ASSERT (state == MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION);
   BSON_ASSERT (mongocrypt_decryptor_status (decryptor, status));
   mongocrypt_decryptor_destroy (decryptor);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   mongocrypt_status_destroy (status);
}


static void
_test_decryptor_need_decryption (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   mongocrypt_decryptor_t *decryptor;
   mongocrypt_binary_t *decrypted;
   bson_t as_bson;
   bson_iter_t iter;

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new (NULL, status);
   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   decryptor = mongocrypt_decryptor_new (crypt);
   _mongocrypt_tester_run_decryptor_to (
      tester, decryptor, MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED);
   BSON_ASSERT (mongocrypt_decryptor_status (decryptor, status));
   decrypted = mongocrypt_decryptor_decrypted_doc (decryptor);
   _mongocrypt_binary_to_bson (decrypted, &as_bson);
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
   BSON_ASSERT (0 == strcmp (bson_iter_utf8 (&iter, NULL), "457-55-5462"));
   mongocrypt_binary_destroy (decrypted);
   mongocrypt_decryptor_destroy (decryptor);
   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


void
_mongocrypt_tester_install_decryptor (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_decryptor_need_doc);
   INSTALL_TEST (_test_decryptor_need_keys);
   INSTALL_TEST (_test_decryptor_need_decryption);
}