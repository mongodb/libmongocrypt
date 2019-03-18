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
#include <mongocrypt-key-broker-private.h>

#include "test-mongocrypt.h"

static void
_test_encryptor (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   mongocrypt_binary_t *command;
   mongocrypt_binary_t *collection_info;
   mongocrypt_binary_t *marked_reply;
   mongocrypt_binary_t *key_document;
   mongocrypt_binary_t *kms_reply;
   mongocrypt_t *mongocrypt;
   mongocrypt_key_broker_t *kb;
   mongocrypt_encryptor_t *encryptor;
   const mongocrypt_binary_t *key_query;
   mongocrypt_key_decryptor_t *key_decryptor;
   bson_t tmp;
   _mongocrypt_buffer_t tmp_buf;
   bson_iter_t iter;

   status = mongocrypt_status_new ();
   mongocrypt = mongocrypt_new (NULL, status);

   collection_info =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   key_document =
      _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   kms_reply = _mongocrypt_tester_file (tester, "./test/example/kms-reply.txt");
   command = _mongocrypt_tester_file (tester, "./test/example/command.json");
   marked_reply =
      _mongocrypt_tester_file (tester, "./test/example/marked-reply.json");

   encryptor = mongocrypt_encryptor_new (mongocrypt);

   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS);
   mongocrypt_encryptor_add_ns (encryptor, "test.test");

   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);
   mongocrypt_encryptor_add_collection_info (encryptor, collection_info);

   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);
   mongocrypt_encryptor_add_markings (encryptor, marked_reply);

   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS);

   kb = mongocrypt_encryptor_get_key_broker (encryptor);
   BSON_ASSERT (kb);

   key_query = mongocrypt_key_broker_get_key_filter (kb);

   /* check that the key query has the form { _id: $in : [ ] }. */
   _mongocrypt_buffer_from_binary (&tmp_buf, key_query);
   _mongocrypt_buffer_to_bson (&tmp_buf, &tmp);
   bson_iter_init (&iter, &tmp);
   BSON_ASSERT (bson_iter_find_descendant (&iter, "_id.$in.0", &iter));

   ASSERT_OR_PRINT (mongocrypt_key_broker_add_key (kb, key_document),
                    mongocrypt_key_broker_status (kb));
   mongocrypt_key_broker_done_adding_keys (kb);

   key_decryptor = mongocrypt_key_broker_next_decryptor (kb);

   int bytes_needed =
      mongocrypt_key_decryptor_bytes_needed (key_decryptor, 1024);

   while (bytes_needed > 0) {
      /* feed the whole reply */
      BSON_ASSERT (mongocrypt_key_decryptor_feed (key_decryptor, kms_reply));
      bytes_needed =
         mongocrypt_key_decryptor_bytes_needed (key_decryptor, 1024);
   }
   mongocrypt_key_broker_add_decrypted_key (kb, key_decryptor);
   mongocrypt_encryptor_key_broker_done (encryptor);

   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION);
   mongocrypt_encryptor_encrypt (encryptor);

   _mongocrypt_buffer_from_binary (
      &tmp_buf, mongocrypt_encryptor_encrypted_cmd (encryptor));
   _mongocrypt_buffer_to_bson (&tmp_buf, &tmp);
   CRYPT_TRACEF (&mongocrypt->log, "encrypted to: %s", tmp_json (&tmp));

   mongocrypt_destroy (mongocrypt);
   mongocrypt_binary_destroy (command);
   mongocrypt_binary_destroy (marked_reply);
   mongocrypt_binary_destroy (kms_reply);
   mongocrypt_binary_destroy (key_document);
   mongocrypt_binary_destroy (collection_info);
}

void
_mongocrypt_tester_install_encryptor (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_encryptor);
}