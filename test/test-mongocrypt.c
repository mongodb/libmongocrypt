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

#include <stdio.h>
#include <stdlib.h>

#include <bson/bson.h>
#include <mongocrypt.h>
#include <mongocrypt-key-broker.h>

#include "test-mongocrypt.h"


/* Return a repeated character with no null terminator. */
char *
_mongocrypt_repeat_char (char c, uint32_t times)
{
   char *result;
   uint32_t i;

   result = bson_malloc (times);
   for (i = 0; i < times; i++) {
      result[i] = c;
   }

   return result;
}


static void
_load_json (_mongocrypt_tester_t *tester, const char *path)
{
   bson_error_t error;
   bson_json_reader_t *reader;
   bson_t as_bson;
   bool ret;
   _mongocrypt_buffer_t *buf;

   reader = bson_json_reader_new_from_file (path, &error);
   ASSERT_OR_PRINT_BSON (reader, error);
   bson_init (&as_bson);
   ret = bson_json_reader_read (reader, &as_bson, &error);
   ASSERT_OR_PRINT_BSON (ret, error);

   buf = &tester->file_bufs[tester->file_count];
   _mongocrypt_buffer_steal_from_bson (buf, &as_bson);
   tester->file_paths[tester->file_count] = bson_strdup (path);
   tester->file_count++;
}


static void
_load_http (_mongocrypt_tester_t *tester, const char *path)
{
   int fd;
   char *contents;
   int n_read;
   int filesize;
   char storage[512];
   int i;
   _mongocrypt_buffer_t *buf;

   filesize = 0;
   contents = NULL;
   fd = open (path, O_RDONLY);
   while ((n_read = read (fd, storage, sizeof (storage))) > 0) {
      filesize += n_read;
      /* Append storage. Performance does not matter. */
      contents = bson_realloc (contents, filesize);
      memcpy (contents + (filesize - n_read), storage, n_read);
   }

   if (n_read < 0) {
      fprintf (stderr, "failed to read %s\n", path);
      abort ();
   }

   close (fd);

   buf = &tester->file_bufs[tester->file_count];
   /* copy and fix newlines */
   _mongocrypt_buffer_init (buf);
   /* allocate twice the size since \n may become \r\n */
   buf->data = bson_malloc0 (filesize * 2);
   buf->len = 0;
   buf->owned = true;
   for (i = 0; i < filesize; i++) {
      if (contents[i] == '\n' && contents[i - 1] != '\r') {
         buf->data[buf->len++] = '\r';
      }
      buf->data[buf->len++] = contents[i];
   }

   bson_free (contents);
   tester->file_paths[tester->file_count] = bson_strdup (path);
   tester->file_count++;
}


void
_mongocrypt_tester_install (_mongocrypt_tester_t *tester,
                            char *name,
                            _mongocrypt_test_fn fn)
{
   tester->test_fns[tester->test_count] = fn;
   tester->test_names[tester->test_count] = bson_strdup (name);
   tester->test_count++;
}


mongocrypt_binary_t *
_mongocrypt_tester_file (_mongocrypt_tester_t *tester, const char *path)
{
   int i;

   for (i = 0; i < tester->file_count; i++) {
      if (0 == strcmp (tester->file_paths[i], path)) {
         return _mongocrypt_buffer_to_binary (&tester->file_bufs[i]);
      }
   }

   /* File not found, load it. */
   if (strstr (path, ".json")) {
      _load_json (tester, path);
   } else if (strstr (path, ".txt")) {
      _load_http (tester, path);
   }

   return _mongocrypt_buffer_to_binary (
      &tester->file_bufs[tester->file_count - 1]);
}


/* Satisfy the key requests of a key broker using example data. */
void
_mongocrypt_tester_satisfy_key_broker (_mongocrypt_tester_t *tester,
                                       mongocrypt_key_broker_t *key_broker)
{
   mongocrypt_binary_t *bin;
   mongocrypt_key_decryptor_t *key_decryptor;

   /* Add the single key document. */
   bin = _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   BSON_ASSERT (mongocrypt_key_broker_add_key (key_broker, bin));
   mongocrypt_binary_destroy (bin);
   mongocrypt_key_broker_done_adding_keys (key_broker);

   /* Decrypt the key material. */
   key_decryptor = mongocrypt_key_broker_next_decryptor (key_broker);
   bin = _mongocrypt_tester_file (tester, "./test/example/kms-reply.txt");
   BSON_ASSERT (mongocrypt_key_decryptor_feed (key_decryptor, bin));
   mongocrypt_binary_destroy (bin);
   BSON_ASSERT (0 == mongocrypt_key_decryptor_bytes_needed (key_decryptor, 1));
   BSON_ASSERT (mongocrypt_key_broker_add_decrypted_key (key_broker, key_decryptor));
   BSON_ASSERT (!mongocrypt_key_broker_next_decryptor (key_broker));
}


mongocrypt_binary_t* _mongocrypt_tester_encrypted_doc (_mongocrypt_tester_t* tester) {
   mongocrypt_t* crypt;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_status_t *status;
   mongocrypt_binary_t *tmp;

   if (!_mongocrypt_buffer_empty(&tester->encrypted_doc)) {
      return _mongocrypt_buffer_to_binary (&tester->encrypted_doc);
   }

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new (NULL);
   ASSERT_OR_PRINT (crypt, status);

   encryptor = mongocrypt_encryptor_new (crypt);
   _mongocrypt_tester_run_encryptor_to (tester, encryptor, MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED);
   tmp = mongocrypt_encryptor_encrypted_cmd (encryptor);
   _mongocrypt_buffer_copy_from_binary (&tester->encrypted_doc, tmp);
   mongocrypt_binary_destroy (tmp);
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_destroy (crypt);
   return _mongocrypt_buffer_to_binary (&tester->encrypted_doc);
}


int
main (int argc, char **argv)
{
   _mongocrypt_tester_t tester = {0};
   int i;

   printf ("Pass a list of test names to run only specific tests. E.g.:\n");
   printf ("test-mongocrypt _mongocrypt_test_mcgrew\n\n");

   /* Install all tests. */
   _mongocrypt_tester_install_crypto (&tester);
   _mongocrypt_tester_install_log (&tester);
   _mongocrypt_tester_install_data_key (&tester);
   _mongocrypt_tester_install_encryptor (&tester);
   _mongocrypt_tester_install_ciphertext (&tester);
   _mongocrypt_tester_install_decryptor (&tester);

   printf ("Running tests...\n");
   for (i = 0; tester.test_names[i]; i++) {
      int j;
      bool found = false;

      if (argc > 1) {
         for (j = 1; j < argc; j++) {
            found = (0 == strcmp (argv[j], tester.test_names[i]));
            if (found)
               break;
         }
         if (!found) {
            continue;
         }
      }
      printf ("  begin %s\n", tester.test_names[i]);
      tester.test_fns[i](&tester);
      printf ("  end %s\n", tester.test_names[i]);
   }
   printf ("... done running tests\n");

   if (i == 0) {
      printf ("WARNING - no tests run.\n");
   }

   /* Clean up tester. */
   for (i = 0; i < tester.file_count; i++) {
      _mongocrypt_buffer_cleanup (&tester.file_bufs[i]);
   }
}
