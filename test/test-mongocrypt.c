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

#include "mongocrypt.h"
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
   mongocrypt_binary_t *to_return = mongocrypt_binary_new ();

   for (i = 0; i < tester->file_count; i++) {
      if (0 == strcmp (tester->file_paths[i], path)) {
         _mongocrypt_buffer_to_binary (&tester->file_bufs[i], to_return);
         return to_return;
      }
   }

   /* File not found, load it. */
   if (strstr (path, ".json")) {
      _load_json (tester, path);
   } else if (strstr (path, ".txt")) {
      _load_http (tester, path);
   }

   _mongocrypt_buffer_to_binary (&tester->file_bufs[tester->file_count - 1],
                                 to_return);
   return to_return;
}


void
_mongocrypt_tester_satisfy_kms (_mongocrypt_tester_t *tester,
                                mongocrypt_kms_ctx_t *kms)
{
   mongocrypt_binary_t *bin;

   bin = _mongocrypt_tester_file (tester, "./test/example/kms-reply.txt");
   mongocrypt_kms_ctx_feed (kms, bin);
   BSON_ASSERT (0 == mongocrypt_kms_ctx_bytes_needed (kms));
   mongocrypt_binary_destroy (bin);
}


/* Run the state machine on example data until hitting stop_state or a
 * terminal state. */
void
_mongocrypt_tester_run_ctx_to (_mongocrypt_tester_t *tester,
                               mongocrypt_ctx_t *ctx,
                               mongocrypt_ctx_state_t stop_state)
{
   mongocrypt_ctx_state_t state;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_binary_t *bin;

   state = mongocrypt_ctx_state (ctx);
   while (state != stop_state) {
      switch (state) {
      case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
         BSON_ASSERT (ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
         bin = _mongocrypt_tester_file (tester,
                                        "./test/example/collection-info.json");
         BSON_ASSERT (mongocrypt_ctx_mongo_feed (ctx, bin));
         BSON_ASSERT (mongocrypt_ctx_mongo_done (ctx));
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
         BSON_ASSERT (ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
         bin = _mongocrypt_tester_file (
            tester, "./test/example/mongocryptd-reply.json");
         BSON_ASSERT (mongocrypt_ctx_mongo_feed (ctx, bin));
         BSON_ASSERT (mongocrypt_ctx_mongo_done (ctx));
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
         bin = _mongocrypt_tester_file (tester,
                                        "./test/example/key-document.json");
         BSON_ASSERT (mongocrypt_ctx_mongo_feed (ctx, bin));
         BSON_ASSERT (mongocrypt_ctx_mongo_done (ctx));
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_CTX_NEED_KMS:
         kms = mongocrypt_ctx_next_kms_ctx (ctx);
         _mongocrypt_tester_satisfy_kms (tester, kms);
         BSON_ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx));
         mongocrypt_ctx_kms_done (ctx);
         break;
      case MONGOCRYPT_CTX_READY:
         bin = mongocrypt_binary_new ();
         state = mongocrypt_ctx_finalize (ctx, bin);
         mongocrypt_binary_destroy (bin);
         break;
      case MONGOCRYPT_CTX_NOTHING_TO_DO:
      case MONGOCRYPT_CTX_DONE:
      case MONGOCRYPT_CTX_ERROR:
         BSON_ASSERT (state == stop_state);
         return;
      }
      state = mongocrypt_ctx_state (ctx);
   }
   BSON_ASSERT (state == stop_state);
}


mongocrypt_binary_t *
_mongocrypt_tester_encrypted_doc (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;

   bin = mongocrypt_binary_new ();
   if (!_mongocrypt_buffer_empty (&tester->encrypted_doc)) {
      _mongocrypt_buffer_to_binary (&tester->encrypted_doc, bin);
      return bin;
   }

   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_init (crypt, NULL), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx);

   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   bin = mongocrypt_binary_new ();
   mongocrypt_ctx_finalize (ctx, bin);
   _mongocrypt_buffer_copy_from_binary (&tester->encrypted_doc, bin);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   _mongocrypt_buffer_to_binary (&tester->encrypted_doc, bin);
   return bin;
}


void
_mongocrypt_tester_fill_buffer (_mongocrypt_buffer_t *buf, int n)
{
   uint8_t i;

   memset (buf, 0, sizeof (*buf));
   buf->data = bson_malloc (n);
   for (i = 0; i < n; i++) {
      buf->data[i] = i;
   }
   buf->len = n;
   buf->owned = true;
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
   _mongocrypt_tester_install_ctx_encrypt (&tester);
   _mongocrypt_tester_install_ctx_decrypt (&tester);
   _mongocrypt_tester_install_ciphertext (&tester);
   _mongocrypt_tester_install_key_broker (&tester);

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
