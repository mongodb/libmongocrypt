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
#include <assert.h>

#include <bson/bson.h>
#include <mongocrypt.h>

static void
_load_json_as_bson (const char *path, bson_t *as_bson)
{
   bson_error_t error;
   bson_json_reader_t *reader;

   reader = bson_json_reader_new_from_file (path, &error);
   if (!reader) {
      fprintf (stderr, "could not open: %s\n", path);
      abort ();
   }
   bson_init (as_bson);
   if (!bson_json_reader_read (reader, as_bson, &error)) {
      fprintf (stderr, "could not read json from: %s\n", path);
      abort ();
   }

   bson_json_reader_destroy (reader);
}

static mongocrypt_binary_t *
_read_json (const char *path, uint8_t **data)
{
   bson_t as_bson;
   uint32_t len;

   _load_json_as_bson (path, &as_bson);

   *data = bson_destroy_with_steal (&as_bson, true, &len);
   return mongocrypt_binary_new_from_data (*data, len);
}

static mongocrypt_binary_t *
_read_http (const char *path, uint8_t **data)
{
   int fd;
   char *contents = NULL;
   int n_read;
   int filesize = 0;
   char storage[512];
   int i;
   uint32_t len;

   fd = open (path, O_RDONLY);
   while ((n_read = read (fd, storage, sizeof (storage))) > 0) {
      filesize += n_read;
      contents = bson_realloc (contents, filesize);
      memcpy (contents + (filesize - n_read), storage, n_read);
   }

   if (n_read < 0) {
      fprintf (stderr, "failed to read %s\n", path);
      abort ();
   }

   close (fd);
   len = 0;

   /* Copy and fix newlines: \n becomes \r\n. */
   *data = bson_malloc0 (filesize * 2);
   for (i = 0; i < filesize; i++) {
      if (contents[i] == '\n' && contents[i - 1] != '\r') {
         (*data)[len++] = '\r';
      }
      (*data)[len++] = contents[i];
   }

   bson_free (contents);
   return mongocrypt_binary_new_from_data (*data, len);
}

static void
_print_binary_as_bson (mongocrypt_binary_t *binary)
{
   bson_t as_bson;
   char *str;

   BSON_ASSERT (binary);

   bson_init_static (&as_bson,
                     mongocrypt_binary_data (binary),
                     mongocrypt_binary_len (binary));
   str = bson_as_json (&as_bson, NULL);
   printf ("%s\n", str);
   bson_free (str);
}

static void
_print_binary_as_text (mongocrypt_binary_t *binary)
{
   uint32_t i;
   uint8_t *ptr;

   ptr = (uint8_t *) mongocrypt_binary_data (binary);
   for (i = 0; i < mongocrypt_binary_len (binary); i++) {
      if (ptr[i] == '\r')
         printf ("\\r");
      else if (ptr[i] == '\n')
         printf ("\\n");
      else
         printf ("%c", (char) ptr[i]);
   }
   printf ("\n");
}

#define CHECK(stmt) \
   if (!stmt) {     \
      continue;     \
   }

static mongocrypt_binary_t *
_run_state_machine (mongocrypt_ctx_t *ctx)
{
   mongocrypt_binary_t *input, *output = NULL;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_ctx_state_t state;
   mongocrypt_status_t *status;
   uint8_t *data;
   bool done;

   done = false;
   status = mongocrypt_status_new ();

   output = mongocrypt_binary_new ();

   while (!done) {
      state = mongocrypt_ctx_state (ctx);
      switch (state) {
      case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
         CHECK (mongocrypt_ctx_mongo_op (ctx, output));
         printf ("\nrunning listCollections on mongod with this filter:\n");
         _print_binary_as_bson (output);
         printf ("\nmocking reply from file:\n");
         input = _read_json ("./test/example/collection-info.json", &data);
         _print_binary_as_bson (input);
         CHECK (mongocrypt_ctx_mongo_feed (ctx, input));
         mongocrypt_binary_destroy (input);
         bson_free (data);
         CHECK (mongocrypt_ctx_mongo_done (ctx));

         mongocrypt_binary_destroy (output);
         output = mongocrypt_binary_new ();

         break;
      case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
         CHECK (mongocrypt_ctx_mongo_op (ctx, output));
         printf ("\nrunning cmd on mongocryptd with this schema:\n");
         _print_binary_as_bson (output);
         printf ("\nmocking reply from file:\n");
         input = _read_json ("./test/example/mongocryptd-reply.json", &data);
         _print_binary_as_bson (input);
         CHECK (mongocrypt_ctx_mongo_feed (ctx, input));
         mongocrypt_binary_destroy (input);
         bson_free (data);
         CHECK (mongocrypt_ctx_mongo_done (ctx));

         mongocrypt_binary_destroy (output);
         output = mongocrypt_binary_new ();

         break;
      case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
         CHECK (mongocrypt_ctx_mongo_op (ctx, output));
         printf ("\nrunning a find on the key vault coll with this filter:\n");
         _print_binary_as_bson (output);
         printf ("\nmocking reply from file:\n");
         input = _read_json ("./test/example/key-document.json", &data);
         _print_binary_as_bson (input);
         CHECK (mongocrypt_ctx_mongo_feed (ctx, input));
         mongocrypt_binary_destroy (input);
         bson_free (data);

         mongocrypt_binary_destroy (output);
         output = mongocrypt_binary_new ();

         CHECK (mongocrypt_ctx_mongo_done (ctx));
         break;
      case MONGOCRYPT_CTX_NEED_KMS:
         while ((kms = mongocrypt_ctx_next_kms_ctx (ctx))) {
            CHECK (mongocrypt_kms_ctx_message (kms, output));
            printf ("\nsending the following to kms:\n");
            _print_binary_as_text (output);
            printf ("\nmocking reply from file\n");
            input = _read_http ("./test/example/kms-decrypt-reply.txt", &data);
            _print_binary_as_text (input);
            CHECK (mongocrypt_kms_ctx_feed (kms, input));
            mongocrypt_binary_destroy (input);

            mongocrypt_binary_destroy (output);
            output = mongocrypt_binary_new ();

            bson_free (data);
            assert (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
         }
         mongocrypt_ctx_kms_done (ctx);
         break;
      case MONGOCRYPT_CTX_READY:
         CHECK (mongocrypt_ctx_finalize (ctx, output));
         printf ("\nfinal bson is:\n");
         _print_binary_as_bson (output);
         break;
      case MONGOCRYPT_CTX_DONE:
         done = true;
         break;
      case MONGOCRYPT_CTX_NOTHING_TO_DO:
         printf ("\nnothing to do\n");
         done = true;
         break;
      case MONGOCRYPT_CTX_ERROR:
         mongocrypt_ctx_status (ctx, status);
         printf ("\ngot error: %s\n", mongocrypt_status_message (status, NULL));
         done = true;
         break;
      case MONGOCRYPT_CTX_WAITING:
         printf ("\nunexpected waiting state\n");
         done = true;
         break;
      }
   }

   mongocrypt_status_destroy (status);

   return output;
}


static mongocrypt_binary_t *
_iter_to_binary (bson_iter_t *iter)
{
   uint8_t *data;
   uint32_t len;

   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (iter));
   bson_iter_binary (iter, NULL, &len, (const uint8_t **) &data);
   return mongocrypt_binary_new_from_data (data, len);
}


int
main ()
{
   bson_iter_t iter;
   mongocrypt_binary_t *output = NULL;
   mongocrypt_binary_t *encrypted_doc = NULL;
   bson_t key_doc;
   bson_t *wrapped;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_ctx_t *explicit_decrypt_ctx;
   mongocrypt_binary_t *msg;
   mongocrypt_binary_t *key_id;
   mongocrypt_binary_t *input;
   uint8_t *data;

   printf ("******* ENCRYPTION *******\n\n");

   crypt = mongocrypt_new ();
   mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1);
   if (!mongocrypt_init (crypt)) {
      mongocrypt_status_t *status;
      status = mongocrypt_status_new ();
      mongocrypt_status (crypt, status);
      fprintf (stderr, "failed to initialize");
      abort ();
   }

   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_encrypt_init (ctx, "test.test", -1);
   output = _run_state_machine (ctx);
   mongocrypt_binary_destroy (output);
   mongocrypt_ctx_destroy (ctx);

   printf ("\n******* DECRYPTION *******\n\n");
   ctx = mongocrypt_ctx_new (crypt);
   input = _read_json ("./test/example/encrypted-document.json", &data);
   mongocrypt_ctx_decrypt_init (ctx, input);
   mongocrypt_binary_destroy (input);
   output = _run_state_machine (ctx);
   mongocrypt_binary_destroy (output);

   mongocrypt_ctx_destroy (ctx);

   printf ("\n******* EXPLICIT ENCRYPTION *******\n");

   ctx = mongocrypt_ctx_new (crypt);

   /* Explicit encryption requires a key_id option */
   _load_json_as_bson ("./test/example/key-document.json", &key_doc);
   bson_iter_init_find (&iter, &key_doc, "_id");
   key_id = _iter_to_binary (&iter);
   mongocrypt_ctx_setopt_key_id (ctx, key_id);
   bson_destroy (&key_doc);
   mongocrypt_ctx_setopt_algorithm (
      ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Randomized", -1);

   wrapped = BCON_NEW ("v", "hello");
   msg = mongocrypt_binary_new_from_data ((uint8_t *) bson_get_data (wrapped),
                                          wrapped->len);
   mongocrypt_ctx_explicit_encrypt_init (ctx, msg);
   mongocrypt_binary_destroy (msg);
   encrypted_doc = _run_state_machine (ctx);

   printf ("\n******* EXPLICIT DECRYPTION *******\n");

   explicit_decrypt_ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (explicit_decrypt_ctx, encrypted_doc);

   output = _run_state_machine (explicit_decrypt_ctx);

   mongocrypt_ctx_destroy (explicit_decrypt_ctx);

   mongocrypt_ctx_destroy (ctx);
   bson_destroy (wrapped);
   bson_free (data);
   mongocrypt_binary_destroy (key_id);
   mongocrypt_binary_destroy (output);
   mongocrypt_binary_destroy (encrypted_doc);
   mongocrypt_destroy (crypt);
}
