/*
 * Copyright 2018-present MongoDB, Inc.
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

#include <kms_message/kms_message.h>
#include <mongoc/mongoc.h>

#include "mongocrypt-binary.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-request-private.h"
#include "mongocrypt-schema-cache-private.h"
#include "mongocrypt-status-private.h"
#include "mongocrypt-log-private.h"

static void
_print_bin (_mongocrypt_buffer_t *buf)
{
   uint32_t i;

   for (i = 0; i < buf->len; i++) {
      printf ("%02x", buf->data[i]);
   }
   printf ("\n");
}

const char *
mongocrypt_version (void)
{
   return MONGOCRYPT_VERSION;
}

void
_mongocrypt_set_error (mongocrypt_status_t *status,
                       uint32_t type,
                       uint32_t code,
                       const char *format,
                       ...)
{
   va_list args;

   if (status) {
      status->type = type;
      status->code = code;

      va_start (args, format);
      bson_vsnprintf (status->message, sizeof status->message, format, args);
      va_end (args);

      status->message[sizeof status->message - 1] = '\0';
   }
}


void
_bson_error_to_mongocrypt_error (const bson_error_t *bson_error,
                                 uint32_t type,
                                 uint32_t code,
                                 mongocrypt_status_t *status)
{
   _mongocrypt_set_error (status, type, code, "%s", bson_error->message);
}


const char *
tmp_json (const bson_t *bson)
{
   static char storage[1024];
   char *json;

   memset (storage, 0, 1024);
   json = bson_as_json (bson, NULL);
   bson_snprintf (storage, sizeof (storage), "%s", json);
   bson_free (json);
   return (const char *) storage;
}


const char *
tmp_buf (const _mongocrypt_buffer_t *buf)
{
   static char storage[1024];
   int i, n;

   memset (storage, 0, 1024);
   /* capped at two characters per byte, minus 1 for trailing \0 */
   n = sizeof (storage) / 2 - 1;
   if (buf->len < n) {
      n = buf->len;
   }

   for (i = 0; i < n; i++) {
      bson_snprintf (storage + (i * 2), 3, "%02x", buf->data[i]);
   }

   return (const char *) storage;
}


MONGOCRYPT_ONCE_FUNC (_mongocrypt_do_init)
{
   kms_message_init ();
   _mongocrypt_log_init ();
   MONGOCRYPT_ONCE_RETURN;
}


void
mongocrypt_init (const mongocrypt_opts_t *opts)
{
   static mongocrypt_once_t once = MONGOCRYPT_ONCE_INIT;
   mongocrypt_once (&once, _mongocrypt_do_init);
   if (opts && opts->log_fn) {
      _mongocrypt_log_set_fn (opts->log_fn, opts->log_ctx);
   }
}


void
mongocrypt_cleanup ()
{
   kms_message_cleanup ();
}


mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status)
{
   mongocrypt_t *crypt = NULL;
   bool success = false;

   CRYPT_ENTRY;

   crypt = bson_malloc0 (sizeof (mongocrypt_t));

   crypt->opts = mongocrypt_opts_copy (opts);
   mongocrypt_mutex_init (&crypt->mutex);

   crypt->schema_cache = _mongocrypt_schema_cache_new ();

   success = true;

fail:
   if (!success) {
      mongocrypt_destroy (crypt);
      crypt = NULL;
   }
   return crypt;
}


void
mongocrypt_destroy (mongocrypt_t *crypt)
{
   CRYPT_ENTRY;
   if (!crypt) {
      return;
   }
   mongocrypt_opts_destroy (crypt->opts);
   _mongocrypt_schema_cache_destroy (crypt->schema_cache);
   _mongocrypt_key_cache_destroy (crypt->key_cache);
   mongocrypt_mutex_destroy (&crypt->mutex);
   bson_free (crypt);
}


bool
_parse_ciphertext_unowned (_mongocrypt_buffer_t *in,
                           _mongocrypt_ciphertext_t *ciphertext,
                           mongocrypt_status_t *status)
{
   uint32_t offset;
   /* TODO: serialize with respect to endianness. Move this to
    * mongocrypt-parsing.c? Check mongoc scatter/gatter for inspiration. */

   BSON_ASSERT (in);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);
   /* skip first byte */
   offset = 1;

   memcpy (&ciphertext->keyvault_alias_len, in->data + offset, 2);
   offset += 2;

   ciphertext->keyvault_alias = (char *) in->data + offset;
   offset += ciphertext->keyvault_alias_len;

   ciphertext->key_id.data = in->data + offset;
   ciphertext->key_id.len = 16;
   ciphertext->key_id.subtype = BSON_SUBTYPE_UUID;
   offset += 16;

   offset += 1; /* Original BSON type, skip for now. */

   ciphertext->iv.data = in->data + offset;
   ciphertext->iv.len = 16;
   ciphertext->iv.subtype = BSON_SUBTYPE_BINARY;
   offset += 16;

   memcpy (&ciphertext->data.len, in->data + offset, 4);
   offset += 4;

   ciphertext->data.data = in->data + offset;
   return true;
}


static bool
_collect_key_from_ciphertext (void *ctx,
                              _mongocrypt_buffer_t *in,
                              mongocrypt_status_t *status)
{
   _mongocrypt_ciphertext_t ciphertext;
   mongocrypt_request_t *request;
   bson_t filter;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (status);
   request = (mongocrypt_request_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      return false;
   }

   /* TODO: check key cache for the key ID. */
   /* If the key cache does not have the key, add a new key query. Also,
    * deduplicate requests! */
   return true;
}


mongocrypt_request_t *
mongocrypt_decrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *encrypted_docs,
                          uint32_t num_docs,
                          mongocrypt_status_t *status)
{
   mongocrypt_request_t *request;
   bool success = false;
   int i;

   BSON_ASSERT (crypt);
   BSON_ASSERT (encrypted_docs);
   BSON_ASSERT (status);

   request = bson_malloc0 (sizeof (mongocrypt_request_t));
   request->crypt = crypt;
   request->type = MONGOCRYPT_REQUEST_DECRYPT;
   request->num_input_docs = num_docs;
   request->encrypted_docs = encrypted_docs;

   for (i = 0; i < num_docs; i++) {
      bson_iter_t iter;
      bson_t bson;

      bson_init_static (&bson, encrypted_docs[i].data, encrypted_docs[i].len);
      bson_iter_init (&iter, &bson);
      if (!_mongocrypt_traverse_binary_in_bson (
             _collect_key_from_ciphertext, request, 1, &iter, status)) {
         goto fail;
      }
   }

   success = true;

fail:
   if (!success) {
      mongocrypt_request_destroy (request);
      request = NULL;
   }

   return request;
}

static bool
_replace_ciphertext_with_plaintext (void *ctx,
                                    _mongocrypt_buffer_t *in,
                                    bson_value_t *out,
                                    mongocrypt_status_t *status)
{
   mongocrypt_request_t *request;
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t plaintext = {0};
   bson_t wrapper;
   bson_iter_t iter;
   const _mongocrypt_key_t *key;
   uint32_t bytes_written;
   bool ret = false;

   CRYPT_ENTRY;
   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   BSON_ASSERT (status);

   request = (mongocrypt_request_t *) ctx;
   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      goto fail;
   }

   /* look up the key */
   key = _mongocrypt_key_cache_get_by_id (
      request->crypt->key_cache, &ciphertext.key_id, status);
   if (!key) {
      goto fail;
   }

   printf ("Decrypting:");
   _print_bin (&ciphertext.data);
   plaintext.len = ciphertext.data.len;
   plaintext.data = bson_malloc0 (plaintext.len);
   plaintext.owned = true;
   if (!_mongocrypt_do_decryption (NULL,
                                   &key->data_key,
                                   &ciphertext.data,
                                   &plaintext,
                                   &bytes_written,
                                   status)) {
      goto fail;
   }
   plaintext.len = bytes_written;
   printf ("To:");
   _print_bin (&plaintext);

   bson_init_static (&wrapper, plaintext.data, plaintext.len);
   bson_iter_init_find (&iter, &wrapper, "");
   bson_value_copy (bson_iter_value (&iter), out);
   ret = true;

fail:
   bson_free (plaintext.data);
   return true;
}

bool
mongocrypt_decrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t **docs,
                           mongocrypt_status_t *status)
{
   int i;
   mongocrypt_binary_t *results;
   bool ret = false;

   CRYPT_ENTRY;
   results =
      bson_malloc0 (sizeof (mongocrypt_binary_t) * request->num_input_docs);

   for (i = 0; i < request->num_input_docs; i++) {
      bson_iter_t iter;
      bson_t bson, out = BSON_INITIALIZER;

      bson_init_static (&bson,
                        request->encrypted_docs[i].data,
                        request->encrypted_docs[i].len);
      bson_iter_init (&iter, &bson);
      if (!_mongocrypt_transform_binary_in_bson (
             _replace_ciphertext_with_plaintext,
             request,
             1,
             &iter,
             &out,
             status)) {
         goto fail;
      }
      results[i].data = bson_destroy_with_steal (&out, true, &results[i].len);
   }

   *docs = results;

   ret = true;

fail:
   if (!ret) {
      for (i = 0; i < request->num_input_docs; i++) {
         bson_free (results[i].data);
      }
      bson_free (results);
   }
   return ret;
}
