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
#include "mongocrypt-key-query-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-opts-private.h"

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


static void
_spawn_mongocryptd (void)
{
/* oddly, starting mongocryptd in libmongoc starts multiple instances. */
#ifdef SPAWN_BUG_FIXED
   pid_t pid = fork ();

   CRYPT_ENTRY;
   CRYPT_TRACE ("spawning mongocryptd\n");
   if (pid == 0) {
      int ret;
      /* child */
      CRYPT_TRACE ("child starting mongocryptd\n");
      ret = execlp ("mongocryptd", "mongocryptd", (char *) NULL);
      if (ret == -1) {
         MONGOC_ERROR ("child process unable to exec mongocryptd");
         abort ();
      }
   }
#endif
}


void
mongocrypt_init ()
{
   mongoc_init ();
   kms_message_init ();
}


void
mongocrypt_cleanup ()
{
   mongoc_cleanup ();
   kms_message_cleanup ();
}



mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status)
{
   mongocrypt_t *crypt = NULL;
   mongoc_uri_t *uri = NULL;
   bool success = false;

   CRYPT_ENTRY;
   BSON_ASSERT (opts);
   BSON_ASSERT (status);
   _spawn_mongocryptd ();
   crypt = bson_malloc0 (sizeof (mongocrypt_t));

   if (opts->mongocryptd_uri) {
      uri = mongoc_uri_new (opts->mongocryptd_uri);
      if (!uri) {
         CLIENT_ERR ("invalid uri for mongocryptd");
         goto fail;
      }
      crypt->mongocryptd_pool = mongoc_client_pool_new (uri);
   } else {
      uri = mongoc_uri_new ("mongodb://%2Ftmp%2Fmongocryptd.sock");
      BSON_ASSERT (uri);
      crypt->mongocryptd_pool = mongoc_client_pool_new (uri);
   }

   if (!crypt->mongocryptd_pool) {
      CLIENT_ERR ("Unable to create client to mongocryptd");
      goto fail;
   }

   mongoc_client_pool_set_error_api (crypt->mongocryptd_pool,
                                     MONGOC_ERROR_API_VERSION_2);
   crypt->opts = mongocrypt_opts_copy (opts);
   mongocrypt_mutex_init (&crypt->mutex);

   crypt->cache = _mongocrypt_key_cache_new (_mongocrypt_kms_decrypt, crypt);
   success = true;

fail:
   mongoc_uri_destroy (uri);
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
   mongoc_client_pool_destroy (crypt->mongocryptd_pool);
   _mongocrypt_key_cache_destroy (crypt->cache);
   mongocrypt_mutex_destroy (&crypt->mutex);
   bson_free (crypt);
}


static bool
_collect_key_from_marking (void *ctx,
                           _mongocrypt_buffer_t *in,
                           mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking;
   mongocrypt_request_t *request;
   bson_t filter;
   mongocrypt_key_query_t *key_query;

   request = (mongocrypt_request_t *) ctx;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      return false;
   }

   /* TODO:
    * - Check if we already have the key in the key cache.
    * - Group key queries by key vault name. This just makes a new key query per
    * key.
    */

   /* If the key cache does not have the key, add a new key query. */
   key_query = &request->key_queries[request->num_key_queries++];
   bson_init (&key_query->filter);
   if (marking.key_id.len) {
      _mongocrypt_bson_append_buffer (
         &key_query->filter, "_id", 3, &marking.key_id);
   } else if (marking.key_alt_name) {
      bson_append_value (
         &key_query->filter, "keyAltName", 10, marking.key_alt_name);
   }
   key_query->filter_bin.data = (uint8_t *) bson_get_data (&key_query->filter);
   key_query->filter_bin.len = key_query->filter.len;
   key_query->keyvault_alias = bson_strdup (marking.keyvault_alias);
   return true;
}

mongocrypt_request_t *
mongocrypt_encrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *schema_in,
                          const mongocrypt_binary_t *cmd_in,
                          mongocrypt_status_t *status)
{
   bson_t schema, cmd;
   bson_t marking_cmd;
   bson_error_t bson_error;
   bool succeeded = false;
   mongoc_client_t *mongocryptd_client = NULL;
   mongocrypt_request_t *request = NULL;

   CRYPT_ENTRY;
   BSON_ASSERT (crypt);
   BSON_ASSERT (schema_in);
   BSON_ASSERT (cmd_in);
   BSON_ASSERT (status);
   bson_init_static (&schema, schema_in->data, schema_in->len);
   bson_init_static (&cmd, cmd_in->data, cmd_in->len);

   /* Construct the marking command to send. This consists of the original
    * command with the field "jsonSchema" added. */
   bson_copy_to (&cmd, &marking_cmd);
   bson_append_document (&marking_cmd, "jsonSchema", 10, &schema);
   mongocryptd_client = mongoc_client_pool_pop (crypt->mongocryptd_pool);
   CRYPT_TRACE ("=> marking cmd to mongocryptd:\n\t%s",
                tmp_json (&marking_cmd));
   request = bson_malloc0 (sizeof (mongocrypt_request_t));
   request->crypt = crypt;
   request->type = MONGOCRYPT_REQUEST_ENCRYPT;

   if (!mongoc_client_command_simple (mongocryptd_client,
                                      "admin",
                                      &marking_cmd,
                                      NULL /* read prefs */,
                                      &request->mongocryptd_reply,
                                      &bson_error)) {
      MONGOCRYPTD_ERR_W_REPLY (bson_error, &request->mongocryptd_reply);
      goto fail;
   }

   CRYPT_TRACE ("<= mongocryptd replied:\n\t%s",
                tmp_json (&request->mongocryptd_reply));

   if (!_mongocryptd_marking_reply_parse (
          &request->mongocryptd_reply, request, status)) {
      goto fail;
   }

   if (request->has_encryption_placeholders) {
      if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_marking,
                                                (void *) request,
                                                0,
                                                request->result_iter,
                                                status)) {
         goto fail;
      }
   }

   succeeded = true;

fail:
   bson_destroy (&marking_cmd);
   if (mongocryptd_client) {
      mongoc_client_pool_push (crypt->mongocryptd_pool, mongocryptd_client);
   }
   bson_destroy (&schema);
   bson_destroy (&cmd);
   if (!succeeded) {
      mongocrypt_request_destroy (request);
      request = NULL;
   }
   return request;
}

/* From Driver's spec:
struct fle_blob {
 uint8  fle_blob_subtype = (1 or 2);
 uint16 key_vault_alias_length;
 uint8  key_vault_alias[key_vault_alias_length];
 uint8  key_uuid[16];
 uint8  original_bson_type;
 uint8  iv[16];
 uint32 ciphertext_length;
 uint8  ciphertext[ciphertext_length];
}
*/
void
_serialize_ciphertext (_mongocrypt_ciphertext_t *ciphertext,
                       _mongocrypt_buffer_t *out)
{
   uint32_t offset;

   BSON_ASSERT (ciphertext);
   BSON_ASSERT (out);
   /* TODO: serialize with respect to endianness. Move this to
    * mongocrypt-parsing.c? Check mongoc scatter/gatter for inspiration. */
   out->len = 1 + 2 + ciphertext->keyvault_alias_len + 16 + 1 + 16 + 4 +
              ciphertext->data.len;
   out->data = bson_malloc0 (out->len);
   offset = 0;

   out->data[offset] = '\01'; /* TODO: account for randomized. */
   offset += 1;

   memcpy (out->data + offset, &ciphertext->keyvault_alias_len, 2);
   offset += 2;

   memcpy (out->data + offset,
           ciphertext->keyvault_alias,
           ciphertext->keyvault_alias_len);
   offset += ciphertext->keyvault_alias_len;

   BSON_ASSERT (ciphertext->key_id.len == 16);
   memcpy (out->data + offset, ciphertext->key_id.data, 16);
   offset += 16;

   /* TODO: ciphertext is just a document: { '': <value> } for now. */
   out->data[offset] = '\05';
   offset += 1;

   BSON_ASSERT (ciphertext->iv.len == 16);
   memcpy (out->data + offset, ciphertext->iv.data, 16);
   offset += 16;

   memcpy (out->data + offset, &ciphertext->data.len, 4);
   offset += 4;

   memcpy (out->data + offset, ciphertext->data.data, ciphertext->data.len);
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
_replace_marking_with_ciphertext (void *ctx,
                                  _mongocrypt_buffer_t *in,
                                  bson_value_t *out,
                                  mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ciphertext_t ciphertext = {0};
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   _mongocrypt_buffer_t plaintext = {0};
   mongocrypt_request_t *request;
   bson_t wrapper = BSON_INITIALIZER;
   const _mongocrypt_key_t *key;
   bool ret;
   uint32_t bytes_written;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   BSON_ASSERT (status);
   request = (mongocrypt_request_t *) ctx;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      goto fail;
   }

   if (marking.key_alt_name) {
      CLIENT_ERR ("TODO looking up key by keyAltName not yet supported");
      goto fail;
   }

   memcpy (&ciphertext.iv, &marking.iv, sizeof (_mongocrypt_buffer_t));

   /* get the key for this marking. */
   key =
      _mongocrypt_key_cache_get_by_id (request->crypt->cache, &marking.key_id, status);
   if (!key) {
      goto fail;
   }

   CRYPT_TRACE ("performing encryption");
   bson_append_iter (&wrapper, "", 0, &marking.v_iter);

   plaintext.data = (uint8_t *) bson_get_data (&wrapper);
   plaintext.len = wrapper.len;

   printf ("Encrypting:");
   _print_bin (&plaintext);
   ciphertext.data.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext.data.data = bson_malloc (ciphertext.data.len);
   ciphertext.data.owned = true;
   ret = _mongocrypt_do_encryption (&ciphertext.iv,
                                    NULL,
                                    &key->data_key,
                                    &plaintext,
                                    &ciphertext.data,
                                    &bytes_written,
                                    status);
   if (!ret) {
      goto fail;
   }
   BSON_ASSERT (bytes_written == ciphertext.data.len);
   printf ("to:");
   _print_bin (&ciphertext.data);

   memcpy (&ciphertext.key_id, &marking.key_id, sizeof (_mongocrypt_buffer_t));
   ciphertext.keyvault_alias = marking.keyvault_alias;
   ciphertext.keyvault_alias_len = strlen (marking.keyvault_alias);
   _serialize_ciphertext (&ciphertext, &serialized_ciphertext);

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = 6;

   ret = true;

fail:
   bson_free (ciphertext.data.data);
   bson_destroy (&wrapper);
   return ret;
}


bool
mongocrypt_encrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t *encrypted_out,
                           mongocrypt_status_t *status)
{
   int ret = false;
   bson_t out = BSON_INITIALIZER;

   BSON_ASSERT (request);
   BSON_ASSERT (encrypted_out);
   BSON_ASSERT (status);

   ret = _mongocrypt_transform_binary_in_bson (_replace_marking_with_ciphertext,
                                               request,
                                               0,
                                               request->result_iter,
                                               &out,
                                               status);
   if (!ret) {
      bson_destroy (&out);
      goto fail;
   }

   encrypted_out->data =
      bson_destroy_with_steal (&out, true, &encrypted_out->len);

   ret = true;
fail:
   return ret;
}


static bool
_collect_key_from_ciphertext (void *ctx,
                              _mongocrypt_buffer_t *in,
                              mongocrypt_status_t *status)
{
   _mongocrypt_ciphertext_t ciphertext;
   mongocrypt_request_t *request;
   bson_t filter;
   mongocrypt_key_query_t *key_query;

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
   key_query = &request->key_queries[request->num_key_queries++];
   bson_init (&key_query->filter);
   _mongocrypt_bson_append_buffer (
      &key_query->filter, "_id", 3, &ciphertext.key_id);
   key_query->filter_bin.data = (uint8_t *) bson_get_data (&key_query->filter);
   key_query->filter_bin.len = key_query->filter.len;
   key_query->keyvault_alias =
      bson_strndup (ciphertext.keyvault_alias, ciphertext.keyvault_alias_len);
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
             _collect_key_from_ciphertext, request, 1, iter, status)) {
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
      request->crypt->cache, &ciphertext.key_id, status);
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
             iter,
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
