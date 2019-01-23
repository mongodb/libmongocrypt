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

#include "mongocrypt-private.h"


char *
mongocrypt_version (void)
{
   return MONGOCRYPT_VERSION;
}


const char *
mongocrypt_error_message (mongocrypt_error_t *error)
{
   return error->message;
}


uint32_t
mongocrypt_error_code (mongocrypt_error_t *error)
{
   return error->code;
}


void *
mongocrypt_error_ctx (mongocrypt_error_t *error)
{
   return error->ctx;
}


void
mongocrypt_error_destroy (mongocrypt_error_t *error)
{
   if (!error) {
      return;
   }
   bson_free (error->ctx);
   bson_free (error);
}


void
_mongocrypt_set_error (mongocrypt_error_t **error,
                       uint32_t type,
                       uint32_t code,
                       const char *format,
                       ...)
{
   va_list args;

   if (error) {
      *error = bson_malloc (sizeof (mongocrypt_error_t));

      (*error)->type = type;
      (*error)->code = code;

      va_start (args, format);
      bson_vsnprintf (
         (*error)->message, sizeof (*error)->message, format, args);
      va_end (args);

      (*error)->message[sizeof (*error)->message - 1] = '\0';
   }
}


void
_bson_error_to_mongocrypt_error (const bson_error_t *bson_error,
                                 uint32_t type,
                                 uint32_t code,
                                 mongocrypt_error_t **error)
{
   _mongocrypt_set_error (error, type, code, "%s", bson_error->message);
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


mongocrypt_opts_t *
mongocrypt_opts_new (void)
{
   return bson_malloc0 (sizeof (mongocrypt_opts_t));
}


void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts)
{
   bson_free (opts->aws_region);
   bson_free (opts->aws_secret_access_key);
   bson_free (opts->aws_access_key_id);
   bson_free (opts->mongocryptd_uri);
   bson_free (opts->default_keyvault_client_uri);
   bson_free (opts);
}


static mongocrypt_opts_t *
mongocrypt_opts_copy (const mongocrypt_opts_t *src)
{
   mongocrypt_opts_t *dst = bson_malloc0 (sizeof (mongocrypt_opts_t));
   dst->aws_region = bson_strdup (src->aws_region);
   dst->aws_secret_access_key = bson_strdup (src->aws_secret_access_key);
   dst->aws_access_key_id = bson_strdup (src->aws_access_key_id);
   dst->mongocryptd_uri = bson_strdup (src->mongocryptd_uri);
   dst->default_keyvault_client_uri =
      bson_strdup (src->default_keyvault_client_uri);
   return dst;
}


void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value)
{
   switch (opt) {
   case MONGOCRYPT_AWS_REGION:
      opts->aws_region = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_AWS_SECRET_ACCESS_KEY:
      opts->aws_secret_access_key = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_AWS_ACCESS_KEY_ID:
      opts->aws_access_key_id = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_MONGOCRYPTD_URI:
      opts->mongocryptd_uri = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_DEFAULT_KEYVAULT_CLIENT_URI:
      opts->default_keyvault_client_uri = bson_strdup ((char *) value);
      break;
   default:
      fprintf (stderr, "Invalid option: %d\n", (int) opt);
      abort ();
   }
}


mongocrypt_t *
mongocrypt_new (mongocrypt_opts_t *opts, mongocrypt_error_t **error)
{
   /* store AWS credentials, init structures in client, store schema
    * somewhere. */
   mongocrypt_t *crypt;
   mongoc_uri_t *uri;

   CRYPT_ENTRY;
   BSON_ASSERT (*error == NULL);
   _spawn_mongocryptd ();
   crypt = bson_malloc0 (sizeof (mongocrypt_t));
   if (opts->mongocryptd_uri) {
      uri = mongoc_uri_new (opts->mongocryptd_uri);
      if (!uri) {
         CLIENT_ERR ("invalid uri for mongocryptd");
         mongocrypt_destroy (crypt);
         return NULL;
      }
      crypt->mongocryptd_pool = mongoc_client_pool_new (uri);
      mongoc_client_pool_set_error_api (crypt->mongocryptd_pool,
                                        MONGOC_ERROR_API_VERSION_2);
      mongoc_uri_destroy (uri);
   } else {
      uri = mongoc_uri_new ("mongodb://%2Ftmp%2Fmongocryptd.sock");
      BSON_ASSERT (uri);
      crypt->mongocryptd_pool = mongoc_client_pool_new (uri);
      mongoc_uri_destroy (uri);
   }
   if (!crypt->mongocryptd_pool) {
      CLIENT_ERR ("Unable to create client to mongocryptd");
      mongocrypt_destroy (crypt);
      return NULL;
   }
   /* TODO: use 'u' from schema to get key vault clients. Note no opts here. */
   /* TODO: don't create a key vault pool, request keys from the driver. */
   uri = mongoc_uri_new (opts->default_keyvault_client_uri);
   crypt->keyvault_pool = mongoc_client_pool_new (uri);
   mongoc_uri_destroy (uri);
   if (!crypt->keyvault_pool) {
      CLIENT_ERR ("Unable to create client to keyvault");
      mongocrypt_destroy (crypt);
      return NULL;
   }
   crypt->opts = mongocrypt_opts_copy (opts);
   mongocrypt_mutex_init (&crypt->mutex);
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
   mongoc_client_pool_destroy (crypt->keyvault_pool);
   mongocrypt_mutex_destroy (&crypt->mutex);
   bson_free (crypt);
}


/*
 * _get_key - to be removed, don't bother fixing.
*/
static bool
_get_key (mongocrypt_t *crypt,
          _mongocrypt_buffer_t *key_id,
          const char *key_alt_name,
          _mongocrypt_key_t *out,
          mongocrypt_error_t **error)
{
   mongoc_client_t *keyvault_client;
   mongoc_collection_t *datakey_coll = NULL;
   mongoc_cursor_t *cursor = NULL;
   bson_t filter;
   const bson_t *doc;
   bool ret = false;

   CRYPT_ENTRY;
   keyvault_client = mongoc_client_pool_pop (crypt->keyvault_pool);
   datakey_coll =
      mongoc_client_get_collection (keyvault_client, "admin", "datakeys");
   bson_init (&filter);
   if (key_id->len) {
      _mongocrypt_bson_append_buffer (&filter, "_id", 3, key_id);
   } else if (key_alt_name) {
      bson_append_utf8 (
         &filter, "keyAltName", 10, key_alt_name, (int) strlen (key_alt_name));
   } else {
      CLIENT_ERR ("must provide key id or alt name");
      bson_destroy (&filter);
      goto cleanup;
   }

   CRYPT_TRACE ("finding key by filter: %s", tmp_json (&filter));
   cursor =
      mongoc_collection_find_with_opts (datakey_coll, &filter, NULL, NULL);
   bson_destroy (&filter);

   if (!mongoc_cursor_next (cursor, &doc)) {
      CLIENT_ERR ("key not found");
      goto cleanup;
   }

   CRYPT_TRACE ("got key: %s\n", tmp_json (doc));
   if (!_mongocrypt_key_parse (doc, out, error)) {
      goto cleanup;
   }

   CRYPT_TRACE ("decrypting key_material");
   if (!_mongocrypt_kms_decrypt (crypt, out, error)) {
      goto cleanup;
   }

   ret = true;

cleanup:
   mongoc_client_pool_push (crypt->keyvault_pool, keyvault_client);
   mongoc_cursor_destroy (cursor);
   mongoc_collection_destroy (datakey_coll);
   return ret;
}

/* Don't bother fixing */
static bool
_get_key_by_uuid (mongocrypt_t *crypt,
                  _mongocrypt_buffer_t *key_id,
                  _mongocrypt_key_t *out,
                  mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   return _get_key (crypt, key_id, NULL, out, error);
}


static bool
_append_encrypted (mongocrypt_t *crypt,
                   _mongocrypt_marking_t *marking,
                   bson_t *out,
                   const char *field,
                   uint32_t field_len,
                   mongocrypt_error_t **error)
{
   bool ret = false;
   /* will hold { 'k': <key id>, 'iv': <iv>, 'e': <encrypted data> } */
   bson_t encrypted_w_metadata = BSON_INITIALIZER;
   /* will hold { 'e': <encrypted data> } */
   bson_t to_encrypt = BSON_INITIALIZER;
   uint8_t *encrypted = NULL;
   uint32_t encrypted_len;
   _mongocrypt_key_t key = {{0}};

   CRYPT_ENTRY;
   if (!_get_key (
          crypt, &marking->key_id, marking->key_alt_name, &key, error)) {
      CLIENT_ERR ("could not get key");
      goto cleanup;
   }

   bson_append_iter (&to_encrypt, "v", 1, &marking->v_iter);
   /* TODO: 'a' and 'u' */

   if (!_mongocrypt_do_encryption (marking->iv.data,
                                   key.data_key.data,
                                   bson_get_data (&to_encrypt),
                                   to_encrypt.len,
                                   &encrypted,
                                   &encrypted_len,
                                   error)) {
      goto cleanup;
   }

   CRYPT_TRACE ("did encryption");

   /* append { 'k': <key id>, 'iv': <iv>, 'e': <encrypted { v: <val> } > } */
   _mongocrypt_bson_append_buffer (
      &encrypted_w_metadata, "k", 1, &marking->key_id);
   _mongocrypt_bson_append_buffer (
      &encrypted_w_metadata, "iv", 2, &marking->iv);
   bson_append_binary (&encrypted_w_metadata,
                       "e",
                       1,
                       BSON_SUBTYPE_BINARY,
                       encrypted,
                       encrypted_len);
   bson_append_binary (out,
                       field,
                       field_len,
                       BSON_SUBTYPE_ENCRYPTED,
                       bson_get_data (&encrypted_w_metadata),
                       encrypted_w_metadata.len);

   ret = true;

cleanup:
   bson_destroy (&to_encrypt);
   bson_free (encrypted);
   bson_destroy (&encrypted_w_metadata);
   mongocrypt_key_cleanup (&key);
   return ret;
}


static bool
_append_decrypted (mongocrypt_t *crypt,
                   _mongocrypt_ciphertext_t *encrypted,
                   bson_t *out,
                   const char *field,
                   uint32_t field_len,
                   mongocrypt_error_t **error)
{
   _mongocrypt_key_t key = {{0}};
   uint8_t *decrypted;
   uint32_t decrypted_len;
   bool ret = false;

   CRYPT_ENTRY;
   if (!_get_key_by_uuid (crypt, &encrypted->key_id, &key, error)) {
      return ret;
   }

   if (!_mongocrypt_do_decryption (encrypted->iv.data,
                                   key.data_key.data,
                                   encrypted->data.data,
                                   encrypted->data.len,
                                   &decrypted,
                                   &decrypted_len,
                                   error)) {
      goto cleanup;
   } else {
      bson_t wrapped; /* { 'v': <the value> } */
      bson_iter_t wrapped_iter;
      bson_init_static (&wrapped, decrypted, decrypted_len);
      if (!bson_iter_init_find (&wrapped_iter, &wrapped, "v")) {
         bson_destroy (&wrapped);
         CLIENT_ERR ("invalid encrypted data, missing 'v' field");
         goto cleanup;
      }
      bson_append_value (
         out, field, field_len, bson_iter_value (&wrapped_iter));
      bson_destroy (&wrapped);
   }

   ret = true;

cleanup:
   bson_free (decrypted);
   mongocrypt_key_cleanup (&key);
   return ret;
}

typedef enum { MARKING_TO_ENCRYPTED, ENCRYPTED_TO_PLAIN } transform_t;

static bool
_copy_and_transform (mongocrypt_t *crypt,
                     bson_iter_t iter,
                     bson_t *out,
                     mongocrypt_error_t **error,
                     transform_t transform)
{
   // CRYPT_ENTRY;
   // while (bson_iter_next (&iter)) {
   //    if (BSON_ITER_HOLDS_BINARY (&iter)) {
   //       _mongocrypt_buffer_t value;
   //       bson_t as_bson;

   //       _mongocrypt_unowned_buffer_from_iter (&iter, &value);
   //       if (value.subtype == BSON_SUBTYPE_ENCRYPTED) {
   //          bson_init_static (&as_bson, value.data, value.len);
   //          CRYPT_TRACE ("found FLE binary: %s", tmp_json (&as_bson));
   //          if (transform == MARKING_TO_ENCRYPTED) {
   //             mongocrypt_marking_t marking = {{0}};

   //             if (!_mongocrypt_marking_parse_unowned (
   //                    &as_bson, &marking, error)) {
   //                return false;
   //             }
   //             if (!_append_encrypted (crypt,
   //                                     &marking,
   //                                     out,
   //                                     bson_iter_key (&iter),
   //                                     bson_iter_key_len (&iter),
   //                                     error))
   //                return false;
   //          } else {
   //             mongocrypt_encrypted_t encrypted = {{0}};

   //             if (!_mongocrypt_encrypted_parse_unowned (
   //                    &as_bson, &encrypted, error)) {
   //                return false;
   //             }
   //             if (!_append_decrypted (crypt,
   //                                     &encrypted,
   //                                     out,
   //                                     bson_iter_key (&iter),
   //                                     bson_iter_key_len (&iter),
   //                                     error))
   //                return false;
   //          }
   //          continue;
   //       }
   //       /* otherwise, fall through. copy over like a normal value. */
   //    }

   //    if (BSON_ITER_HOLDS_ARRAY (&iter)) {
   //       bson_iter_t child_iter;
   //       bson_t child_out;
   //       bool ret;

   //       bson_iter_recurse (&iter, &child_iter);
   //       bson_append_array_begin (
   //          out, bson_iter_key (&iter), bson_iter_key_len (&iter),
   //          &child_out);
   //       ret = _copy_and_transform (
   //          crypt, child_iter, &child_out, error, transform);
   //       bson_append_array_end (out, &child_out);
   //       if (!ret) {
   //          return false;
   //       }
   //    } else if (BSON_ITER_HOLDS_DOCUMENT (&iter)) {
   //       bson_iter_t child_iter;
   //       bson_t child_out;
   //       bool ret;

   //       bson_iter_recurse (&iter, &child_iter);
   //       bson_append_document_begin (
   //          out, bson_iter_key (&iter), bson_iter_key_len (&iter),
   //          &child_out);
   //       ret = _copy_and_transform (
   //          crypt, child_iter, &child_out, error, transform);
   //       bson_append_document_end (out, &child_out);
   //       if (!ret) {
   //          return false;
   //       }
   //    } else {
   //       bson_append_value (out,
   //                          bson_iter_key (&iter),
   //                          bson_iter_key_len (&iter),
   //                          bson_iter_value (&iter));
   //    }
   // }
   return true;
}


static bool
_replace_markings (mongocrypt_t *crypt,
                   const bson_t *reply,
                   bson_t *out,
                   mongocrypt_error_t **error)
{
   bson_iter_t iter;

   CRYPT_ENTRY;
   BSON_ASSERT (bson_iter_init_find (&iter, reply, "ok"));
   if (!bson_iter_as_bool (&iter)) {
      CLIENT_ERR ("markFields returned ok:0");
      return false;
   }

   if (!bson_iter_init_find (&iter, reply, "data")) {
      CLIENT_ERR ("markFields returned ok:0");
      return false;
   }
   /* recurse into array. */
   bson_iter_recurse (&iter, &iter);
   bson_iter_next (&iter);
   /* recurse into first document. */
   bson_iter_recurse (&iter, &iter);
   if (!_copy_and_transform (crypt, iter, out, error, MARKING_TO_ENCRYPTED)) {
      return false;
   }
   return true;
}


static void
_make_marking_cmd (const bson_t *data, const bson_t *schema, bson_t *cmd)
{
   bson_t child;

   bson_init (cmd);
   BSON_APPEND_INT64 (cmd, "markFields", 1);
   BSON_APPEND_ARRAY_BEGIN (cmd, "data", &child);
   BSON_APPEND_DOCUMENT (&child, "0", data);
   bson_append_array_end (cmd, &child);
   BSON_APPEND_DOCUMENT (cmd, "schema", schema);
}

int
mongocrypt_encrypt (mongocrypt_t *crypt,
                    const mongocrypt_binary_t *bson_schema,
                    const mongocrypt_binary_t *bson_doc,
                    mongocrypt_binary_t *bson_out,
                    mongocrypt_error_t **error)
{
   bson_t cmd, reply;
   bson_t schema, doc, out;
   bson_error_t bson_error;
   mongoc_client_t *mongocryptd_client;
   bool ret;

   CRYPT_ENTRY;
   BSON_ASSERT (*error == NULL);
   ret = false;
   memset (bson_out, 0, sizeof (*bson_out));

   bson_init (&out);
   bson_init_static (&doc, bson_doc->data, bson_doc->len);
   bson_init_static (&schema, bson_schema->data, bson_schema->len);

   mongocryptd_client = mongoc_client_pool_pop (crypt->mongocryptd_pool);

   _make_marking_cmd (&doc, &schema, &cmd);
   if (!mongoc_client_command_simple (mongocryptd_client,
                                      "admin",
                                      &cmd,
                                      NULL /* read prefs */,
                                      &reply,
                                      &bson_error)) {
      MONGOCRYPTD_ERR_W_REPLY (bson_error, &reply);
      goto cleanup;
   }

   CRYPT_TRACE ("sent marking cmd: %s", tmp_json (&cmd));
   CRYPT_TRACE ("got back: %s", tmp_json (&reply));

   if (!_replace_markings (crypt, &reply, &out, error)) {
      goto cleanup;
   }

   ret = true;
cleanup:
   if (ret) {
      bson_out->data = bson_destroy_with_steal (&out, true, &bson_out->len);
   } else {
      bson_destroy (&out);
   }
   bson_destroy (&cmd);
   bson_destroy (&reply);
   mongoc_client_pool_push (crypt->mongocryptd_pool, mongocryptd_client);
   return ret;
}

int
mongocrypt_decrypt (mongocrypt_t *crypt,
                    const mongocrypt_binary_t *bson_doc,
                    mongocrypt_binary_t *bson_out,
                    mongocrypt_error_t **error)
{
   bson_iter_t iter;
   bson_t doc;
   bson_t out;

   CRYPT_ENTRY;
   BSON_ASSERT (*error == NULL);
   memset (bson_out, 0, sizeof (*bson_out));

   bson_init (&out);
   bson_init_static (&doc, bson_doc->data, bson_doc->len);
   bson_iter_init (&iter, &doc);
   if (!_copy_and_transform (crypt, iter, &out, error, ENCRYPTED_TO_PLAIN)) {
      bson_destroy (&out);
      return false;
   }
   bson_out->data = bson_destroy_with_steal (&out, true, &bson_out->len);
   return true;
}

void
mongocrypt_request_destroy (mongocrypt_request_t *request)
{
   if (!request) {
      return;
   }
   bson_destroy (&request->mongocryptd_reply);
   /* TODO: destroy key queries. */
}

int
mongocrypt_request_needs_keys (mongocrypt_request_t *request)
{
   return request->key_query_iter < request->num_key_queries;
}

mongocrypt_key_query_t *
mongocrypt_request_next_key_query (mongocrypt_request_t *request,
                                   mongocrypt_opts_t *opts)
{
   mongocrypt_key_query_t *key_query =
      &request->key_queries[request->key_query_iter];
   request->key_query_iter++;
   return key_query;
}

int
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_error_t **error)
{
   int i;
   for (i = 0; i < num_responses; i++) {
      /* TODO: don't marshal this. */
      _mongocrypt_buffer_t buf = {0};
      buf.data = responses[i].data;
      buf.len = responses[i].len;
      if (!_mongocrypt_keycache_add (request->crypt, &buf, 1, error)) {
         return 0;
      }
   }
   return 1;
}

const mongocrypt_binary_t *
mongocrypt_key_query_filter (mongocrypt_key_query_t *key_query)
{
   return &key_query->filter_bin;
}

const char *
mongocrypt_key_query_alias (mongocrypt_key_query_t *key_query)
{
   return key_query->keyvault_alias;
}

typedef struct {
   mongocrypt_t *crypt;
   mongocrypt_request_t *request;
} _collect_key_ctx_t;

static bool
_collect_key_from_marking (void *ctx_void,
                           _mongocrypt_buffer_t *in,
                           mongocrypt_error_t **error)
{
   _collect_key_ctx_t *ctx;
   _mongocrypt_marking_t marking;
   bson_t filter;
   mongocrypt_key_query_t *key_query;

   ctx = (_collect_key_ctx_t *) ctx_void;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, error)) {
      return false;
   }

   /* TODO: check key cache for the key ID. */
   /* If the key cache does not have the key, add a new key query. */
   key_query = &ctx->request->key_queries[ctx->request->num_key_queries++];
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
                          mongocrypt_error_t **error)
{
   bson_t schema, cmd;
   bson_t marking_cmd;
   bson_error_t bson_error;
   bool succeeded = false;
   mongoc_client_t *mongocryptd_client = NULL;
   mongocrypt_request_t *request = NULL;

   CRYPT_ENTRY;
   bson_init_static (&schema, schema_in->data, schema_in->len);
   bson_init_static (&cmd, cmd_in->data, cmd_in->len);
   /* Construct the marking command to send. This consists of the original
    * command with the field "jsonSchema" added. */
   bson_copy_to (&cmd, &marking_cmd);
   bson_append_document (&marking_cmd, "jsonSchema", 10, &schema);
   mongocryptd_client = mongoc_client_pool_pop (crypt->mongocryptd_pool);
   CRYPT_TRACE ("sending marking cmd\n\t%s", tmp_json (&marking_cmd));
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
   CRYPT_TRACE ("got reply back\n\t%s", tmp_json (&request->mongocryptd_reply));

   if (!_mongocryptd_marking_reply_parse (
          &request->mongocryptd_reply, request, error)) {
      goto fail;
   }
   if (request->has_encryption_placeholders) {
      _collect_key_ctx_t ctx = {crypt, request};
      if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_marking,
                                                (void *) &ctx,
                                                0,
                                                request->result_iter,
                                                error)) {
         goto fail;
      }
   }

   succeeded = true;

fail:
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

typedef struct {
   mongocrypt_t *crypt; /* TODO: redundant, request already has a crypt */
   mongocrypt_request_t *request; 
} _replace_marking_with_ciphertext_ctx_t;

static void _serialize_ciphertext (_mongocrypt_ciphertext_t* ciphertext, _mongocrypt_buffer_t* out) {
   /* TODO: serialize with respect to endianness. Move this to mongocrypt-parsing.c? */
   uint16_t keyvault_alias_len = (uint16_t)strlen(ciphertext->keyvault_alias);

   out->len = 1 + 2 + 1 + 16 + keyvault_alias_len + ciphertext->iv.len + ciphertext->data.len;
   out->data = bson_malloc0(out->len);
   out->data[0] = '\01'; /* TODO: account for randomized. */
   memcpy(out->data + 1, &keyvault_alias_len, 2);
   /* Don't copy null byte. */
   memcpy(out->data + 1 + 2, ciphertext->keyvault_alias, keyvault_alias_len);
   memcpy(out->data + 1 + 2 + keyvault_alias_len, ciphertext->key_id.data, ciphertext->key_id.len);
   memcpy(out->data + 1 + 2 + keyvault_alias_len + ciphertext->key_id.len, ciphertext->data.data, ciphertext->data.len);
}

static bool
_replace_marking_with_ciphertext (void* ctx_in, _mongocrypt_buffer_t* in, _mongocrypt_buffer_t* out, mongocrypt_error_t** error) {
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ciphertext_t ciphertext = {0};
   _replace_marking_with_ciphertext_ctx_t* ctx;
   _mongocrypt_key_t* key;
   bson_t wrapper = BSON_INITIALIZER;
   int ret;

   ctx = (_replace_marking_with_ciphertext_ctx_t*) ctx_in;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, error)) {
      return false;
   }

   memcpy(&ciphertext.iv, &marking.iv, sizeof(_mongocrypt_buffer_t));
   /* get the key associated with the marking. */
   if (marking.key_alt_name) {
      CLIENT_ERR("looking up key by keyAltName not yet supported");
      return false;
   }

   key = _mongocrypt_keycache_get_by_id (ctx->crypt, &marking.key_id, error);
   printf("here\n");
   _mongocrypt_keycache_dump (ctx->crypt);
   if (!key) {
      return false;
   }

   MONGOCRYPT_TRACE ("about to encrypt");
   bson_append_iter (&wrapper, "", 0, &marking.v_iter);

   ret = _mongocrypt_do_encryption(ciphertext.iv.data, key->data_key.data, bson_get_data(&wrapper), wrapper.len, &ciphertext.data.data, &ciphertext.data.len, error);
   if (!ret) {
      return false;
   }
   
   memcpy(&ciphertext.key_id, &marking.iv, sizeof(_mongocrypt_buffer_t));
   ciphertext.keyvault_alias = marking.keyvault_alias;
   _serialize_ciphertext (&ciphertext, out);

   ret = true;
   return ret;
}

int
mongocrypt_encrypt_finish (mongocrypt_request_t* request, const mongocrypt_opts_t* opts, mongocrypt_binary_t* encrypted_out, mongocrypt_error_t** error) {
   int ret = 0;
   bson_t out = BSON_INITIALIZER;
   _replace_marking_with_ciphertext_ctx_t ctx = { request->crypt, request };

   ret = _mongocrypt_transform_binary_in_bson (_replace_marking_with_ciphertext, &ctx, 0, request->result_iter, &out, error);
   if (!ret) {
      bson_destroy (&out);
      goto fail;
   }   
   encrypted_out->data = bson_destroy_with_steal(&out, true, &encrypted_out->len);

   ret = 1;
fail:
   return ret;
}