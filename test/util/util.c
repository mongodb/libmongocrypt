/*
 * Copyright 2020-present MongoDB, Inc.
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

#include "util.h"

/* Utilities for integration tests and example runners. */

#include <mongoc/mongoc.h>
#include "mongocrypt.h"

static void
_errexit_status (mongocrypt_status_t *status, int line)
{
   int code;
   const char *msg;

   code = mongocrypt_status_code (status);
   msg = mongocrypt_status_message (status, NULL);
   MONGOC_ERROR ("Error at line %d with code %d and msg: %s", line, code, msg);
   exit (1);
}

void
_errexit_mongocrypt (mongocrypt_t *crypt, int line)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   mongocrypt_status (crypt, status);
   _errexit_status (status, line);
   mongocrypt_status_destroy (status);
}

void
_errexit_ctx (mongocrypt_ctx_t *ctx, int line)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   mongocrypt_ctx_status (ctx, status);
   _errexit_status (status, line);
   mongocrypt_status_destroy (status);
}

void
_errexit_bson (bson_error_t *error, int line)
{
   MONGOC_ERROR ("Error at line %d with code %d and msg: %s",
                 line,
                 error->code,
                 error->message);
   exit (1);
}

void
_log_to_stdout (mongocrypt_log_level_t level,
                const char *message,
                uint32_t message_len,
                void *ctx)
{
   switch (level) {
   case MONGOCRYPT_LOG_LEVEL_FATAL:
      printf ("FATAL");
      break;
   case MONGOCRYPT_LOG_LEVEL_ERROR:
      printf ("ERROR");
      break;
   case MONGOCRYPT_LOG_LEVEL_WARNING:
      printf ("WARNING");
      break;
   case MONGOCRYPT_LOG_LEVEL_INFO:
      printf ("INFO");
      break;
   case MONGOCRYPT_LOG_LEVEL_TRACE:
      printf ("TRACE");
      break;
   default:
      printf ("?????");
      break;
   }
   printf (" %s\n", message);
}

char *
util_getenv (const char *key)
{
   char *value = getenv (key);
   if (!value) {
      MONGOC_ERROR ("Environment variable: %s not set", key);
   }
   return value;
}

mongocrypt_binary_t *
util_bson_to_bin (bson_t *bson)
{
   return mongocrypt_binary_new_from_data ((uint8_t *) bson_get_data (bson),
                                           bson->len);
}

bson_t *
util_bin_to_bson (mongocrypt_binary_t *bin)
{
   return bson_new_from_data (mongocrypt_binary_data (bin),
                              mongocrypt_binary_len (bin));
}


/* Defined in mongoc-stream.c */
bool
_mongoc_stream_writev_full (mongoc_stream_t *stream,
                            mongoc_iovec_t *iov,
                            size_t iovcnt,
                            int32_t timeout_msec,
                            bson_error_t *error);

const char *
_state_string (mongocrypt_ctx_state_t state)
{
   switch (state) {
   case MONGOCRYPT_CTX_ERROR:
      return "MONGOCRYPT_CTX_ERROR";
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      return "MONGOCRYPT_CTX_NEED_MONGO_COLLINFO";
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      return "MONGOCRYPT_CTX_NEED_MONGO_MARKINGS";
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      return "MONGOCRYPT_CTX_NEED_MONGO_KEYS";
   case MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS:
      return "MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS";
   case MONGOCRYPT_CTX_NEED_KMS:
      return "MONGOCRYPT_CTX_NEED_KMS";
   case MONGOCRYPT_CTX_READY:
      return "MONGOCRYPT_CTX_READY";
   case MONGOCRYPT_CTX_DONE:
      return "MONGOCRYPT_CTX_DONE";
   default:
      return "UNKNOWN";
   }
}

/*--------------------------------------------------------------------------
 *
 * _mongoc_cse_run_state_machine --
 *    Run the mongocrypt_ctx state machine.
 *
 * Post-conditions:
 *    *result may be set to a new bson_t, or NULL otherwise. Caller should
 *    not assume return value of true means *result is set. If false returned,
 *    @error is set.
 *
 * --------------------------------------------------------------------------
 */
/// Defined in mongoc-crypt.c
bool
_state_machine_run (_state_machine_t *state_machine,
                    bson_t *result,
                    bson_error_t *error);

bson_t *
util_read_json_file (const char *path)
{
   bson_json_reader_t *reader;
   bson_error_t error;
   bson_t *doc;

   reader = bson_json_reader_new_from_file (path, &error);
   if (!reader) {
      ERREXIT ("Error opening %s: %s", path, error.message);
   }

   doc = bson_new ();
   if (1 != bson_json_reader_read (reader, doc, &error)) {
      ERREXIT ("Could not read BSON from %s: %s", path, error.message);
   }
   bson_json_reader_destroy (reader);
   return doc;
}

void
args_parse (bson_t *args, int argc, char **argv)
{
   int i;

   if (argc % 2 != 0) {
      ERREXIT ("Invalid arguments, expected list of key-value pairs.");
   }

   for (i = 0; i < argc; i++) {
      for (i = 0; i < argc; i += 2) {
         if (0 != strncmp (argv[i], "--", 2)) {
            ERREXIT ("Malformed option: %s", argv[i]);
         }
         bson_append_utf8 (args, argv[i] + 2, -1, argv[i + 1], -1);
      }
   }
}

const char *
bson_get_utf8 (bson_t *bson, const char *dotkey, const char *default_value)
{
   bson_iter_t iter;

   bson_iter_init (&iter, bson);
   if (bson_iter_find_descendant (&iter, dotkey, &iter) &&
       BSON_ITER_HOLDS_UTF8 (&iter)) {
      return bson_iter_utf8 (&iter, NULL);
   }
   return default_value;
}

const char *
bson_req_utf8 (bson_t *bson, const char *dotkey)
{
   const char *ret;

   ret = bson_get_utf8 (bson, dotkey, NULL);
   if (!ret) {
      ERREXIT ("Required field missing: '%s'", dotkey);
   }
   return ret;
}

const uint8_t *
bson_get_bin (bson_t *bson, const char *dotkey, uint32_t *len)
{
   bson_iter_t iter;
   bson_iter_t subiter;
   bson_subtype_t subtype;
   const uint8_t *data = NULL;

   bson_iter_init (&iter, bson);
   if (bson_iter_find_descendant (&iter, dotkey, &subiter) &&
       BSON_ITER_HOLDS_BINARY (&subiter)) {
      bson_iter_binary (&subiter, &subtype, len, &data);
   }
   return data;
}

const uint8_t *
bson_req_bin (bson_t *bson, const char *dotkey, uint32_t *len)
{
   const uint8_t *ret;

   ret = bson_get_bin (bson, dotkey, len);
   if (!ret) {
      ERREXIT ("Required field missing: '%s'", dotkey);
   }
   return ret;
}

bson_t *
bson_get_json (bson_t *bson, const char *dotkey)
{
   const char *path;

   path = bson_get_utf8 (bson, dotkey, NULL);
   if (!path) {
      return NULL;
   }
   return util_read_json_file (path);
}

bson_t *
bson_req_json (bson_t *bson, const char *dotkey)
{
   bson_t *ret;

   ret = bson_get_json (bson, dotkey);
   if (!ret) {
      ERREXIT ("Required field missing: '%s'", dotkey);
   }
   return ret;
}

bool
bson_get_bool (bson_t *bson, const char *dotkey, bool default_value)
{
   const char *as_str;

   as_str = bson_get_utf8 (bson, dotkey, NULL);
   if (!as_str) {
      return default_value;
   }
   if (0 == bson_strcasecmp (as_str, "true") || 0 == strcmp (as_str, "1")) {
      return true;
   }
   return default_value;
}
