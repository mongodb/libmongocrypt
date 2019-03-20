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
#include <bson/bson.h>

#include "mongocrypt-binary.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-os-private.h"
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

void _mongocrypt_do_init(void)
{
   kms_message_init ();
}


mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts)
{
   mongocrypt_t *crypt = NULL;

   if (0 != _mongocrypt_once (_mongocrypt_do_init)) {
      return NULL;
   }

   crypt = bson_malloc0 (sizeof (mongocrypt_t));
   crypt->opts = mongocrypt_opts_copy (opts);
   _mongocrypt_mutex_init (&crypt->mutex);
   _mongocrypt_log_init (&crypt->log, opts);
   crypt->schema_cache = _mongocrypt_schema_cache_new ();
   crypt->status = mongocrypt_status_new();
   return crypt;
}


bool
mongocrypt_status (mongocrypt_t *crypt, mongocrypt_status_t* out) {
   if (!mongocrypt_status_ok (crypt->status)) {
      mongocrypt_status_copy_to (crypt->status, out);
      return false;
   }
   mongocrypt_status_reset (out);
   return true;
}

void
mongocrypt_destroy (mongocrypt_t *crypt)
{
   if (!crypt) {
      return;
   }
   mongocrypt_opts_destroy (crypt->opts);
   _mongocrypt_schema_cache_destroy (crypt->schema_cache);
   _mongocrypt_key_cache_destroy (crypt->key_cache);
   _mongocrypt_mutex_destroy (&crypt->mutex);
   _mongocrypt_log_cleanup (&crypt->log);
   mongocrypt_status_destroy (crypt->status);
   bson_free (crypt);
}
