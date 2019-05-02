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

#include "mongocrypt-crypto-private.h"
#include "mongocrypt-cache-collinfo-private.h"
#include "mongocrypt-cache-key-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-os-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"


const char *
mongocrypt_version (uint32_t *len)
{
   if (len) {
      *len = strlen (MONGOCRYPT_VERSION);
   }
   return MONGOCRYPT_VERSION;
}


void
_mongocrypt_set_error (mongocrypt_status_t *status,
                       mongocrypt_status_type_t type,
                       uint32_t code,
                       const char *format,
                       ...)
{
   va_list args;

   if (status) {
      status->type = type;
      status->code = code;

      va_start (args, format);
      status->len = (uint32_t) bson_vsnprintf (
         status->message, sizeof status->message, format, args);
      va_end (args);

      status->message[sizeof status->message - 1] = '\0';
   }
}


const char *
tmp_json (const bson_t *bson)
{
   static char storage[1024];
   char *json;

   memset (storage, 0, 1024);
   json = bson_as_canonical_extended_json (bson, NULL);
   bson_snprintf (storage, sizeof (storage), "%s", json);
   bson_free (json);
   return (const char *) storage;
}


const char *
tmp_buf (const _mongocrypt_buffer_t *buf)
{
   static char storage[1024];
   uint32_t i, n;

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

void
_mongocrypt_do_init (void)
{
   kms_message_init ();
   _crypto_init ();
}


mongocrypt_t *
mongocrypt_new (void)
{
   mongocrypt_t *crypt;

   crypt = bson_malloc0 (sizeof (mongocrypt_t));
   _mongocrypt_mutex_init (&crypt->mutex);
   _mongocrypt_cache_collinfo_init (&crypt->cache_collinfo);
   _mongocrypt_cache_key_init (&crypt->cache_key);
   crypt->status = mongocrypt_status_new ();
   _mongocrypt_opts_init (&crypt->opts);
   _mongocrypt_log_init (&crypt->log);
   crypt->ctx_counter = 1;
   return crypt;
}


bool
mongocrypt_setopt_log_handler (mongocrypt_t *crypt,
                               mongocrypt_log_fn_t log_fn,
                               void *log_ctx)
{
   if (crypt->initialized) {
      mongocrypt_status_t *status = crypt->status;
      CLIENT_ERR ("options cannot be set after initialization");
      return false;
   }
   crypt->opts.log_fn = log_fn;
   crypt->opts.log_ctx = log_ctx;
   return true;
}


bool
mongocrypt_setopt_kms_provider_aws (mongocrypt_t *crypt,
                                    const char *aws_access_key_id,
                                    int32_t aws_access_key_id_len,
                                    const char *aws_secret_access_key,
                                    int32_t aws_secret_access_key_len)
{
   mongocrypt_status_t *status = crypt->status;

   if (crypt->initialized) {
      CLIENT_ERR ("options cannot be set after initialization");
      return false;
   }

   if (0 != (crypt->opts.kms_providers & MONGOCRYPT_KMS_PROVIDER_AWS)) {
      CLIENT_ERR ("aws kms provider already set");
      return false;
   }

   if (!_mongocrypt_validate_and_copy_string (
          aws_access_key_id,
          aws_access_key_id_len,
          &crypt->opts.kms_aws_access_key_id)) {
      CLIENT_ERR ("invalid aws access key id");
      return false;
   }

   if (!_mongocrypt_validate_and_copy_string (
          aws_secret_access_key,
          aws_secret_access_key_len,
          &crypt->opts.kms_aws_secret_access_key)) {
      CLIENT_ERR ("invalid aws secret access key");
      return false;
   }
   crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
   return true;
}


bool
mongocrypt_setopt_kms_provider_local (mongocrypt_t *crypt,
                                      mongocrypt_binary_t *key)
{
   mongocrypt_status_t *status = crypt->status;

   if (crypt->initialized) {
      CLIENT_ERR ("options cannot be set after initialization");
      return false;
   }

   if (0 != (crypt->opts.kms_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL)) {
      CLIENT_ERR ("local kms provider already set");
      return false;
   }

   if (!key) {
      CLIENT_ERR ("passed null key");
      return false;
   }

   if (mongocrypt_binary_len (key) != MONGOCRYPT_KEYMATERIAL_LEN) {
      CLIENT_ERR ("local key must be %d bytes", MONGOCRYPT_KEYMATERIAL_LEN);
      return false;
   }

   _mongocrypt_buffer_copy_from_binary (&crypt->opts.kms_local_key, key);
   crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
   return true;
}


bool
mongocrypt_init (mongocrypt_t *crypt)
{
   mongocrypt_status_t *status;

   status = crypt->status;
   if (crypt->initialized) {
      CLIENT_ERR ("already initialized");
      return false;
   }

   crypt->initialized = true;

   if (0 != _mongocrypt_once (_mongocrypt_do_init)) {
      CLIENT_ERR ("failed to initialize");
      return false;
   }

   if (!_mongocrypt_opts_validate (&crypt->opts, status)) {
      return false;
   }

   if (crypt->opts.log_fn) {
      _mongocrypt_log_set_fn (
         &crypt->log, crypt->opts.log_fn, crypt->opts.log_ctx);
   }
   return true;
}


bool
mongocrypt_status (mongocrypt_t *crypt, mongocrypt_status_t *out)
{
   if (!mongocrypt_status_ok (crypt->status)) {
      _mongocrypt_status_copy_to (crypt->status, out);
      return false;
   }
   _mongocrypt_status_reset (out);
   return true;
}


void
mongocrypt_destroy (mongocrypt_t *crypt)
{
   if (!crypt) {
      return;
   }
   _mongocrypt_opts_cleanup (&crypt->opts);
   _mongocrypt_cache_cleanup (&crypt->cache_collinfo);
   _mongocrypt_cache_cleanup (&crypt->cache_key);
   _mongocrypt_mutex_cleanup (&crypt->mutex);
   _mongocrypt_log_cleanup (&crypt->log);
   mongocrypt_status_destroy (crypt->status);
   bson_free (crypt);
}


bool
_mongocrypt_validate_and_copy_string (const char *in,
                                      int32_t in_len,
                                      char **out)
{
   if (!in) {
      return false;
   }

   if (in_len < -1) {
      return false;
   }

   if (in_len == -1) {
      in_len = strlen (in);
   }

   if (!bson_utf8_validate (in, in_len, false)) {
      return false;
   }
   *out = bson_strndup (in, in_len);
   return true;
}
