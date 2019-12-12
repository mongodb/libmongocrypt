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

#include "mongocrypt-private.h"
#include "mongocrypt-binary-private.h"
#include "mongocrypt-cache-collinfo-private.h"
#include "mongocrypt-cache-key-private.h"
#include "mongocrypt-config.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-os-private.h"
#include "mongocrypt-status-private.h"

/* Assert size for interop with wrapper purposes */
BSON_STATIC_ASSERT (sizeof (mongocrypt_log_level_t) == 4);


const char *
mongocrypt_version (uint32_t *len)
{
   if (len) {
      *len = (uint32_t) strlen (MONGOCRYPT_VERSION);
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
   char *prepared_message;

   if (status) {
      va_start (args, format);
      prepared_message = bson_strdupv_printf (format, args);
      if (!prepared_message) {
         mongocrypt_status_set (status, type, code, "Out of memory", -1);
      } else {
         mongocrypt_status_set (status, type, code, prepared_message, -1);
         bson_free (prepared_message);
      }
      va_end (args);
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
   (void) kms_message_init ();
   _native_crypto_init ();
}


mongocrypt_t *
mongocrypt_new (void)
{
   mongocrypt_t *crypt;

   crypt = bson_malloc0 (sizeof (mongocrypt_t));
   BSON_ASSERT (crypt);

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
   if (!crypt) {
      return false;
   }

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
   mongocrypt_status_t *status;

   if (!crypt) {
      return false;
   }
   status = crypt->status;

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

   if (crypt->log.trace_enabled) {
      _mongocrypt_log (&crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\", %s=%d, %s=\"%s\", %s=%d)",
                       BSON_FUNC,
                       "aws_access_key_id",
                       crypt->opts.kms_aws_access_key_id,
                       "aws_access_key_id_len",
                       aws_access_key_id_len,
                       "aws_secret_access_key",
                       crypt->opts.kms_aws_secret_access_key,
                       "aws_secret_access_key_len",
                       aws_secret_access_key_len);
   }
   crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
   return true;
}

char *
_mongocrypt_new_string_from_bytes (const void *in, int len)
{
   const int max_bytes = 100;
   const int chars_per_byte = 2;
   int out_size = max_bytes * chars_per_byte;
   const unsigned char *src = in;
   char *out;
   char *ret;

   out_size += len > max_bytes ? sizeof ("...") : 1 /* for null */;
   out = bson_malloc0 (out_size);
   BSON_ASSERT (out);

   ret = out;

   for (int i = 0; i < len && i < max_bytes; i++, out += chars_per_byte) {
      sprintf (out, "%02X", src[i]);
   }

   sprintf (out, (len > max_bytes) ? "..." : "");
   return ret;
}

char *
_mongocrypt_new_json_string_from_binary (mongocrypt_binary_t *binary)
{
   bson_t bson;
   uint32_t len;

   if (!_mongocrypt_binary_to_bson (binary, &bson) ||
       !bson_validate (&bson, BSON_VALIDATE_NONE, NULL)) {
      char *hex;
      char *full_str;

      hex = _mongocrypt_new_string_from_bytes (binary->data, binary->len);
      full_str = bson_strdup_printf ("(malformed) %s", hex);
      bson_free (hex);
      return full_str;
   }
   return bson_as_canonical_extended_json (&bson, (size_t *) &len);
}

bool
mongocrypt_setopt_schema_map (mongocrypt_t *crypt,
                              mongocrypt_binary_t *schema_map)
{
   bson_t tmp;
   bson_error_t bson_err;
   mongocrypt_status_t *status;

   if (!crypt) {
      return false;
   }
   status = crypt->status;

   if (crypt->initialized) {
      CLIENT_ERR ("options cannot be set after initialization");
      return false;
   }

   if (!schema_map || !mongocrypt_binary_data (schema_map)) {
      CLIENT_ERR ("passed null schema map");
      return false;
   }

   if (!_mongocrypt_buffer_empty (&crypt->opts.schema_map)) {
      CLIENT_ERR ("already set schema map");
      return false;
   }

   _mongocrypt_buffer_copy_from_binary (&crypt->opts.schema_map, schema_map);

   /* validate bson */
   if (!_mongocrypt_buffer_to_bson (&crypt->opts.schema_map, &tmp)) {
      CLIENT_ERR ("invalid bson");
      return false;
   }

   if (!bson_validate_with_error (&tmp, BSON_VALIDATE_NONE, &bson_err)) {
      CLIENT_ERR (bson_err.message);
      return false;
   }

   return true;
}


bool
mongocrypt_setopt_kms_provider_local (mongocrypt_t *crypt,
                                      mongocrypt_binary_t *key)
{
   mongocrypt_status_t *status;

   if (!crypt) {
      return false;
   }
   status = crypt->status;

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

   if (mongocrypt_binary_len (key) != MONGOCRYPT_KEY_LEN) {
      CLIENT_ERR ("local key must be %d bytes", MONGOCRYPT_KEY_LEN);
      return false;
   }

   if (crypt->log.trace_enabled) {
      char *key_val;
      key_val = _mongocrypt_new_string_from_bytes (key->data, key->len);

      _mongocrypt_log (&crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\")",
                       BSON_FUNC,
                       "key",
                       key_val);
      bson_free (key_val);
   }

   _mongocrypt_buffer_copy_from_binary (&crypt->opts.kms_local_key, key);
   crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
   return true;
}


bool
mongocrypt_init (mongocrypt_t *crypt)
{
   mongocrypt_status_t *status;

   if (!crypt) {
      return false;
   }
   status = crypt->status;
   if (crypt->initialized) {
      CLIENT_ERR ("already initialized");
      return false;
   }

   crypt->initialized = true;

   if (0 != _mongocrypt_once (_mongocrypt_do_init) ||
       !(_native_crypto_initialized)) {
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

   if (!crypt->crypto) {
#ifndef MONGOCRYPT_ENABLE_CRYPTO
      CLIENT_ERR ("libmongocrypt built with native crypto disabled. crypto "
                  "hooks required");
      return false;
#else
      /* set default hooks. */
      crypt->crypto = bson_malloc0 (sizeof (*crypt->crypto));
      BSON_ASSERT (crypt->crypto);

#endif
   }
   return true;
}


bool
mongocrypt_status (mongocrypt_t *crypt, mongocrypt_status_t *out)
{
   if (!crypt) {
      return false;
   }

   if (!out) {
      mongocrypt_status_t *status = crypt->status;
      CLIENT_ERR ("argument 'out' is required");
      return false;
   }

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
   bson_free (crypt->crypto);
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
      in_len = (uint32_t) strlen (in);
   }

   if (!bson_utf8_validate (in, in_len, false)) {
      return false;
   }
   *out = bson_strndup (in, in_len);
   return true;
}


bool
mongocrypt_setopt_crypto_hooks (mongocrypt_t *crypt,
                                mongocrypt_crypto_fn aes_256_cbc_encrypt,
                                mongocrypt_crypto_fn aes_256_cbc_decrypt,
                                mongocrypt_random_fn random,
                                mongocrypt_hmac_fn hmac_sha_512,
                                mongocrypt_hmac_fn hmac_sha_256,
                                mongocrypt_hash_fn sha_256,
                                void *ctx)
{
   mongocrypt_status_t *status;

   if (!crypt) {
      return false;
   }

   status = crypt->status;

   if (crypt->initialized) {
      CLIENT_ERR ("options cannot be set after initialization");
      return false;
   }

   if (crypt->crypto) {
      CLIENT_ERR ("crypto_hooks already set");
      return false;
   }

   crypt->crypto = bson_malloc0 (sizeof (*crypt->crypto));
   BSON_ASSERT (crypt->crypto);

   crypt->crypto->hooks_enabled = true;
   crypt->crypto->ctx = ctx;

   if (!aes_256_cbc_encrypt) {
      CLIENT_ERR ("aes_256_cbc_encrypt not set");
      return false;
   }
   crypt->crypto->aes_256_cbc_encrypt = aes_256_cbc_encrypt;

   if (!aes_256_cbc_decrypt) {
      CLIENT_ERR ("aes_256_cbc_decrypt not set");
      return false;
   }
   crypt->crypto->aes_256_cbc_decrypt = aes_256_cbc_decrypt;

   if (!random) {
      CLIENT_ERR ("random not set");
      return false;
   }
   crypt->crypto->random = random;

   if (!hmac_sha_512) {
      CLIENT_ERR ("hmac_sha_512 not set");
      return false;
   }
   crypt->crypto->hmac_sha_512 = hmac_sha_512;

   if (!hmac_sha_256) {
      CLIENT_ERR ("hmac_sha_256 not set");
      return false;
   }
   crypt->crypto->hmac_sha_256 = hmac_sha_256;

   if (!sha_256) {
      CLIENT_ERR ("sha_256 not set");
      return false;
   }
   crypt->crypto->sha_256 = sha_256;

   return true;
}