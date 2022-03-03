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

#include "mlib/thread.h"
#include "mlib/path.h"
#include "mlib/error.h"

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
#include "mongocrypt-status-private.h"
#include "mongocrypt-util-private.h"

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
   crypt->cache_oauth_azure = _mongocrypt_cache_oauth_new ();
   crypt->cache_oauth_gcp = _mongocrypt_cache_oauth_new ();
   crypt->csfle_lib = MCR_DLL_NULL;

   static mlib_once_flag init_flag = MLIB_ONCE_INITIALIZER;

   if (!mlib_call_once (&init_flag, _mongocrypt_do_init) ||
       !_native_crypto_initialized) {
      mongocrypt_status_t *status = crypt->status;

      CLIENT_ERR ("failed to initialize");
      /* Return crypt with failure status so caller can obtain error when
       * calling mongocrypt_init */
   }

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
          &crypt->opts.kms_provider_aws.access_key_id)) {
      CLIENT_ERR ("invalid aws access key id");
      return false;
   }

   if (!_mongocrypt_validate_and_copy_string (
          aws_secret_access_key,
          aws_secret_access_key_len,
          &crypt->opts.kms_provider_aws.secret_access_key)) {
      CLIENT_ERR ("invalid aws secret access key");
      return false;
   }

   if (crypt->log.trace_enabled) {
      _mongocrypt_log (&crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\", %s=%d, %s=\"%s\", %s=%d)",
                       BSON_FUNC,
                       "aws_access_key_id",
                       crypt->opts.kms_provider_aws.access_key_id,
                       "aws_access_key_id_len",
                       aws_access_key_id_len,
                       "aws_secret_access_key",
                       crypt->opts.kms_provider_aws.secret_access_key,
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

   _mongocrypt_buffer_copy_from_binary (&crypt->opts.kms_provider_local.key,
                                        key);
   crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
   return true;
}

typedef struct {
   /// Whether the load is successful
   bool okay;
   /// The DLL handle to the opened library.
   mcr_dll lib;
   /// A vtable for the functions in the DLL
   _mcr_csfle_v1_vtable vtable;
} _loaded_csfle;

/**
 * @brief Attempt to open the CSFLE dynamic library and initialize a vtable for
 * it.
 */
static _loaded_csfle
_try_load_csfle (const char *filepath, _mongocrypt_log_t *log)
{
   // Try to open the dynamic lib
   mcr_dll lib = mcr_dll_open (filepath);
   // Check for errors, which are represented by strings
   if (lib.error_string.data) {
      // Error opening candidate
      _mongocrypt_log (
         log,
         MONGOCRYPT_LOG_LEVEL_WARNING,
         "Error while opening candidate for CSFLE dynamic library [%s]: %s",
         filepath,
         lib.error_string.data);
      // Free resources, which will include the error string
      mcr_dll_close (lib);
      // Bad:
      return (_loaded_csfle){.okay = false};
   }

   // Successfully opened DLL
   _mongocrypt_log (log,
                    MONGOCRYPT_LOG_LEVEL_TRACE,
                    "Loading CSFLE dynamic library [%s]",
                    filepath);

   // Construct the library vtable
   bool vtable_okay = true;
   _mcr_csfle_v1_vtable vtable;
#define X_FUNC(Name, RetType, ...)                                             \
   {                                                                           \
      /* Symbol names are qualified by the lib name and version: */            \
      const char *symname = "mongo_csfle_v1_" #Name;                           \
      vtable.Name = mcr_dll_sym (lib, symname);                                \
      if (vtable.Name == NULL) {                                               \
         /* The requested symbol is not present */                             \
         _mongocrypt_log (                                                     \
            log,                                                               \
            MONGOCRYPT_LOG_LEVEL_ERROR,                                        \
            "Missing required symbol '%s' from CSFLE dynamic library [%s]",    \
            symname,                                                           \
            filepath);                                                         \
         /* Mark the vtable as broken, but keep trying to load more symbols to \
          * produce error messages for all missing symbols */                  \
         vtable_okay = false;                                                  \
      }                                                                        \
   }
   MONGOC_CSFLE_FUNCTIONS_X
#undef X_FUNC

   if (!vtable_okay) {
      mcr_dll_close (lib);
      _mongocrypt_log (
         log,
         MONGOCRYPT_LOG_LEVEL_ERROR,
         "One or more required symbols are missing from CSFLE dynamic library "
         "[%s], so this dynamic library will not be used.",
         filepath);
      return (_loaded_csfle){.okay = false};
   }

   // Success!
   _mongocrypt_log (log,
                    MONGOCRYPT_LOG_LEVEL_INFO,
                    "Opened CSFLE dynamic library [%s]",
                    filepath);
   return (_loaded_csfle){.okay = true, .lib = lib, .vtable = vtable};
}

/**
 * @brief If the leading path element in `filepath` is $ORIGIN, replace that
 * with the directory containing the current executing module.
 *
 * @return true If no error occurred and the path is valid
 * @return false If there was an error and `filepath` cannot be processed
 */
bool
_try_replace_dollar_origin (mstr *filepath, _mongocrypt_log_t *log)
{
   const mstr_view dollar_origin = mstrv_lit ("$ORIGIN");
   if (!mstr_starts_with (filepath->view, dollar_origin)) {
      // Nothing to replace
      return true;
   }
   // Check that the next char is a path separator or end-of-string:
   char peek = filepath->data[dollar_origin.len];
   if (peek != 0 && !mpath_is_sep (peek, MPATH_NATIVE)) {
      // Not a single path element
      return true;
   }
   // Replace $ORIGIN with the directory of the current module
   const current_module_result self_exe_r = current_module_path ();
   if (self_exe_r.error) {
      // Failed to get the current module to load replace $ORIGIN
      mstr error = merror_system_error_string (self_exe_r.error);
      _mongocrypt_log (log,
                       MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Error while loading the executable module path for "
                       "substitution of $ORIGIN in CSFLE search path [%s]: %s",
                       filepath->data,
                       error.data);
      mstr_free (error);
      return false;
   }
   const mstr_view self_dir = mpath_parent (self_exe_r.path.view, MPATH_NATIVE);
   mstr_inplace_splice (filepath, 0, dollar_origin.len, self_dir);
   mstr_free (self_exe_r.path);
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

   if (!mongocrypt_status_ok (crypt->status)) {
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

   mcr_dll_close (crypt->csfle_lib);

   mstr csfle_cand_filepath = MSTR_NULL;
   if (crypt->opts.csfle_lib_override_path.data) {
      // If an override path was specified, skip the library searching behavior
      csfle_cand_filepath =
         mstr_copy (crypt->opts.csfle_lib_override_path.view);
      if (_try_replace_dollar_origin (&csfle_cand_filepath, &crypt->log)) {
         // Succesfully substituted $ORIGIN
         // Do not allow a plain filename to go through, as that will cause the
         // DLL load to search the system.
         mstr_assign (&csfle_cand_filepath,
                      mpath_absolute (csfle_cand_filepath.view, MPATH_NATIVE));
         _loaded_csfle candidate =
            _try_load_csfle (csfle_cand_filepath.data, &crypt->log);
         if (candidate.okay) {
            // Successfully loaded
            crypt->csfle_vtable = candidate.vtable;
            crypt->csfle_lib = candidate.lib;
         }
      }
   } else {
      // No override path was specified, so try to find it on the provided
      // search paths.
      for (int i = 0; i < crypt->opts.n_cselib_search_paths; ++i) {
         mstr_view cand_dir = crypt->opts.cselib_search_paths[i].view;
         mstr_view csfle_filename = mstrv_lit ("mongo_csfle_v1" MCR_DLL_SUFFIX);
         if (mstr_eq (cand_dir, mstrv_lit ("$SYSTEM"))) {
            // Caller wants us to search for the library on the system's default
            // library paths. Pass only the library's filename to cause dll_open
            // to search on the library paths.
            mstr_assign (&csfle_cand_filepath, mstr_copy (csfle_filename));
         } else {
            // Compose the candidate filepath:
            mstr_assign (&csfle_cand_filepath,
                         mpath_join (cand_dir, csfle_filename, MPATH_NATIVE));
            if (!_try_replace_dollar_origin (&csfle_cand_filepath,
                                             &crypt->log)) {
               // Error while substituting $ORIGIN
               continue;
            }
         }
         // Try to load the file:
         _loaded_csfle candidate =
            _try_load_csfle (csfle_cand_filepath.data, &crypt->log);
         if (candidate.okay) {
            // We got one:
            crypt->csfle_vtable = candidate.vtable;
            crypt->csfle_lib = candidate.lib;
            // Stop searching:
            break;
         }
      }
   }
   mstr_free (csfle_cand_filepath);

   // If a CSFLE override path was specified, but we did not succeed in loading
   // CSFLE, that is a hard-error.
   if (crypt->opts.csfle_lib_override_path.data &&
       !mcr_dll_is_open (crypt->csfle_lib)) {
      CLIENT_ERR ("A CSFLE override path was specified [%s], but we failed to "
                  "open a dynamic library at that location",
                  crypt->opts.csfle_lib_override_path.data);
      return false;
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
   _mongocrypt_cache_oauth_destroy (crypt->cache_oauth_azure);
   _mongocrypt_cache_oauth_destroy (crypt->cache_oauth_gcp);

#ifndef __linux__
   mcr_dll_close (crypt->csfle_lib);
#else
   /// NOTE: On Linux, skip closing the CSFLE library itself, since a bug in the
   /// way ld-linux and GCC interact causes static destructors to not run during
   /// dlclose(). Still, free the error string that may be non-null:
   mstr_free (crypt->csfle_lib.error_string);
#endif

   bson_free (crypt);
}


const char *
mongocrypt_csfle_version_string (const mongocrypt_t *crypt, uint32_t *len)
{
   if (!mcr_dll_is_open (crypt->csfle_lib)) {
      if (len) {
         *len = 0;
      }
      return NULL;
   }
   const char *version = crypt->csfle_vtable.get_version_str ();
   if (len) {
      *len = (uint32_t) (strlen (version));
   }
   return version;
}

uint64_t
mongocrypt_csfle_version (const mongocrypt_t *crypt)
{
   if (!mcr_dll_is_open (crypt->csfle_lib)) {
      return 0;
   }
   return crypt->csfle_vtable.get_version ();
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

bool
mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5 (
   mongocrypt_t *crypt,
   mongocrypt_hmac_fn sign_rsaes_pkcs1_v1_5,
   void *sign_ctx)
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

   if (crypt->opts.sign_rsaes_pkcs1_v1_5) {
      CLIENT_ERR ("signature hook already set");
      return false;
   }

   crypt->opts.sign_rsaes_pkcs1_v1_5 = sign_rsaes_pkcs1_v1_5;
   crypt->opts.sign_ctx = sign_ctx;
   return true;
}

bool
mongocrypt_setopt_kms_providers (mongocrypt_t *crypt,
                                 mongocrypt_binary_t *kms_providers)
{
   mongocrypt_status_t *status;
   bson_t as_bson;
   bson_iter_t iter;

   if (!crypt) {
      return false;
   }
   status = crypt->status;

   if (crypt->initialized) {
      CLIENT_ERR ("options cannot be set after initialization");
      return false;
   }

   if (!_mongocrypt_binary_to_bson (kms_providers, &as_bson) ||
       !bson_iter_init (&iter, &as_bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   while (bson_iter_next (&iter)) {
      const char *field_name;

      field_name = bson_iter_key (&iter);

      if (0 == strcmp (field_name, "azure")) {
         if (0 != (crypt->opts.kms_providers & MONGOCRYPT_KMS_PROVIDER_AZURE)) {
            CLIENT_ERR ("azure KMS provider already set");
            return false;
         }

         if (!_mongocrypt_parse_required_utf8 (
                &as_bson,
                "azure.tenantId",
                &crypt->opts.kms_provider_azure.tenant_id,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_parse_required_utf8 (
                &as_bson,
                "azure.clientId",
                &crypt->opts.kms_provider_azure.client_id,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_parse_required_utf8 (
                &as_bson,
                "azure.clientSecret",
                &crypt->opts.kms_provider_azure.client_secret,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_parse_optional_endpoint (
                &as_bson,
                "azure.identityPlatformEndpoint",
                &crypt->opts.kms_provider_azure.identity_platform_endpoint,
                NULL /* opts */,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_check_allowed_fields (&as_bson,
                                                "azure",
                                                crypt->status,
                                                "tenantId",
                                                "clientId",
                                                "clientSecret",
                                                "identityPlatformEndpoint")) {
            return false;
         }
         crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_AZURE;
      } else if (0 == strcmp (field_name, "gcp")) {
         if (0 != (crypt->opts.kms_providers & MONGOCRYPT_KMS_PROVIDER_GCP)) {
            CLIENT_ERR ("gcp KMS provider already set");
            return false;
         }

         if (!_mongocrypt_parse_required_utf8 (
                &as_bson,
                "gcp.email",
                &crypt->opts.kms_provider_gcp.email,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_parse_required_binary (
                &as_bson,
                "gcp.privateKey",
                &crypt->opts.kms_provider_gcp.private_key,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_parse_optional_endpoint (
                &as_bson,
                "gcp.endpoint",
                &crypt->opts.kms_provider_gcp.endpoint,
                NULL /* opts */,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_check_allowed_fields (&as_bson,
                                                "gcp",
                                                crypt->status,
                                                "email",
                                                "privateKey",
                                                "endpoint")) {
            return false;
         }
         crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_GCP;
      } else if (0 == strcmp (field_name, "local")) {
         if (!_mongocrypt_parse_required_binary (
                &as_bson,
                "local.key",
                &crypt->opts.kms_provider_local.key,
                crypt->status)) {
            return false;
         }

         if (crypt->opts.kms_provider_local.key.len != MONGOCRYPT_KEY_LEN) {
            CLIENT_ERR ("local key must be %d bytes", MONGOCRYPT_KEY_LEN);
            return false;
         }

         if (!_mongocrypt_check_allowed_fields (
                &as_bson, "local", crypt->status, "key")) {
            return false;
         }
         crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
      } else if (0 == strcmp (field_name, "aws")) {
         if (!_mongocrypt_parse_required_utf8 (
                &as_bson,
                "aws.accessKeyId",
                &crypt->opts.kms_provider_aws.access_key_id,
                crypt->status)) {
            return false;
         }
         if (!_mongocrypt_parse_required_utf8 (
                &as_bson,
                "aws.secretAccessKey",
                &crypt->opts.kms_provider_aws.secret_access_key,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_parse_optional_utf8 (
                &as_bson,
                "aws.sessionToken",
                &crypt->opts.kms_provider_aws.session_token,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_check_allowed_fields (&as_bson,
                                                "aws",
                                                crypt->status,
                                                "accessKeyId",
                                                "secretAccessKey",
                                                "sessionToken")) {
            return false;
         }
         crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
      } else if (0 == strcmp (field_name, "kmip")) {
         _mongocrypt_endpoint_parse_opts_t opts = {0};

         opts.allow_empty_subdomain = true;
         if (!_mongocrypt_parse_required_endpoint (
                &as_bson,
                "kmip.endpoint",
                &crypt->opts.kms_provider_kmip.endpoint,
                &opts,
                crypt->status)) {
            return false;
         }

         if (!_mongocrypt_check_allowed_fields (
                &as_bson, "kmip", crypt->status, "endpoint")) {
            return false;
         }
         crypt->opts.kms_providers |= MONGOCRYPT_KMS_PROVIDER_KMIP;
      } else {
         CLIENT_ERR ("unsupported KMS provider: %s", field_name);
         return false;
      }
   }

   if (crypt->log.trace_enabled) {
      char *as_str = bson_as_json (&as_bson, NULL);
      _mongocrypt_log (&crypt->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%s\")",
                       BSON_FUNC,
                       "kms_providers",
                       as_str);
      bson_free (as_str);
   }

   return true;
}


void
mongocrypt_setopt_append_csfle_search_path (mongocrypt_t *crypt,
                                            const char *path)
{
   // Dup the path string for us to manage
   mstr pathdup = mstr_copy_cstr (path);
   // Increase array len
   const int new_len = crypt->opts.n_cselib_search_paths + 1;
   mstr *const new_array =
      bson_realloc (crypt->opts.cselib_search_paths, sizeof (mstr) * new_len);
   // Store the path
   new_array[new_len - 1] = pathdup;
   // Write back opts
   crypt->opts.cselib_search_paths = new_array;
   crypt->opts.n_cselib_search_paths = new_len;
}


void
mongocrypt_setopt_set_csfle_lib_path_override (mongocrypt_t *crypt,
                                               const char *path)
{
   mstr_assign (&crypt->opts.csfle_lib_override_path, mstr_copy_cstr (path));
}
