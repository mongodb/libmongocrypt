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

#include <bson/bson.h>

#include "mongocrypt-opts-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"

#include <kms_message/kms_b64.h>

void
_mongocrypt_opts_init (_mongocrypt_opts_t *opts)
{
   memset (opts, 0, sizeof (*opts));
}

static void
_mongocrypt_opts_kms_provider_azure_cleanup (
   _mongocrypt_opts_kms_provider_azure_t *kms_provider_azure)
{
   bson_free (kms_provider_azure->client_id);
   bson_free (kms_provider_azure->client_secret);
   bson_free (kms_provider_azure->tenant_id);
   _mongocrypt_endpoint_destroy (
      kms_provider_azure->identity_platform_endpoint);
}

static void
_mongocrypt_opts_kms_provider_gcp_cleanup (
   _mongocrypt_opts_kms_provider_gcp_t *kms_provider_gcp)
{
   bson_free (kms_provider_gcp->email);
   _mongocrypt_endpoint_destroy (kms_provider_gcp->endpoint);
   _mongocrypt_buffer_cleanup (&kms_provider_gcp->private_key);
}

void
_mongocrypt_opts_kms_providers_cleanup (
   _mongocrypt_opts_kms_providers_t *kms_providers)
{
   bson_free (kms_providers->aws.secret_access_key);
   bson_free (kms_providers->aws.access_key_id);
   bson_free (kms_providers->aws.session_token);
   _mongocrypt_buffer_cleanup (&kms_providers->local.key);
   _mongocrypt_opts_kms_provider_azure_cleanup (&kms_providers->azure);
   _mongocrypt_opts_kms_provider_gcp_cleanup (&kms_providers->gcp);
   _mongocrypt_endpoint_destroy (kms_providers->kmip.endpoint);
}


void
_mongocrypt_opts_merge_kms_providers (
   _mongocrypt_opts_kms_providers_t* dest,
   const _mongocrypt_opts_kms_providers_t* source)
{
   if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
      memcpy(&dest->aws, &source->aws, sizeof(source->aws));
      dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
   }
   if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      memcpy(&dest->local, &source->local, sizeof(source->local));
      dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
   }
   if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_AZURE) {
      memcpy(&dest->azure, &source->azure, sizeof(source->azure));
      dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AZURE;
   }
   if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_GCP) {
      memcpy(&dest->gcp, &source->gcp, sizeof(source->gcp));
      dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_GCP;
   }
   if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_KMIP) {
      memcpy(&dest->kmip, &source->kmip, sizeof(source->kmip));
      dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_KMIP;
   }
   /* ensure all providers were copied */
   BSON_ASSERT (!(source->configured_providers &~ dest->configured_providers));
}


void
_mongocrypt_opts_cleanup (_mongocrypt_opts_t *opts)
{
   _mongocrypt_opts_kms_providers_cleanup (&opts->kms_providers);
   _mongocrypt_buffer_cleanup (&opts->schema_map);
   // Free any lib search paths added by the caller
   for (int i = 0; i < opts->n_cselib_search_paths; ++i) {
      mstr_free (opts->cselib_search_paths[i]);
   }
   bson_free (opts->cselib_search_paths);
   mstr_free (opts->csfle_lib_override_path);
}


bool
_mongocrypt_opts_kms_providers_validate (
   _mongocrypt_opts_kms_providers_t *kms_providers,
   bool allow_empty_providers,
   mongocrypt_status_t *status)
{
   if (!kms_providers->configured_providers && !allow_empty_providers) {
      CLIENT_ERR ("no kms provider set");
      return false;
   }

   if (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
      if (!kms_providers->aws.access_key_id ||
          !kms_providers->aws.secret_access_key) {
         CLIENT_ERR ("aws credentials unset");
         return false;
      }
   }

   if (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      if (_mongocrypt_buffer_empty (&kms_providers->local.key)) {
         CLIENT_ERR ("local data key unset");
         return false;
      }
   }

   return true;
}


bool
_mongocrypt_opts_validate (_mongocrypt_opts_t *opts,
                           mongocrypt_status_t *status)
{
   return _mongocrypt_opts_kms_providers_validate(
      &opts->kms_providers,
      /* providers list may be empty if on-demand KMS retrieval is used */
      opts->use_need_kms_credentials_state,
      status);
}

bool
_mongocrypt_parse_optional_utf8 (const bson_t *bson,
                                 const char *dotkey,
                                 char **out,
                                 mongocrypt_status_t *status)
{
   bson_iter_t iter;
   bson_iter_t child;

   *out = NULL;

   if (!bson_iter_init (&iter, bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }
   if (!bson_iter_find_descendant (&iter, dotkey, &child)) {
      /* Not found. Not an error. */
      return true;
   }
   if (!BSON_ITER_HOLDS_UTF8 (&child)) {
      CLIENT_ERR ("expected UTF-8 %s", dotkey);
      return false;
   }

   *out = bson_strdup (bson_iter_utf8 (&child, NULL));
   return true;
}


bool
_mongocrypt_parse_required_utf8 (const bson_t *bson,
                                 const char *dotkey,
                                 char **out,
                                 mongocrypt_status_t *status)
{
   if (!_mongocrypt_parse_optional_utf8 (bson, dotkey, out, status)) {
      return false;
   }

   if (!*out) {
      CLIENT_ERR ("expected UTF-8 %s", dotkey);
      return false;
   }

   return true;
}

bool
_mongocrypt_parse_optional_endpoint (const bson_t *bson,
                                     const char *dotkey,
                                     _mongocrypt_endpoint_t **out,
                                     _mongocrypt_endpoint_parse_opts_t *opts,
                                     mongocrypt_status_t *status)
{
   char *endpoint_raw;

   *out = NULL;

   if (!_mongocrypt_parse_optional_utf8 (bson, dotkey, &endpoint_raw, status)) {
      return false;
   }

   /* Not found. Not an error. */
   if (!endpoint_raw) {
      return true;
   }

   *out = _mongocrypt_endpoint_new (endpoint_raw, -1, opts, status);
   bson_free (endpoint_raw);
   return (*out) != NULL;
}

bool
_mongocrypt_parse_required_endpoint (const bson_t *bson,
                                     const char *dotkey,
                                     _mongocrypt_endpoint_t **out,
                                     _mongocrypt_endpoint_parse_opts_t *opts,
                                     mongocrypt_status_t *status)
{
   if (!_mongocrypt_parse_optional_endpoint (bson, dotkey, out, opts, status)) {
      return false;
   }

   if (!*out) {
      CLIENT_ERR ("expected endpoint %s", dotkey);
      return false;
   }

   return true;
}


bool
_mongocrypt_parse_optional_binary (const bson_t *bson,
                                   const char *dotkey,
                                   _mongocrypt_buffer_t *out,
                                   mongocrypt_status_t *status)
{
   bson_iter_t iter;
   bson_iter_t child;

   _mongocrypt_buffer_init (out);

   if (!bson_iter_init (&iter, bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }
   if (!bson_iter_find_descendant (&iter, dotkey, &child)) {
      /* Not found. Not an error. */
      return true;
   }
   if (BSON_ITER_HOLDS_UTF8 (&child)) {
      size_t out_len;
      /* Attempt to base64 decode. */
      out->data =
         kms_message_b64_to_raw (bson_iter_utf8 (&child, NULL), &out_len);
      if (!out->data) {
         CLIENT_ERR ("unable to parse base64 from UTF-8 field %s", dotkey);
         return false;
      }
      out->len = (uint32_t) out_len;
      out->owned = true;
   } else if (BSON_ITER_HOLDS_BINARY (&child)) {
      if (!_mongocrypt_buffer_copy_from_binary_iter (out, &child)) {
         CLIENT_ERR ("unable to parse binary from field %s", dotkey);
         return false;
      }
   } else {
      CLIENT_ERR ("expected UTF-8 or binary %s", dotkey);
      return false;
   }


   return true;
}

bool
_mongocrypt_parse_required_binary (const bson_t *bson,
                                   const char *dotkey,
                                   _mongocrypt_buffer_t *out,
                                   mongocrypt_status_t *status)
{
   if (!_mongocrypt_parse_optional_binary (bson, dotkey, out, status)) {
      return false;
   }

   if (out->len == 0) {
      CLIENT_ERR ("expected UTF-8 or binary %s", dotkey);
      return false;
   }

   return true;
}

bool
_mongocrypt_check_allowed_fields_va (const bson_t *bson,
                                     const char *dotkey,
                                     mongocrypt_status_t *status,
                                     ...)
{
   va_list args;
   const char *field;
   bson_iter_t iter;

   if (dotkey) {
      bson_iter_t parent;

      bson_iter_init (&parent, bson);
      if (!bson_iter_find_descendant (&parent, dotkey, &iter) ||
          !BSON_ITER_HOLDS_DOCUMENT (&iter)) {
         CLIENT_ERR ("invalid BSON, expected %s", dotkey);
         return false;
      }
      bson_iter_recurse (&iter, &iter);
   } else {
      bson_iter_init (&iter, bson);
   }

   while (bson_iter_next (&iter)) {
      bool found = false;

      va_start (args, status);
      field = va_arg (args, const char *);
      while (field) {
         if (0 == strcmp (field, bson_iter_key (&iter))) {
            found = true;
            break;
         }
         field = va_arg (args, const char *);
      }
      va_end (args);

      if (!found) {
         CLIENT_ERR ("Unexpected field: '%s'", bson_iter_key (&iter));
         return false;
      }
   }
   return true;
}
