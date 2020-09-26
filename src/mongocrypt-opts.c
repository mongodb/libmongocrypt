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
_mongocrypt_opts_cleanup (_mongocrypt_opts_t *opts)
{
   bson_free (opts->kms_aws_secret_access_key);
   bson_free (opts->kms_aws_access_key_id);
   _mongocrypt_buffer_cleanup (&opts->kms_local_key);
   _mongocrypt_buffer_cleanup (&opts->schema_map);
   _mongocrypt_opts_kms_provider_azure_cleanup (&opts->kms_provider_azure);
   _mongocrypt_opts_kms_provider_gcp_cleanup (&opts->kms_provider_gcp);
}


bool
_mongocrypt_opts_validate (_mongocrypt_opts_t *opts,
                           mongocrypt_status_t *status)
{
   if (!opts->kms_providers) {
      CLIENT_ERR ("no kms provider set");
      return false;
   }

   if (opts->kms_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
      if (!opts->kms_aws_access_key_id || !opts->kms_aws_secret_access_key) {
         CLIENT_ERR ("aws credentials unset");
         return false;
      }
   }

   if (opts->kms_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      if (_mongocrypt_buffer_empty (&opts->kms_local_key)) {
         CLIENT_ERR ("local data key unset");
         return false;
      }
   }

   return true;
}

bool
_mongocrypt_parse_optional_utf8 (bson_t *bson,
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
_mongocrypt_parse_required_utf8 (bson_t *bson,
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
_mongocrypt_parse_optional_endpoint (bson_t *bson,
                                     const char *dotkey,
                                     _mongocrypt_endpoint_t **out,
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

   *out = _mongocrypt_endpoint_new (endpoint_raw, -1, status);
   bson_free (endpoint_raw);
   return (*out) != NULL;
}

bool
_mongocrypt_parse_required_endpoint (bson_t *bson,
                                     const char *dotkey,
                                     _mongocrypt_endpoint_t **out,
                                     mongocrypt_status_t *status)
{
   if (!_mongocrypt_parse_optional_endpoint (bson, dotkey, out, status)) {
      return false;
   }

   if (!*out) {
      CLIENT_ERR ("expected endpoint %s", dotkey);
      return false;
   }

   return true;
}


bool
_mongocrypt_parse_optional_binary (bson_t *bson,
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
_mongocrypt_parse_required_binary (bson_t *bson,
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