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

#ifndef MONGOCRYPT_OPTS_PRIVATE_H
#define MONGOCRYPT_OPTS_PRIVATE_H

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-endpoint-private.h"

/* KMS providers are used in a bit set.
 *
 * Check for set membership using bitwise and:
 *   int kms_set = fn();
 *   if (kms_set & MONGOCRYPT_KMS_PROVIDER_AWS)
 * Add to a set using bitwise or:
 *   kms_set |= MONGOCRYPT_KMS_PROVIDER_LOCAL
 */
typedef enum {
   MONGOCRYPT_KMS_PROVIDER_NONE = 0,
   MONGOCRYPT_KMS_PROVIDER_AWS = 1 << 0,
   MONGOCRYPT_KMS_PROVIDER_LOCAL = 1 << 1,
   MONGOCRYPT_KMS_PROVIDER_AZURE = 1 << 2,
   MONGOCRYPT_KMS_PROVIDER_GCP = 1 << 3
} _mongocrypt_kms_provider_t;

typedef struct {
   char *tenant_id;
   char *client_id;
   char *client_secret;
   _mongocrypt_endpoint_t *identity_platform_endpoint;
} _mongocrypt_opts_kms_provider_azure_t;

typedef struct {
   char *email;
   _mongocrypt_buffer_t private_key;
   _mongocrypt_endpoint_t *endpoint;
} _mongocrypt_opts_kms_provider_gcp_t;

typedef struct {
   int kms_providers; /* A bit set of _mongocrypt_kms_provider_t */
   char *kms_aws_secret_access_key;    /* Set for AWS provider. */
   char *kms_aws_access_key_id;        /* Set for AWS provider. */
   _mongocrypt_buffer_t kms_local_key; /* Set for local provider. */
   mongocrypt_log_fn_t log_fn;
   void *log_ctx;
   _mongocrypt_buffer_t schema_map;
   _mongocrypt_opts_kms_provider_azure_t kms_provider_azure;
   _mongocrypt_opts_kms_provider_gcp_t kms_provider_gcp;
   mongocrypt_hmac_fn sign_rsaes_pkcs1_v1_5;
   void *sign_ctx;
} _mongocrypt_opts_t;


void
_mongocrypt_opts_init (_mongocrypt_opts_t *opts);


void
_mongocrypt_opts_cleanup (_mongocrypt_opts_t *opts);


bool
_mongocrypt_opts_validate (_mongocrypt_opts_t *opts,
                           mongocrypt_status_t *status)
   MONGOCRYPT_WARN_UNUSED_RESULT;

/*
 * Parse an optional UTF-8 value from BSON.
 * @dotkey may be a dot separated key like: "a.b.c".
 * @*out is set to a copy of the string if found, NULL otherwise. Caller must
 * clean up with bson_free (*out).
 * Returns true if no error occured.
 */
bool
_mongocrypt_parse_optional_utf8 (bson_t *bson,
                                 const char *dotkey,
                                 char **out,
                                 mongocrypt_status_t *status);

/*
 * Parse a required UTF-8 value from BSON.
 * @dotkey may be a dot separated key like: "a.b.c".
 * @*out is set to a copy of the string if found, NULL otherwise. Caller must
 * clean up with bson_free (*out).
 * Returns true if no error occured.
 */
bool
_mongocrypt_parse_required_utf8 (bson_t *bson,
                                 const char *dotkey,
                                 char **out,
                                 mongocrypt_status_t *status);

/*
 * Parse an optional endpoint UTF-8 from BSON.
 * @dotkey may be a dot separated key like: "a.b.c".
 * @*out is set to a new _mongocrypt_endpoint_t of the if found, NULL otherwise.
 * Caller must clean up with _mongocrypt_endpoint_destroy (*out).
 * Returns true if no error occured.
 */
bool
_mongocrypt_parse_optional_endpoint (bson_t *bson,
                                     const char *dotkey,
                                     _mongocrypt_endpoint_t **out,
                                     mongocrypt_status_t *status);

/*
 * Parse a required endpoint UTF-8 from BSON.
 * @dotkey may be a dot separated key like: "a.b.c".
 * @*out is set to a new _mongocrypt_endpoint_t of the if found, NULL otherwise.
 * Caller must clean up with _mongocrypt_endpoint_destroy (*out).
 * Returns true if no error occured.
 */
bool
_mongocrypt_parse_required_endpoint (bson_t *bson,
                                     const char *dotkey,
                                     _mongocrypt_endpoint_t **out,
                                     mongocrypt_status_t *status);

/*
 * Parse an optional binary type from BSON.
 * The field parsed is accepted as:
 * - A BSON binary value (of any subtype).
 * - A BSON UTF-8 value, set to base64 encoded data.
 *
 * @dotkey may be a dot separated key like: "a.b.c"
 * @out is initialized with the parsed data, or initialized to empty on error.
 * Caller must clean up with _mongocrypt_buffer_cleanup (out).
 * Returns true if no error occurred.
 */
bool
_mongocrypt_parse_optional_binary (bson_t *bson,
                                   const char *dotkey,
                                   _mongocrypt_buffer_t *out,
                                   mongocrypt_status_t *status);

/*
 * Parse a required binary type from BSON.
 * The field parsed is accepted as:
 * - A BSON binary value (of any subtype).
 * - A BSON UTF-8 value, set to base64 encoded data.
 *
 * @dotkey may be a dot separated key like: "a.b.c"
 * @out is initialized with the parsed data, or initialized to empty on error.
 * Caller must clean up with _mongocrypt_buffer_cleanup (out).
 * Returns true if no error occurred.
 */
bool
_mongocrypt_parse_required_binary (bson_t *bson,
                                   const char *dotkey,
                                   _mongocrypt_buffer_t *out,
                                   mongocrypt_status_t *status);

#endif /* MONGOCRYPT_OPTS_PRIVATE_H */
