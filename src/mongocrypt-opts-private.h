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

#include "mongocrypt.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-log-private.h"

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
   MONGOCRYPT_KMS_PROVIDER_LOCAL = 1 << 1
} _mongocrypt_kms_provider_t;


typedef struct {
   int kms_providers; /* A bit set of _mongocrypt_kms_provider_t */
   char *kms_aws_secret_access_key;    /* Set for AWS provider. */
   char *kms_aws_access_key_id;        /* Set for AWS provider. */
   _mongocrypt_buffer_t kms_local_key; /* Set for local provider. */
   mongocrypt_log_fn_t log_fn;
   void *log_ctx;
   _mongocrypt_buffer_t schema_map;
} _mongocrypt_opts_t;


void
_mongocrypt_opts_init (_mongocrypt_opts_t *opts);


void
_mongocrypt_opts_cleanup (_mongocrypt_opts_t *opts);


bool
_mongocrypt_opts_validate (_mongocrypt_opts_t *opts,
                           mongocrypt_status_t *status)
   MONGOCRYPT_WARN_UNUSED_RESULT;


#endif /* MONGOCRYPT_OPTS_PRIVATE_H */
