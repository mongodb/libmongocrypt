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

void
_mongocrypt_opts_init (_mongocrypt_opts_t *opts)
{
   memset (opts, 0, sizeof (*opts));
}


void
_mongocrypt_opts_cleanup (_mongocrypt_opts_t *opts)
{
   bson_free (opts->kms_aws_secret_access_key);
   bson_free (opts->kms_aws_access_key_id);
   _mongocrypt_buffer_cleanup (&opts->kms_local_key);
   _mongocrypt_buffer_cleanup (&opts->schema_map);
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