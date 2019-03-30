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
   bson_free (opts->aws_secret_access_key);
   bson_free (opts->aws_access_key_id);
}


bool
_mongocrypt_opts_validate (_mongocrypt_opts_t *opts,
                           mongocrypt_status_t *status)
{
   if (!opts->aws_secret_access_key) {
      CLIENT_ERR ("required kms provider option aws_secret_access_key unset");
      return false;
   }
   if (!opts->aws_access_key_id) {
      CLIENT_ERR ("required kms provider option aws_access_key_id unset");
      return false;
   }
   return true;
}
