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

#include <mongoc/mongoc.h>

#include "mongocrypt-opts-private.h"

mongocrypt_opts_t *
mongocrypt_opts_new (void)
{
   return bson_malloc0 (sizeof (mongocrypt_opts_t));
}


void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts)
{
   bson_free (opts->aws_region);
   bson_free (opts->aws_secret_access_key);
   bson_free (opts->aws_access_key_id);
   bson_free (opts->mongocryptd_uri);
   bson_free (opts);
}


mongocrypt_opts_t *
mongocrypt_opts_copy (const mongocrypt_opts_t *src)
{
   mongocrypt_opts_t *dst = bson_malloc0 (sizeof (mongocrypt_opts_t));
   dst->aws_region = bson_strdup (src->aws_region);
   dst->aws_secret_access_key = bson_strdup (src->aws_secret_access_key);
   dst->aws_access_key_id = bson_strdup (src->aws_access_key_id);
   dst->mongocryptd_uri = bson_strdup (src->mongocryptd_uri);
   return dst;
}


void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value)
{
   switch (opt) {
   case MONGOCRYPT_AWS_REGION:
      opts->aws_region = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_AWS_SECRET_ACCESS_KEY:
      opts->aws_secret_access_key = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_AWS_ACCESS_KEY_ID:
      opts->aws_access_key_id = bson_strdup ((char *) value);
      break;
   case MONGOCRYPT_MONGOCRYPTD_URI:
      opts->mongocryptd_uri = bson_strdup ((char *) value);
      break;
   default:
      fprintf (stderr, "Invalid option: %d\n", (int) opt);
      abort ();
   }
}
