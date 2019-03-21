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
#include "mongocrypt-log-private.h"

struct _mongocrypt_opts_t {
   char *aws_region;
   char *aws_secret_access_key;
   char *aws_access_key_id;
   mongocrypt_log_fn_t log_fn;
   void *log_ctx;
};

mongocrypt_opts_t *
_mongocrypt_opts_copy (const mongocrypt_opts_t *src);

#endif /* MONGOCRYPT_OPTS_PRIVATE_H */
