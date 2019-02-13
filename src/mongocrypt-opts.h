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

#ifndef OPTS_H
#define OPTS_H

typedef struct _mongocrypt_opts_t mongocrypt_opts_t;

typedef enum {
   MONGOCRYPT_AWS_REGION,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY,
   MONGOCRYPT_AWS_ACCESS_KEY_ID,
   MONGOCRYPT_AWS_KMS_URI,
   MONGOCRYPT_MONGOCRYPTD_URI
} mongocrypt_opt_t;

mongocrypt_opts_t *
mongocrypt_opts_new (void);


void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts);


void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value);


#endif /* OPTS_H */
