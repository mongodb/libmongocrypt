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
#ifndef MONGOCRYPT_MONGOCCRYPT_H
#define MONGOCRYPT_MONGOCCRYPT_H

#include <stdint.h>

typedef struct _mongocrypt_t mongocrypt_t;
typedef struct _mongocrypt_opts_t mongocrypt_opts_t;
typedef enum {
   MONGOCRYPT_AWS_REGION,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY,
   MONGOCRYPT_AWS_ACCESS_KEY_ID,
   MONGOCRYPT_MONGOCRYPTD_URI,
   MONGOCRYPT_DEFAULT_KEYVAULT_CLIENT_URI
} mongocrypt_opt_t;

typedef struct _mongocrypt_error_t {
   uint32_t domain;
   uint32_t code;
   char message[1024];
} mongocrypt_error_t;

typedef struct {
   uint8_t *data;
   uint32_t len;
} mongocrypt_bson_t;

void
mongocrypt_init (void);

void
mongocrypt_cleanup (void);

mongocrypt_opts_t *
mongocrypt_opts_new (void);

void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts);

void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value);

mongocrypt_t *
mongocrypt_new (mongocrypt_opts_t *opts, mongocrypt_error_t *error);

void
mongocrypt_destroy (mongocrypt_t *crypt);

int
mongocrypt_encrypt (mongocrypt_t *crypt,
                    const mongocrypt_bson_t *bson_schema,
                    const mongocrypt_bson_t *bson_doc,
                    mongocrypt_bson_t *bson_out,
                    mongocrypt_error_t *error);

int
mongocrypt_decrypt (mongocrypt_t *crypt,
                    const mongocrypt_bson_t *bson_doc,
                    mongocrypt_bson_t *bson_out,
                    mongocrypt_error_t *error);

#endif