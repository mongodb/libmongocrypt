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

typedef struct _mongoc_crypt_t mongoc_crypt_t;
typedef struct _mongoc_crypt_opts_t mongoc_crypt_opts_t;
typedef enum {
   MONGOCRYPT_AWS_REGION,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY,
   MONGOCRYPT_AWS_ACCESS_KEY_ID,
   MONGOCRYPT_MONGOCRYPTD_URI,
   MONGOCRYPT_DEFAULT_KEYVAULT_CLIENT_URI
} mongoc_crypt_opt_t;

typedef struct _mongoc_crypt_error_t {
   uint32_t domain;
   uint32_t code;
   char message[1024];
} mongoc_crypt_error_t;

typedef struct {
   uint8_t* data;
   uint32_t len;
} mongoc_crypt_bson_t;

void
mongoc_crypt_init();

void
mongoc_crypt_cleanup();

mongoc_crypt_opts_t *
mongoc_crypt_opts_new (void);

void
mongoc_crypt_opts_destroy (mongoc_crypt_opts_t* opts);

void
mongoc_crypt_opts_set_opt (mongoc_crypt_opts_t* opts,
                           mongoc_crypt_opt_t opt,
                           void* value);

mongoc_crypt_t *
mongoc_crypt_new (mongoc_crypt_opts_t* opts, mongoc_crypt_error_t *error);

void
mongoc_crypt_destroy (mongoc_crypt_t *crypt);

int
mongoc_crypt_encrypt (mongoc_crypt_t *crypt,
                      const mongoc_crypt_bson_t *bson_schema,
                      const mongoc_crypt_bson_t *bson_doc,
                      mongoc_crypt_bson_t *bson_out,
                      mongoc_crypt_error_t *error);

int
mongoc_crypt_decrypt (mongoc_crypt_t *crypt,
                      const mongoc_crypt_bson_t *bson_doc,
                      mongoc_crypt_bson_t *bson_out,
                      mongoc_crypt_error_t *error);

#endif