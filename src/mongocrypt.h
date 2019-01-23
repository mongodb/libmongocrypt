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

/* TODO: instead of int, consider using bool. Consider copying over what
 * bson-compat does. */

#define MONGOCRYPT_VERSION "0.1.0"

char *
mongocrypt_version (void);

typedef struct _mongocrypt_t mongocrypt_t;
typedef struct _mongocrypt_opts_t mongocrypt_opts_t;
typedef enum {
   MONGOCRYPT_AWS_REGION,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY,
   MONGOCRYPT_AWS_ACCESS_KEY_ID,
   MONGOCRYPT_MONGOCRYPTD_URI,
   MONGOCRYPT_DEFAULT_KEYVAULT_CLIENT_URI
} mongocrypt_opt_t;

typedef enum {
   MONGOCRYPT_ERROR_TYPE_MONGOCRYPTD,
   MONGOCRYPT_ERROR_TYPE_KMS,
   MONGOCRYPT_ERROR_TYPE_CLIENT
} mongocrypt_error_type_t;

typedef struct {
   uint8_t *data;
   uint32_t len;
} mongocrypt_binary_t; /* TODO: likely rename to BSON */

typedef struct _mongocrypt_error_t mongocrypt_error_t;

typedef struct _mongocrypt_key_query_t mongocrypt_key_query_t;

const mongocrypt_binary_t *
mongocrypt_key_query_filter (mongocrypt_key_query_t *key_query);

const char *
mongocrypt_key_query_alias (mongocrypt_key_query_t *key_query);

void
mongocrypt_error_destroy (mongocrypt_error_t *error);

mongocrypt_error_type_t
mongocrypt_error_type (mongocrypt_error_t *error);

uint32_t
mongocrypt_error_code (mongocrypt_error_t *error);

const char *
mongocrypt_error_message (mongocrypt_error_t *error);

void *
mongocrypt_error_ctx (mongocrypt_error_t *error);

typedef struct _mongocrypt_request_t mongocrypt_request_t;

int
mongocrypt_request_needs_keys (mongocrypt_request_t *request);

mongocrypt_key_query_t *
mongocrypt_request_next_key_query (mongocrypt_request_t *request,
                                   mongocrypt_opts_t *opts);

int
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_error_t **error);


void
mongocrypt_request_destroy (mongocrypt_request_t *request);

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
mongocrypt_new (mongocrypt_opts_t *opts, mongocrypt_error_t **error);

void
mongocrypt_destroy (mongocrypt_t *crypt);

void
mongocrypt_error_cleanup (mongocrypt_error_t *error);

mongocrypt_request_t *
mongocrypt_encrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *schema,
                          const mongocrypt_binary_t *cmd,
                          mongocrypt_error_t **error);

int
mongocrypt_encrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t *encrypted_cmd,
                           mongocrypt_error_t **error);

int
mongocrypt_encrypt (mongocrypt_t *crypt,
                    const mongocrypt_binary_t *bson_schema,
                    const mongocrypt_binary_t *bson_doc,
                    mongocrypt_binary_t *bson_out,
                    mongocrypt_error_t **error);


int
mongocrypt_decrypt (mongocrypt_t *crypt,
                    const mongocrypt_binary_t *bson_doc,
                    mongocrypt_binary_t *bson_out,
                    mongocrypt_error_t **error);

#endif