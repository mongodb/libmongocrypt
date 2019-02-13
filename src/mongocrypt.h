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

#include "mongocrypt-compat.h"
#include <stdint.h>

/* The typedef for key query is in here */
#include "mongocrypt-key-query.h"

#define MONGOCRYPT_VERSION "0.2.0"


const char *
mongocrypt_version (void);


typedef struct _mongocrypt_t mongocrypt_t;


typedef struct _mongocrypt_opts_t mongocrypt_opts_t;


typedef enum {
   MONGOCRYPT_AWS_REGION,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY,
   MONGOCRYPT_AWS_ACCESS_KEY_ID,
   MONGOCRYPT_AWS_KMS_URI,
   MONGOCRYPT_MONGOCRYPTD_URI
} mongocrypt_opt_t;


typedef enum {
   MONGOCRYPT_ERROR_TYPE_NONE,
   MONGOCRYPT_ERROR_TYPE_MONGOCRYPTD,
   MONGOCRYPT_ERROR_TYPE_KMS,
   MONGOCRYPT_ERROR_TYPE_CLIENT
} mongocrypt_error_type_t;


typedef struct _mongocrypt_status_t mongocrypt_status_t;


typedef struct _mongocrypt_request_t mongocrypt_request_t;


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
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status);


void
mongocrypt_destroy (mongocrypt_t *crypt);


void
mongocrypt_status_destroy (mongocrypt_status_t *status);


mongocrypt_status_t *
mongocrypt_status_new (void);


mongocrypt_error_type_t
mongocrypt_status_error_type (mongocrypt_status_t *status);


uint32_t
mongocrypt_status_code (mongocrypt_status_t *status);


const char *
mongocrypt_status_message (mongocrypt_status_t *status);


bool
mongocrypt_request_needs_keys (mongocrypt_request_t *request);


const mongocrypt_key_query_t *
mongocrypt_request_next_key_query (mongocrypt_request_t *request,
                                   const mongocrypt_opts_t *opts);


bool
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_status_t *status);


void
mongocrypt_request_destroy (mongocrypt_request_t *request);


mongocrypt_request_t *
mongocrypt_encrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *schema,
                          const mongocrypt_binary_t *cmd,
                          mongocrypt_status_t *status);


bool
mongocrypt_encrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t *encrypted_cmd,
                           mongocrypt_status_t *status);


mongocrypt_request_t *
mongocrypt_decrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *encrypted_docs,
                          uint32_t num_docs,
                          mongocrypt_status_t *status);


bool
mongocrypt_decrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t **docs,
                           mongocrypt_status_t *status);
#endif
