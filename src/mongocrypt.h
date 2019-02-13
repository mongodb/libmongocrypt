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

#define MONGOCRYPT_VERSION "0.2.0"

#include "mongocrypt-binary.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-request.h"
#include "mongocrypt-status.h"

const char *
mongocrypt_version (void);

typedef struct _mongocrypt_t mongocrypt_t;

void
mongocrypt_init (void);


void
mongocrypt_cleanup (void);


mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status);


void
mongocrypt_destroy (mongocrypt_t *crypt);

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
