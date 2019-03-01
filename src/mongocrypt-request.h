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

#ifndef MONGOCRYPT_REQUEST_H
#define MONGOCRYPT_REQUEST_H

#include "mongocrypt-binary.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-status.h"

typedef struct _mongocrypt_request_t mongocrypt_request_t;


bool
mongocrypt_request_needs_keys (mongocrypt_request_t *request);


bool
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_status_t *status);


void
mongocrypt_request_destroy (mongocrypt_request_t *request);


#endif /* MONGOCRYPT_REQUEST_H */
