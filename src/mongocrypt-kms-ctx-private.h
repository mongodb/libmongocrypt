/*
 * Copyright 2019-present MongoDB, Inc.
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

#ifndef MONGOCRYPT_KMX_CTX_PRIVATE_H
#define MONGOCRYPT_KMX_CTX_PRIVATE_H

#include "mongocrypt.h"
#include "mongocrypt-compat.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-key-cache-private.h"
#include "mongocrypt-opts-private.h"
#include "kms_message/kms_message.h"

typedef enum {
   MONGOCRYPT_KMS_ENCRYPT,
   MONGOCRYPT_KMS_DECRYPT
} _kms_request_type_t;

struct _mongocrypt_kms_ctx_t {
   kms_request_t *req;
   _kms_request_type_t req_type;
   kms_response_parser_t *parser;
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t msg;
   void *ctx;
   _mongocrypt_buffer_t result;
   char *endpoint;
};


bool
_mongocrypt_kms_ctx_init (mongocrypt_kms_ctx_t *kms,
                          _mongocrypt_opts_t *crypt_opts,
                          _mongocrypt_key_t *key,
                          _kms_request_type_t request_type,
                          void *ctx);


bool
_mongocrypt_kms_ctx_result (mongocrypt_kms_ctx_t *kms,
                            _mongocrypt_buffer_t *out);

void
_mongocrypt_kms_ctx_cleanup (mongocrypt_kms_ctx_t *kms);

#endif /* MONGOCRYPT_KMX_CTX_PRIVATE_H */
