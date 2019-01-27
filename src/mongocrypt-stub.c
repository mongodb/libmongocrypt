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

#include <stddef.h>
#include <unistd.h>

#include "mongocrypt.h"

#if defined(_WIN32)
#define BSON_FUNC __FUNCTION__
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ < 199901L
#define BSON_FUNC __FUNCTION__
#else
#define BSON_FUNC __func__
#endif

#ifdef MONGOCRYPT_TRACE
#define CRYPT_ENTRY                                             \
   do {                                                         \
      if (getenv ("MONGOCRYPT_TRACE")) {                        \
         printf ("[CRYPT entry] %s:%d\n", BSON_FUNC, __LINE__); \
      }                                                         \
   } while (0)
#else
#define TRACE(msg, ...)
#define CRYPT_ENTRY
#endif

char *
mongocrypt_version (void)
{
   return MONGOCRYPT_VERSION;
}


void
mongocrypt_init (void)
{
   CRYPT_ENTRY;
}


void
mongocrypt_cleanup (void)
{
   CRYPT_ENTRY;
}


mongocrypt_opts_t *
mongocrypt_opts_new (void)
{
   CRYPT_ENTRY;
   return NULL;
}


void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts)
{
   CRYPT_ENTRY;
}


void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value)
{
   CRYPT_ENTRY;
}

mongocrypt_t *
mongocrypt_new (mongocrypt_opts_t *opts, mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   return NULL;
}

void
mongocrypt_destroy (mongocrypt_t *crypt)
{
   CRYPT_ENTRY;
}


void
mongocrypt_error_destroy (mongocrypt_error_t *error)
{
   CRYPT_ENTRY;
}


mongocrypt_error_type_t
mongocrypt_error_type (mongocrypt_error_t *error)
{
   CRYPT_ENTRY;
   return MONGOCRYPT_ERROR_TYPE_CLIENT;
}


uint32_t
mongocrypt_error_code (mongocrypt_error_t *error)
{
   CRYPT_ENTRY;
   return 0;
}


const char *
mongocrypt_error_message (mongocrypt_error_t *error)
{
   CRYPT_ENTRY;
   return "example error message";
}


void *
mongocrypt_error_ctx (mongocrypt_error_t *error)
{
   CRYPT_ENTRY;
   return NULL;
}


const mongocrypt_binary_t *
mongocrypt_key_query_filter (mongocrypt_key_query_t *key_query)
{
   CRYPT_ENTRY;
   return NULL;
}


const char *
mongocrypt_key_query_alias (mongocrypt_key_query_t *key_query)
{
   CRYPT_ENTRY;
   return NULL;
}


bool
mongocrypt_request_needs_keys (mongocrypt_request_t *request)
{
   CRYPT_ENTRY;
   return false;
}


mongocrypt_key_query_t *
mongocrypt_request_next_key_query (mongocrypt_request_t *request,
                                   mongocrypt_opts_t *opts)
{
   CRYPT_ENTRY;
   return NULL;
}


bool
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   sleep(1);
   return false;
}


void
mongocrypt_request_destroy (mongocrypt_request_t *request)
{
   CRYPT_ENTRY;
}


void
mongocrypt_error_cleanup (mongocrypt_error_t *error)
{
   CRYPT_ENTRY;
}


mongocrypt_request_t *
mongocrypt_encrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *schema,
                          const mongocrypt_binary_t *cmd,
                          mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   sleep(1);
   return NULL;
}


bool
mongocrypt_encrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t *encrypted_cmd,
                           mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   return false;
}


mongocrypt_request_t *
mongocrypt_decrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *encrypted_docs,
                          uint32_t num_docs,
                          mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   return NULL;
}


bool
mongocrypt_decrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t **docs,
                           mongocrypt_error_t **error)
{
   CRYPT_ENTRY;
   return false;
}