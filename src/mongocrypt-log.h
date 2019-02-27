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
#ifndef MONGOCRYPT_LOG_H
#define MONGOCRYPT_LOG_H

#include "mongocrypt-private.h"

/* TRACE messages are only generated if libmongocrypt is compiled with
 * ENABLE_TRACING=ON.
 * They are only logged at runtime if the MONGOCRYPT_TRACE environment variable
 * is set.
 */
typedef enum {
   MONGOCRYPT_LOG_LEVEL_FATAL,
   MONGOCRYPT_LOG_LEVEL_ERROR,
   MONGOCRYPT_LOG_LEVEL_WARNING,
   MONGOCRYPT_LOG_LEVEL_INFO,
   MONGOCRYPT_LOG_LEVEL_TRACE
} mongocrypt_log_level_t;

/* Specify a custom log callback by setting the MONGOCRYPT_LOG_FN and
 * MONGOCRYPT_LOG_CTX options in mongocrypt_init.
 * Calls to the log callback are protected with a mutex.
 */
typedef void (*mongocrypt_log_fn_t) (mongocrypt_log_level_t level,
                                     const char *message,
                                     void *ctx);

#endif /* MONGOCRYPT_LOG_H */