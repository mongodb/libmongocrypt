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

#ifndef MONGOCRYPT_LOG_PRIVATE_H
#define MONGOCRYPT_LOG_PRIVATE_H

#include "mongocrypt-log.h"
#include "mongocrypt-private.h"

void
_mongocrypt_default_log_fn (mongocrypt_log_level_t level,
                            const char *message,
                            void *ctx);

void
_mongocrypt_log (mongocrypt_log_level_t level, const char *message, ...)
   BSON_GNUC_PRINTF (2, 3);

void
_mongocrypt_log_init (void);

void
_mongocrypt_log_set_fn (mongocrypt_log_fn_t fn, void *ctx);


#ifdef MONGOCRYPT_TRACE

#define CRYPT_TRACEF(fmt, ...)                  \
   _mongocrypt_log (MONGOCRYPT_LOG_LEVEL_TRACE, \
                    "(%s:%d) " fmt,             \
                    BSON_FUNC,                  \
                    __LINE__,                   \
                    __VA_ARGS__)

#define CRYPT_TRACE(msg) CRYPT_TRACEF ("%s", msg)

#define CRYPT_ENTRY  \
   _mongocrypt_log ( \
      MONGOCRYPT_LOG_LEVEL_TRACE, "entry (%s:%d)", BSON_FUNC, __LINE__)

#define CRYPT_EXIT                                                         \
   do {                                                                    \
      _mongocrypt_log (                                                    \
         MONGOCRYPT_LOG_LEVEL_TRACE, "exit (%s:%d)", BSON_FUNC, __LINE__); \
      return;                                                              \
   } while (0)

#define CRYPT_RETURN                                                         \
   (x) do                                                                    \
   {                                                                         \
      _mongocrypt_log (                                                      \
         MONGOCRYPT_LOG_LEVEL_TRACE, "return (%s:%d)", BSON_FUNC, __LINE__); \
      return (x);                                                            \
   }                                                                         \
   while (0)

#define CRYPT_GOTO                                                         \
   (x) do                                                                  \
   {                                                                       \
      _mongocrypt_log (                                                    \
         MONGOCRYPT_LOG_LEVEL_TRACE, "goto (%s:%d)", BSON_FUNC, __LINE__); \
      goto x;                                                              \
   }                                                                       \
   while (0)

#else

#define CRYPT_TRACEF(fmt, ...)
#define CRYPT_TRACE(msg)
#define CRYPT_ENTRY
#define CRYPT_EXIT
#define CRYPT_RETURN(x) return (x);
#define CRYPT_GOTO(x) goto x;

#endif /* MONGOCRYPT_TRACE */

#endif /* MONGOCRYPT_LOG_PRIVATE_H */