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

#include "mongocrypt.h"
#include "mongocrypt-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-opts-private.h"
#include "test-mongocrypt.h"

typedef struct {
   char *message;
   mongocrypt_log_level_t expected_level;
} log_test_ctx_t;

static void
_test_log_fn (mongocrypt_log_level_t level,
              const char *message,
              uint32_t message_len,
              void *ctx_void)
{
   log_test_ctx_t *ctx = (log_test_ctx_t *) ctx_void;
   BSON_ASSERT (level == ctx->expected_level);
   BSON_ASSERT (0 == strcmp (message, ctx->message));
}

/* Test a custom log handler on all log levels except for trace. */
static void
_test_log (_mongocrypt_tester_t *tester)
{
   log_test_ctx_t log_ctx = {0};
   mongocrypt_log_level_t levels[] = {MONGOCRYPT_LOG_LEVEL_FATAL,
                                      MONGOCRYPT_LOG_LEVEL_ERROR,
                                      MONGOCRYPT_LOG_LEVEL_WARNING,
                                      MONGOCRYPT_LOG_LEVEL_INFO};
   int i;
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   /* Test logging with a custom handler messages. */
   _mongocrypt_log_set_fn (&crypt->log, _test_log_fn, &log_ctx);
   log_ctx.message = "test";
   for (i = 0; i < sizeof (levels) / sizeof (*levels); i++) {
      log_ctx.expected_level = levels[i];
      _mongocrypt_log (&crypt->log, levels[i], "test");
   }

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

static void
_test_info_log (_mongocrypt_tester_t *tester)
{
   log_test_ctx_t log_ctx = {0};
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;
   uint32_t expected_int = -1;
   const char *expected_string = "_test_info_log_test_str";

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new ();

   _mongocrypt_log_set_fn (&crypt->log, _test_log_fn, &log_ctx);
   log_ctx.expected_level = MONGOCRYPT_LOG_LEVEL_INFO;

   log_ctx.message = "mongocrypt_setopt_kms_provider_aws "
                     "(aws_access_key_id=\"_test\", "
                     "aws_access_key_id_len=5, "
                     "aws_secret_access_key=\"_test_info_log_test_str\", "
                     "aws_secret_access_key_len=-1)";

   /* 'expected_string' is truncated to test for non-null terminated strings */
   mongocrypt_setopt_kms_provider_aws (
      crypt, expected_string, 5, expected_string, expected_int);

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_log (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_log);
   INSTALL_TEST (_test_info_log);
}
