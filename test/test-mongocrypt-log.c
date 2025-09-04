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

#include "mongocrypt-log-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt.h"

typedef struct {
    char *message;
    mongocrypt_log_level_t expected_level;
} log_test_ctx_t;

static void _test_log_fn(mongocrypt_log_level_t level, const char *message, uint32_t message_len, void *ctx_void) {
    log_test_ctx_t *ctx = (log_test_ctx_t *)ctx_void;
    BSON_ASSERT(level == ctx->expected_level);
    BSON_ASSERT(0 == strcmp(message, ctx->message));
}

/* Test a custom log handler on all log levels except for trace. */
static void _test_log(_mongocrypt_tester_t *tester) {
    log_test_ctx_t log_ctx = {0};
    mongocrypt_log_level_t levels[] = {MONGOCRYPT_LOG_LEVEL_FATAL,
                                       MONGOCRYPT_LOG_LEVEL_ERROR,
                                       MONGOCRYPT_LOG_LEVEL_WARNING,
                                       MONGOCRYPT_LOG_LEVEL_INFO};
    size_t i;
    mongocrypt_t *crypt;
    mongocrypt_status_t *status;

    status = mongocrypt_status_new();
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    /* Test logging with a custom handler messages. */
    _mongocrypt_log_set_fn(&crypt->log, _test_log_fn, &log_ctx);
    log_ctx.message = "test";
    for (i = 0; i < sizeof(levels) / sizeof(*levels); i++) {
        log_ctx.expected_level = levels[i];
        _mongocrypt_log(&crypt->log, levels[i], "test");
    }

    mongocrypt_status_destroy(status);
    mongocrypt_destroy(crypt);
}

#if defined(__GLIBC__) || defined(__APPLE__)
static void _test_no_log(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_status_t *status;
    char captured_logs[BUFSIZ];
    const int buffer_size = sizeof(captured_logs);
    int saved_stdout = dup(1);

    /* Redirect stdout to /dev/null and capture output in a buffer
     * so we can check if anything was logged to stdout.
     */
    memset(captured_logs, 0, buffer_size);
    stdout = freopen("/dev/null", "a", stdout);
    setbuf(stdout, captured_logs);

    status = mongocrypt_status_new();
    crypt = mongocrypt_new();
    mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1);
    ASSERT_OK(_mongocrypt_init_for_test(crypt), crypt);
    _mongocrypt_log(&crypt->log, MONGOCRYPT_LOG_LEVEL_FATAL, "Please don't log");
    mongocrypt_status_destroy(status);
    mongocrypt_destroy(crypt);
    BSON_ASSERT(strlen(captured_logs) == 0);
    stdout = fdopen(saved_stdout, "w");
}
#endif

void _mongocrypt_tester_install_log(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_log);
#if defined(__GLIBC__) || defined(__APPLE__)
    INSTALL_TEST(_test_no_log);
#endif
}
