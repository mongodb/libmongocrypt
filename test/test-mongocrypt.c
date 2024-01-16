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

#include <stdio.h>
#include <stdlib.h>

#include <bson/bson.h>

#include "mongocrypt-config.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-marking-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt.h"
#include <kms_message/kms_b64.h> // kms_message_b64_pton

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
#include <sys/sysctl.h>
#endif

/* Return a repeated character with no null terminator. */
char *_mongocrypt_repeat_char(char c, uint32_t times) {
    char *result;
    uint32_t i;

    result = bson_malloc(times);
    BSON_ASSERT(result);

    for (i = 0; i < times; i++) {
        result[i] = c;
    }

    return result;
}

void _load_json_as_bson(const char *path, bson_t *out) {
    bson_error_t error;
    bson_json_reader_t *reader;
    bool ret;

    reader = bson_json_reader_new_from_file(path, &error);
    if (!reader) {
        fprintf(stderr, "error reading: %s\n", path);
    }
    ASSERT_OR_PRINT_BSON(reader, error);
    bson_init(out);
    ret = bson_json_reader_read(reader, out, &error);
    ASSERT_OR_PRINT_BSON(ret, error);

    bson_json_reader_destroy(reader);
}

#define TEST_DATA_COUNT_INC(var)                                                                                       \
    (var)++;                                                                                                           \
    if ((var) >= TEST_DATA_COUNT) {                                                                                    \
        TEST_ERROR("TEST_DATA_COUNT exceeded for %s. Increment TEST_DATA_COUNT.", #var);                               \
    }

static void _load_json(_mongocrypt_tester_t *tester, const char *path) {
    bson_t as_bson;
    _mongocrypt_buffer_t *buf;

    _load_json_as_bson(path, &as_bson);

    buf = &tester->file_bufs[tester->file_count];
    _mongocrypt_buffer_steal_from_bson(buf, &as_bson);
    tester->file_paths[tester->file_count] = bson_strdup(path);
    TEST_DATA_COUNT_INC(tester->file_count);
}

static void _load_http(_mongocrypt_tester_t *tester, const char *path) {
    int fd;
    char *contents;
    int n_read;
    int filesize;
    char storage[512];
    int i;
    _mongocrypt_buffer_t *buf;

    filesize = 0;
    contents = NULL;
    fd = open(path, O_RDONLY);
    while ((n_read = read(fd, storage, sizeof(storage))) > 0) {
        filesize += n_read;
        /* Append storage. Performance does not matter. */
        contents = bson_realloc(contents, filesize);
        memcpy(contents + (filesize - n_read), storage, n_read);
    }

    if (n_read < 0) {
        fprintf(stderr, "failed to read %s\n", path);
        abort();
    }

    close(fd);

    buf = &tester->file_bufs[tester->file_count];
    /* copy and fix newlines */
    _mongocrypt_buffer_init(buf);
    /* allocate twice the size since \n may become \r\n */
    buf->data = bson_malloc0(filesize * 2);
    BSON_ASSERT(buf->data);

    buf->len = 0;
    buf->owned = true;
    for (i = 0; i < filesize; i++) {
        if (contents[i] == '\n' && contents[i - 1] != '\r') {
            buf->data[buf->len++] = '\r';
        }
        buf->data[buf->len++] = contents[i];
    }

    bson_free(contents);
    tester->file_paths[tester->file_count] = bson_strdup(path);
    TEST_DATA_COUNT_INC(tester->file_count);
}

void _mongocrypt_tester_install(_mongocrypt_tester_t *tester,
                                char *name,
                                _mongocrypt_test_fn fn,
                                _mongocrypt_tester_crypto_spec_t crypto_spec) {
    bool crypto_enabled;

#ifdef MONGOCRYPT_ENABLE_CRYPTO
    crypto_enabled = true;
#else
    crypto_enabled = false;
#endif

    if (crypto_spec == CRYPTO_REQUIRED && !crypto_enabled) {
        printf("Skipping test: %s – requires crypto to be enabled\n", name);
        return;
    }

    if (crypto_spec == CRYPTO_PROHIBITED && crypto_enabled) {
        printf("Skipping test: %s – requires crypto to be disabled\n", name);
        return;
    }

    tester->test_fns[tester->test_count] = fn;
    tester->test_names[tester->test_count] = bson_strdup(name);
    TEST_DATA_COUNT_INC(tester->test_count);
}

mongocrypt_binary_t *_mongocrypt_tester_file(_mongocrypt_tester_t *tester, const char *path) {
    int i;
    mongocrypt_binary_t *to_return;

    to_return = mongocrypt_binary_new();
    tester->test_bin[tester->bin_count] = to_return;
    TEST_DATA_COUNT_INC(tester->bin_count);

    for (i = 0; i < tester->file_count; i++) {
        if (0 == strcmp(tester->file_paths[i], path)) {
            _mongocrypt_buffer_to_binary(&tester->file_bufs[i], to_return);
            return to_return;
        }
    }

    /* File not found, load it. */
    if (strstr(path, ".json")) {
        _load_json(tester, path);
    } else if (strstr(path, ".txt")) {
        _load_http(tester, path);
    }

    _mongocrypt_buffer_to_binary(&tester->file_bufs[tester->file_count - 1], to_return);
    return to_return;
}

bson_t *_mongocrypt_tester_bson_from_json(_mongocrypt_tester_t *tester, const char *json, ...) {
    va_list ap;
    char *full_json;
    bson_t *bson;
    bson_error_t error;
    char *c;

    va_start(ap, json);
    full_json = bson_strdupv_printf(json, ap);
    /* Replace ' with " */
    for (c = full_json; *c; c++) {
        if (*c == '\'') {
            *c = '"';
        }
    }

    va_end(ap);
    bson = &tester->test_bson[tester->bson_count];
    TEST_DATA_COUNT_INC(tester->bson_count);
    if (!bson_init_from_json(bson, full_json, strlen(full_json), &error)) {
        fprintf(stderr, "%s", error.message);
        abort();
    }
    bson_free(full_json);
    return bson;
}

mongocrypt_binary_t *_mongocrypt_tester_bin_from_json(_mongocrypt_tester_t *tester, const char *json, ...) {
    va_list ap;
    char *full_json;
    bson_t *bson;
    mongocrypt_binary_t *bin;
    bson_error_t error;
    char *c;

    va_start(ap, json);
    full_json = bson_strdupv_printf(json, ap);
    /* Replace ' with " */
    for (c = full_json; *c; c++) {
        if (*c == '\'') {
            *c = '"';
        }
    }

    va_end(ap);
    bson = &tester->test_bson[tester->bson_count];
    TEST_DATA_COUNT_INC(tester->bson_count);
    if (!bson_init_from_json(bson, full_json, strlen(full_json), &error)) {
        fprintf(stderr, "failed to parse JSON %s: %s", error.message, json);
        abort();
    }
    bin = mongocrypt_binary_new();
    tester->test_bin[tester->bin_count] = bin;
    TEST_DATA_COUNT_INC(tester->bin_count);
    bin->data = (uint8_t *)bson_get_data(bson);
    bin->len = bson->len;
    bson_free(full_json);
    return bin;
}

mongocrypt_binary_t *_mongocrypt_tester_bin(_mongocrypt_tester_t *tester, int size) {
    mongocrypt_binary_t *bin;
    uint8_t *blob;
    int i;

    if (size == 0) {
        return NULL;
    }
    blob = bson_malloc(size);
    BSON_ASSERT(blob);

    for (i = 0; i < size; i++) {
        blob[i] = (i % 3) + 1; /* 1, 2, 3, 1, 2, 3, ... */
    }

    bin = mongocrypt_binary_new_from_data(blob, size);

    tester->test_blob[tester->blob_count] = blob;
    TEST_DATA_COUNT_INC(tester->blob_count);
    tester->test_bin[tester->bin_count] = bin;
    TEST_DATA_COUNT_INC(tester->bin_count);
    return bin;
}

void _mongocrypt_tester_satisfy_kms(_mongocrypt_tester_t *tester, mongocrypt_kms_ctx_t *kms) {
    const char *endpoint;

    BSON_ASSERT(mongocrypt_kms_ctx_endpoint(kms, &endpoint));
    BSON_ASSERT(endpoint == strstr(endpoint, "kms.") && strstr(endpoint, ".amazonaws.com"));
    mongocrypt_kms_ctx_feed(kms, TEST_FILE("./test/data/kms-aws/decrypt-response.txt"));
    BSON_ASSERT(0 == mongocrypt_kms_ctx_bytes_needed(kms));
}

/* Run the state machine on example data until hitting stop_state or a
 * terminal state. */
void _mongocrypt_tester_run_ctx_to(_mongocrypt_tester_t *tester,
                                   mongocrypt_ctx_t *ctx,
                                   mongocrypt_ctx_state_t stop_state) {
    mongocrypt_ctx_state_t state;
    mongocrypt_kms_ctx_t *kms;
    mongocrypt_status_t *status;
    mongocrypt_binary_t *bin;
    bool res;

    status = mongocrypt_status_new();
    state = mongocrypt_ctx_state(ctx);
    while (state != stop_state) {
        switch (state) {
        case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
            if (tester->paths.collection_info) {
                bin = TEST_FILE(tester->paths.collection_info);
            } else {
                bin = TEST_FILE("./test/example/collection-info.json");
            }
            BSON_ASSERT(ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
            BSON_ASSERT(mongocrypt_ctx_mongo_feed(ctx, bin));
            BSON_ASSERT(mongocrypt_ctx_mongo_done(ctx));
            break;
        case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
            if (tester->paths.mongocryptd_reply) {
                bin = TEST_FILE(tester->paths.mongocryptd_reply);
            } else {
                bin = TEST_FILE("./test/example/mongocryptd-reply.json");
            }
            BSON_ASSERT(ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
            res = mongocrypt_ctx_mongo_feed(ctx, bin);
            mongocrypt_ctx_status(ctx, status);
            ASSERT_OR_PRINT(res, status);
            BSON_ASSERT(mongocrypt_ctx_mongo_done(ctx));
            break;
        case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
            if (tester->paths.key_file) {
                bin = TEST_FILE(tester->paths.key_file);
            } else {
                bin = TEST_FILE("./test/example/key-document.json");
            }
            res = mongocrypt_ctx_mongo_feed(ctx, bin);
            mongocrypt_ctx_status(ctx, status);
            ASSERT_OR_PRINT(res, status);
            BSON_ASSERT(mongocrypt_ctx_mongo_done(ctx));
            break;
        case MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS:
            bin = TEST_BSON("{}");
            mongocrypt_ctx_provide_kms_providers(ctx, bin);
            break;
        case MONGOCRYPT_CTX_NEED_KMS:
            kms = mongocrypt_ctx_next_kms_ctx(ctx);
            while (kms) {
                _mongocrypt_tester_satisfy_kms(tester, kms);
                kms = mongocrypt_ctx_next_kms_ctx(ctx);
            }
            res = mongocrypt_ctx_kms_done(ctx);
            mongocrypt_ctx_status(ctx, status);
            ASSERT_OR_PRINT(res, status);
            break;
        case MONGOCRYPT_CTX_READY:
            bin = mongocrypt_binary_new();
            res = mongocrypt_ctx_finalize(ctx, bin);
            mongocrypt_ctx_status(ctx, status);
            ASSERT_OR_PRINT(res, status);
            mongocrypt_binary_destroy(bin);
            break;
        case MONGOCRYPT_CTX_ERROR:
            mongocrypt_ctx_status(ctx, status);
            fprintf(stderr, "Got error: %s\n", mongocrypt_status_message(status, NULL));
            ASSERT_STATE_EQUAL(state, stop_state);
            mongocrypt_status_destroy(status);
            return;
        case MONGOCRYPT_CTX_DONE:
            ASSERT_STATE_EQUAL(state, stop_state);
            mongocrypt_status_destroy(status);
            return;
        default: BSON_ASSERT(false && "Invalid state");
        }
        state = mongocrypt_ctx_state(ctx);
    }
    ASSERT_STATE_EQUAL(state, stop_state);
    mongocrypt_status_destroy(status);
}

/* Get the plaintext associated with the encrypted doc for assertions. */
const char *_mongocrypt_tester_plaintext(_mongocrypt_tester_t *tester) {
    bson_t as_bson;
    bson_iter_t iter;
    _mongocrypt_marking_t marking;
    _mongocrypt_buffer_t buf;
    mongocrypt_status_t *status;

    BSON_ASSERT(_mongocrypt_binary_to_bson(TEST_FILE("./test/example/mongocryptd-reply.json"), &as_bson));
    /* Underlying binary data lives on in tester */
    BSON_ASSERT(bson_iter_init(&iter, &as_bson));
    BSON_ASSERT(bson_iter_find_descendant(&iter, "result.filter.ssn", &iter));
    BSON_ASSERT(_mongocrypt_buffer_from_binary_iter(&buf, &iter));
    status = mongocrypt_status_new();
    ASSERT_OR_PRINT(_mongocrypt_marking_parse_unowned(&buf, &marking, status), status);
    mongocrypt_status_destroy(status);
    BSON_ASSERT(BSON_ITER_HOLDS_UTF8(&marking.v_iter));
    return bson_iter_utf8(&marking.v_iter, NULL);
}

mongocrypt_binary_t *_mongocrypt_tester_encrypted_doc(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *bin;

    bin = mongocrypt_binary_new();
    if (!_mongocrypt_buffer_empty(&tester->encrypted_doc)) {
        _mongocrypt_buffer_to_binary(&tester->encrypted_doc, bin);
        return bin;
    }

    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);

    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_READY);
    mongocrypt_ctx_finalize(ctx, bin);
    _mongocrypt_buffer_copy_from_binary(&tester->encrypted_doc, bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
    _mongocrypt_buffer_to_binary(&tester->encrypted_doc, bin);
    return bin;
}

void _mongocrypt_tester_fill_buffer(_mongocrypt_buffer_t *buf, int n) {
    uint8_t i;

    memset(buf, 0, sizeof(*buf));
    buf->data = bson_malloc(n);
    BSON_ASSERT(buf->data);

    for (i = 0; i < n; i++) {
        buf->data[i] = i;
    }
    buf->len = n;
    buf->owned = true;
}

#define PRIVATE_KEY_FOR_TESTING                                                                                        \
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4JOyv5z05cL18ztpknRC7C"                                        \
    "FY2gYol4DAKerdVUoDJxCTmFMf39dVUEqD0WDiw/qcRtSO1/"                                                                 \
    "FRut08PlSPmvbyKetsLoxlpS8lukSzEFpFK7+L+R4miFOl6HvECyg7lbC1H/"                                                     \
    "WGAhIz9yZRlXhRo9qmO/"                                                                                             \
    "fB6PV9IeYtU+"                                                                                                     \
    "1xYuXicjCDPp36uuxBAnCz7JfvxJ3mdVc0vpSkbSb141nWuKNYR1mgyvvL6KzxO6mYsCo4hRA"                                        \
    "dhuizD9C4jDHk0V2gDCFBk0h8SLEdzStX8L0jG90/Og4y7J1b/cPo/"                                                           \
    "kbYokkYisxe8cPlsvGBf+rZex7XPxc1yWaP080qeABJb+S88O//"                                                              \
    "LAgMBAAECggEBAKVxP1m3FzHBUe2NZ3fYCc0Qa2zjK7xl1KPFp2u4CU+"                                                         \
    "9sy0oZJUqQHUdm5CMprqWwIHPTftWboFenmCwrSXFOFzujljBO7Z3yc1WD3NJl1ZNepLcsRJ3"                                        \
    "WWFH5V+NLJ8Bdxlj1DMEZCwr7PC5+vpnCuYWzvT0qOPTl9RNVaW9VVjHouJ9Fg+"                                                  \
    "s2DrShXDegFabl1iZEDdI4xScHoYBob06A5lw0WOCTayzw0Naf37lM8Y4psRAmI46XLiF/"                                           \
    "Vbuorna4hcChxDePlNLEfMipICcuxTcei1RBSlBa2t1tcnvoTy6cuYDqqImRYjp1KnMKlKQBn"                                        \
    "Q1NjS2TsRGm+F0FbreVCECgYEA4IDJlm8q/hVyNcPe4OzIcL1rsdYN3bNm2Y2O/"                                                  \
    "YtRPIkQ446ItyxD06d9VuXsQpFp9jNACAPfCMSyHpPApqlxdc8z/"                                                             \
    "xATlgHkcGezEOd1r4E7NdTpGg8y6Rj9b8kVlED6v4grbRhKcU6moyKUQT3+"                                                      \
    "1B6ENZTOKyxuyDEgTwZHtFECgYEA0fqdv9h9s77d6eWmIioP7FSymq93pC4umxf6TVicpjpME"                                        \
    "rdD2ZfJGulN37dq8FOsOFnSmFYJdICj/PbJm6p1i8O21lsFCltEqVoVabJ7/"                                                     \
    "0alPfdG2U76OeBqI8ZubL4BMnWXAB/"                                                                                   \
    "VVEYbyWCNpQSDTjHQYs54qa2I0dJB7OgJt1sCgYEArctFQ02/"                                                                \
    "7H5Rscl1yo3DBXO94SeiCFSPdC8f2Kt3MfOxvVdkAtkjkMACSbkoUsgbTVqTYSEOEc2jTgR3i"                                        \
    "Q13JgpHaFbbsq64V0QP3TAxbLIQUjYGVgQaF1UfLOBv8hrzgj45z/ST/"                                                         \
    "G80lOl595+0nCUbmBcgG1AEWrmdF0/"                                                                                   \
    "3RmECgYAKvIzKXXB3+19vcT2ga5Qq2l3TiPtOGsppRb2XrNs9qKdxIYvHmXo/"                                                    \
    "9QP1V3SRW0XoD7ez8FpFabp42cmPOxUNk3FK3paQZABLxH5pzCWI9PzIAVfPDrm+"                                                 \
    "sdnbgG7vAnwfL2IMMJSA3aDYGCbF9EgefG+"                                                                              \
    "STcpfqq7fQ6f5TBgLFwKBgCd7gn1xYL696SaKVSm7VngpXlczHVEpz3kStWR5gfzriPBxXgMV"                                        \
    "cWmcbajRser7ARpCEfbxM1UJyv6oAYZWVSNErNzNVb4POqLYcCNySuC6xKhs9FrEQnyKjyk8w"                                        \
    "I4VnrEMGrQ8e+qYSwYk9Gh6dKGoRMAPYVXQAO0fIsHF/T0a"

mongocrypt_t *_mongocrypt_tester_mongocrypt(tester_mongocrypt_flags flags) {
    mongocrypt_t *crypt;
    char localkey_data[MONGOCRYPT_KEY_LEN] = {0};
    mongocrypt_binary_t *localkey;
    bson_t *kms_providers;
    mongocrypt_binary_t *bin;

    crypt = mongocrypt_new();
    mongocrypt_setopt_log_handler(crypt, _mongocrypt_stdout_log_fn, NULL);
    mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1);
    localkey = mongocrypt_binary_new_from_data((uint8_t *)localkey_data, sizeof localkey_data);
    mongocrypt_setopt_kms_provider_local(crypt, localkey);
    mongocrypt_binary_destroy(localkey);
    kms_providers = BCON_NEW("azure",
                             "{",
                             "tenantId",
                             "",
                             "clientId",
                             "",
                             "clientSecret",
                             "",
                             "}",
                             "gcp",
                             "{",
                             "email",
                             "test@example.com",
                             "privateKey",
                             PRIVATE_KEY_FOR_TESTING,
                             "}",
                             "kmip",
                             "{",
                             "endpoint",
                             "localhost",
                             "}");
    bin = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(kms_providers), kms_providers->len);
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, bin), crypt);
    bson_destroy(kms_providers);
    mongocrypt_binary_destroy(bin);
    if (flags & TESTER_MONGOCRYPT_WITH_CRYPT_V1) {
        ASSERT(mongocrypt_setopt_fle2v2(crypt, false));
    }
    if (flags & TESTER_MONGOCRYPT_WITH_CRYPT_SHARED_LIB) {
        mongocrypt_setopt_append_crypt_shared_lib_search_path(crypt, "$ORIGIN");
    }
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    if (flags & TESTER_MONGOCRYPT_WITH_CRYPT_SHARED_LIB) {
        if (mongocrypt_crypt_shared_lib_version(crypt) == 0) {
            BSON_ASSERT(false
                        && "tester mongocrypt requested WITH_CRYPT_SHARED_LIB, but "
                           "no crypt_shared library was loaded by mongocrypt_init");
        }
    }
    return crypt;
}

static void _test_mongocrypt_bad_init(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_binary_t *local_key;
    char tmp;

    /* Omitting a KMS provider must fail. */
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_init(crypt), crypt, "no kms provider set");
    mongocrypt_destroy(crypt);

    /* Bad KMS provider options must fail. */
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, NULL, -1),
                 crypt,
                 "invalid aws secret access key");
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_kms_provider_aws(crypt, NULL, -1, "example", -1),
                 crypt,
                 "invalid aws access key id");
    mongocrypt_destroy(crypt);

    /* Malformed UTF8 */
    /* An orphaned UTF-8 continuation byte (10xxxxxx) is malformed UTF-8. */
    tmp = (char)0x80;
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, &tmp, 1),
                 crypt,
                 "invalid aws secret access key");
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_kms_provider_local(crypt, NULL), crypt, "passed null key");
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    local_key = mongocrypt_binary_new();
    ASSERT_FAILS(mongocrypt_setopt_kms_provider_local(crypt, local_key), crypt, "local key must be 96 bytes");
    mongocrypt_binary_destroy(local_key);
    mongocrypt_destroy(crypt);

    /* Reinitialization must fail. */
    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    ASSERT_FAILS(mongocrypt_init(crypt), crypt, "already initialized");
    mongocrypt_destroy(crypt);
    /* Setting options after initialization must fail. */
    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    ASSERT_FAILS(mongocrypt_setopt_kms_provider_aws(crypt, "example", -1, "example", -1),
                 crypt,
                 "options cannot be set after initialization");
    mongocrypt_destroy(crypt);
}

static void _test_setopt_schema(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;

    /* Test double setting. */
    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_FILE("./test/data/schema-map.json")), crypt);
    ASSERT_FAILS(mongocrypt_setopt_schema_map(crypt, TEST_FILE("./test/data/schema-map.json")),
                 crypt,
                 "already set schema");

    /* Test NULL/empty input */
    mongocrypt_destroy(crypt);
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_schema_map(crypt, NULL), crypt, "passed null schema");

    mongocrypt_destroy(crypt);
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_schema_map(crypt, TEST_BIN(0)), crypt, "passed null schema");

    /* Test malformed BSON */
    mongocrypt_destroy(crypt);
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_schema_map(crypt, TEST_BIN(10)), crypt, "invalid bson");
    mongocrypt_destroy(crypt);
}

static void _test_setopt_encrypted_field_config_map(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;

    /* Test success. */
    crypt = mongocrypt_new();
    ASSERT_OK(
        mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
        crypt);
    ASSERT_OK(
        mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_FILE("./test/data/encrypted-field-config-map.json")),
        crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    mongocrypt_destroy(crypt);

    /* Test double setting. */
    crypt = mongocrypt_new();
    ASSERT_OK(
        mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_FILE("./test/data/encrypted-field-config-map.json")),
        crypt);
    ASSERT_FAILS(
        mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_FILE("./test/data/encrypted-field-config-map.json")),
        crypt,
        "already set encrypted_field_config_map");
    mongocrypt_destroy(crypt);

    /* Test NULL/empty input */
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_encrypted_field_config_map(crypt, NULL),
                 crypt,
                 "passed null encrypted_field_config_map");
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BIN(0)),
                 crypt,
                 "passed null encrypted_field_config_map");
    mongocrypt_destroy(crypt);

    /* Test malformed BSON */
    crypt = mongocrypt_new();
    ASSERT_FAILS(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BIN(10)), crypt, "invalid bson");
    mongocrypt_destroy(crypt);

    /* Test that it is OK to set both the encrypted field config map and schema
     * map if there are no intersecting collections. */
    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_BSON("{'db.coll1': {}, 'db.coll2': {}}")), crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BSON("{'db.coll3': {}, 'db.coll3': {}}")),
              crypt);
    ASSERT_OK(
        mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
        crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);
    mongocrypt_destroy(crypt);

    /* Test that it is an error to set both the encrypted field config map and
     * schema map referencing the same collection. */
    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_schema_map(crypt, TEST_BSON("{'db.coll1': {}, 'db.coll2': {}}")), crypt);
    ASSERT_OK(mongocrypt_setopt_encrypted_field_config_map(crypt, TEST_BSON("{'db.coll1': {}, 'db.coll3': {}}")),
              crypt);
    ASSERT_OK(
        mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{'aws': {'accessKeyId': 'foo', 'secretAccessKey': 'bar'}}")),
        crypt);
    ASSERT_FAILS(mongocrypt_init(crypt),
                 crypt,
                 "db.coll1 is present in both schema_map and encrypted_field_config_map");
    mongocrypt_destroy(crypt);
}

static void _test_setopt_invalid_kms_providers(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_status_t *status;

    crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "", 0, "", 0), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_masterkey_aws(ctx, "region", -1, "cmk", 3), ctx);
    mongocrypt_ctx_datakey_init(ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_ERROR);

    status = mongocrypt_status_new();
    BSON_ASSERT(!mongocrypt_ctx_status(ctx, status));
    ASSERT_STATUS_CONTAINS(status, "failed to create KMS message");

    mongocrypt_status_destroy(status);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);

    crypt = mongocrypt_new();
    mongocrypt_setopt_use_need_kms_credentials_state(crypt);
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON("{}")), crypt);
    ASSERT_FAILS(mongocrypt_init(crypt), crypt, "no kms provider set");
    mongocrypt_destroy(crypt);
}

typedef struct {
    char *value;
    /* errmsg is the expected error message from mongocrypt_setopt_kms_providers
     */
    char *errmsg;
    /* errmsg_init is the expected error message from mongocrypt_init */
    char *errmsg_init;
    bool use_need_kms_credentials_state;
} setopt_kms_providers_testcase_t;

#define EXAMPLE_LOCAL_MATERIAL                                                                                         \
    "TlPm8M/Uxs0eK13ReFeOUyxVC2rarCf5+LbKuY/dnFxS/"                                                                    \
    "LoYc1CZqnfSXujqqWrrt3fOTQ2TdtNhO4bBfamOyJPx4uJSstehc7It4pLp3LHes70z64AYqJ"                                        \
    "Uemk4G+2He"

static void _test_setopt_kms_providers(_mongocrypt_tester_t *tester) {
    setopt_kms_providers_testcase_t *test;
    size_t i;
    setopt_kms_providers_testcase_t tests[] = {
        {"{'azure': {'tenantId': '', 'clientId': '', 'clientSecret': '', "
         "'identityPlatformEndpoint': 'example.com' }}",
         NULL},
        {"{'azure': {'tenantId': '', 'clientId': '', 'clientSecret': '' }}", NULL},
        {"{'azure': {'tenantId': '', 'clientId': '', 'clientSecret': '', "
         "'identityPlatformEndpoint': 'example' }}",
         "Invalid endpoint"},
        {"{'azure': {'tenantId': '', 'clientSecret': '' }}", "clientId"},
        {"{'aws': {'accessKeyId': 'abc', 'secretAccessKey': 'def'}}", NULL},
        {"{'local': {'key': {'$binary': {'base64': '" EXAMPLE_LOCAL_MATERIAL "', 'subType': '00'}} }}", NULL},
        {"{'local': {'key': '" EXAMPLE_LOCAL_MATERIAL "' }}", NULL},
        {"{'local': {'key': 'invalid base64' }}", "unable to parse base64"},
        /* either base64 string or binary is acceptable for privateKey */
        {"{'gcp': {'endpoint': 'oauth2.googleapis.com', 'email': 'test', "
         "'privateKey': 'AAAA' }}"},
        {"{'gcp': {'endpoint': 'oauth2.googleapis.com', 'email': 'test', "
         "'privateKey': {'$binary': {'base64': 'AAAA', 'subType': '00'}} }}"},
        /* endpoint is not required. */
        {"{'gcp': {'email': 'test', 'privateKey': 'AAAA' }}"},
        {"{'gcp': {'privateKey': 'AAAA'}}", "Failed to parse KMS provider `gcp`: expected UTF-8 email"},
        {"{'gcp': {'email': 'test', 'privateKey': 'invalid base64' }}", "unable to parse base64"},
        {"{'gcp': {'endpoint': 'example', 'email': 'test', 'privateKey': "
         "'AAAA'}}",
         "Invalid endpoint"},
        {"{'azure': {'tenantId': '', 'clientId': '', 'clientSecret': '', "
         "'identityPlatformEndpoint': 'example.com', 'extra': 'invalid' }}",
         "Unexpected field: 'extra'"},
        {"{'aws': {'accessKeyId': 'abc', 'secretAccessKey': 'def', 'extra': "
         "'invalid'}}",
         "Unexpected field: 'extra'"},
        {"{'gcp': {'endpoint': 'oauth2.googleapis.com', 'email': 'test', "
         "'privateKey': 'AAAA', 'extra': 'invalid' }}",
         "Unexpected field: 'extra'"},
        {"{'local': {'key': '" EXAMPLE_LOCAL_MATERIAL "', 'extra': 'invalid' }}", "Unexpected field: 'extra'"},
        {"{'local': {'key': 'AAAA'}}", "local key must be 96 bytes"},
        /* KMIP test cases. */
        {"{'kmip': {'endpoint': '127.0.0.1:5696' }}", NULL},
        /* localhost is a valid endpoint for KMIP.
         * Unlike Azure, GCP, and AWS, applications run their own KMIP servers. */
        {"{'kmip': {'endpoint': 'localhost' }}", NULL},
        {"{'kmip': {'endpoint': '127.0.0.1:5696', 'extra': 'invalid' }}", "Unexpected field: 'extra'"},
        /* Empty documents are OK if on-demand KMS credentials are opted-in with
         * a call to mongocrypt_setopt_use_need_kms_credentials_state. */
        {"{'aws': {}}", NULL, NULL, true},
        {"{'azure': {}}", NULL, NULL, true},
        {"{'local': {}}", NULL, NULL, true},
        {"{'gcp': {}}", NULL, NULL, true},
        {"{'kmip': {}}", NULL, NULL, true},
        /* Empty documents are not OK if on-demand KMS credentials are not
           opted-in. */
        {"{'aws': {}}", NULL, "on-demand credentials not enabled", false},
        {"{'azure': {}}", NULL, "on-demand credentials not enabled", false},
        {"{'local': {}}", NULL, "on-demand credentials not enabled", false},
        {"{'gcp': {}}", NULL, "on-demand credentials not enabled", false},
        {"{'kmip': {}}", NULL, "on-demand credentials not enabled", false},
        {"{'gcp': {'accessToken': 'foobar', 'email': 'foo@bar.com' }}", "Unexpected field: 'email'"},
        {.value = "{ 'azure': { 'accessToken': 'secret' } }"},
    };

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        mongocrypt_t *crypt;

        test = tests + i;
        crypt = mongocrypt_new();
        if (test->use_need_kms_credentials_state) {
            mongocrypt_setopt_use_need_kms_credentials_state(crypt);
        }
        if (!test->errmsg) {
            ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, TEST_BSON(test->value)), crypt);
            if (!test->errmsg_init) {
                ASSERT_OK(mongocrypt_init(crypt), crypt);
            } else {
                ASSERT_FAILS(mongocrypt_init(crypt), crypt, test->errmsg_init);
            }
        } else {
            ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, TEST_BSON(test->value)), crypt, test->errmsg);
        }
        mongocrypt_destroy(crypt);
    }

    // Errors if followed by call to `mongocrypt_setopt_kms_providers` configuring "local".
    // This is a regression test for: MONGOCRYPT-610
    {
        _mongocrypt_buffer_t local_kek_buf;
        // Create buffer for local KEK to pass data.
        {
            _mongocrypt_buffer_init(&local_kek_buf);
            _mongocrypt_buffer_resize(&local_kek_buf, MONGOCRYPT_KEY_LEN);
            int result_len =
                kms_message_b64_pton(EXAMPLE_LOCAL_MATERIAL, local_kek_buf.data, (size_t)local_kek_buf.len);
            ASSERT_CMPINT(result_len, ==, MONGOCRYPT_KEY_LEN);
        }

        mongocrypt_binary_t *more = TEST_BSON("{'local' : {'key' : '%s'}}", EXAMPLE_LOCAL_MATERIAL);
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, _mongocrypt_buffer_as_binary(&local_kek_buf)), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, more), crypt, "already set");
        mongocrypt_destroy(crypt);
        _mongocrypt_buffer_cleanup(&local_kek_buf);
    }

    // Errors if followed by call to `mongocrypt_setopt_kms_providers` configuring "aws".
    // This is a regression test for: MONGOCRYPT-610
    {
        mongocrypt_binary_t *more = TEST_BSON("{'aws' : {'accessKeyId' : 'foo', 'secretAccessKey' : 'bar'}}");
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, more), crypt, "already set");
        mongocrypt_destroy(crypt);
    }
}

bool _aes_ctr_is_supported_by_os = true;

int main(int argc, char **argv) {
    _mongocrypt_tester_t tester = {0};
    int i;

    printf("Pass a list of test names to run only specific tests. E.g.:\n");
    printf("test-mongocrypt _mongocrypt_test_mcgrew\n\n");

    /* Install all tests. */
    _mongocrypt_tester_install_crypto(&tester);
    _mongocrypt_tester_install_log(&tester);
    _mongocrypt_tester_install_data_key(&tester);
    _mongocrypt_tester_install_ctx_encrypt(&tester);
    _mongocrypt_tester_install_ctx_decrypt(&tester);
    _mongocrypt_tester_install_ctx_rewrap_many_datakey(&tester);
    _mongocrypt_tester_install_ciphertext(&tester);
    _mongocrypt_tester_install_key_broker(&tester);
    _mongocrypt_tester_install(&tester, "_test_mongocrypt_bad_init", _test_mongocrypt_bad_init, CRYPTO_REQUIRED);
    _mongocrypt_tester_install_local_kms(&tester);
    _mongocrypt_tester_install_cache(&tester);
    _mongocrypt_tester_install_buffer(&tester);
    _mongocrypt_tester_install_ctx_setopt(&tester);
    _mongocrypt_tester_install_key(&tester);
    _mongocrypt_tester_install_marking(&tester);
    _mongocrypt_tester_install_traverse_util(&tester);
    _mongocrypt_tester_install(&tester, "_test_setopt_schema", _test_setopt_schema, CRYPTO_REQUIRED);
    _mongocrypt_tester_install(&tester,
                               "_test_setopt_encrypted_field_config_map",
                               _test_setopt_encrypted_field_config_map,
                               CRYPTO_REQUIRED);
    _mongocrypt_tester_install(&tester,
                               "_test_setopt_invalid_kms_providers",
                               _test_setopt_invalid_kms_providers,
                               CRYPTO_REQUIRED);
    _mongocrypt_tester_install_crypto_hooks(&tester);
    _mongocrypt_tester_install_key_cache(&tester);
    _mongocrypt_tester_install_kms_responses(&tester);
    _mongocrypt_tester_install_status(&tester);
    _mongocrypt_tester_install_endpoint(&tester);
    _mongocrypt_tester_install(&tester, "_test_setopt_kms_providers", _test_setopt_kms_providers, CRYPTO_OPTIONAL);
    _mongocrypt_tester_install_kek(&tester);
    _mongocrypt_tester_install_cache_oauth(&tester);
    _mongocrypt_tester_install_kms_ctx(&tester);
    _mongocrypt_tester_install_csfle_lib(&tester);
    _mongocrypt_tester_install_dll(&tester);
    _mongocrypt_tester_install_mc_tokens(&tester);
    _mongocrypt_tester_install_fle2_payloads(&tester);
    _mongocrypt_tester_install_fle2_iev_v2_payloads(&tester);
    _mongocrypt_tester_install_efc(&tester);
    _mongocrypt_tester_install_cleanup(&tester);
    _mongocrypt_tester_install_compact(&tester);
    _mongocrypt_tester_install_fle2_payload_uev(&tester);
    _mongocrypt_tester_install_fle2_payload_uev_v2(&tester);
    _mongocrypt_tester_install_fle2_payload_iup(&tester);
    _mongocrypt_tester_install_fle2_payload_iup_v2(&tester);
    _mongocrypt_tester_install_fle2_payload_find_equality_v2(&tester);
    _mongocrypt_tester_install_fle2_payload_find_range_v2(&tester);
    _mongocrypt_tester_install_range_encoding(&tester);
    _mongocrypt_tester_install_range_edge_generation(&tester);
    _mongocrypt_tester_install_range_mincover(&tester);
    _mongocrypt_tester_install_mc_RangeOpts(&tester);
    _mongocrypt_tester_install_mc_FLE2RangeFindDriverSpec(&tester);
    _mongocrypt_tester_install_gcp_auth(&tester);
    _mongocrypt_tester_install_mc_reader(&tester);
    _mongocrypt_tester_install_mc_writer(&tester);
    _mongocrypt_tester_install_opts(&tester);
    _mongocrypt_tester_install_named_kms_providers(&tester);

#ifdef MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO
    char osversion[32];
    size_t osversion_len = sizeof(osversion) - 1;
    int osversion_name[] = {CTL_KERN, KERN_OSRELEASE};

    _aes_ctr_is_supported_by_os = false;

    if (sysctl(osversion_name, 2, osversion, &osversion_len, NULL, 0) == -1) {
        goto get_os_version_failed;
    }

    uint32_t major, minor;
    if (sscanf(osversion, "%u.%u", &major, &minor) != 2) {
        goto get_os_version_failed;
    }

    if (major >= 20) {
        // macOS 11 and newer
        _aes_ctr_is_supported_by_os = true;
    } else {
        major -= 4;
        // macOS 10.1.1 and newer. CTR unsupported in 10.14 and earlier
        _aes_ctr_is_supported_by_os = major > 14;
    }
get_os_version_failed:
#endif

    printf("Running tests...\n");
    for (i = 0; tester.test_names[i]; i++) {
        int j;
        bool found = false;

        if (argc > 1) {
            for (j = 1; j < argc; j++) {
                found = (0 == strcmp(argv[j], tester.test_names[i]));
                if (found) {
                    break;
                }
            }
            if (!found) {
                continue;
            }
        }
        printf("  begin %s\n", tester.test_names[i]);
        tester.test_fns[i](&tester);
        /* Clear state. */
        memset(&tester.paths, 0, sizeof(tester.paths));
        printf("  end %s\n", tester.test_names[i]);
    }
    printf("... done running tests\n");

    if (i == 0) {
        printf("WARNING - no tests run.\n");
    }

    /* Clean up tester. */
    for (i = 0; i < tester.test_count; i++) {
        bson_free(tester.test_names[i]);
    }

    for (i = 0; i < tester.file_count; i++) {
        _mongocrypt_buffer_cleanup(&tester.file_bufs[i]);
        bson_free(tester.file_paths[i]);
    }

    for (i = 0; i < tester.bin_count; i++) {
        mongocrypt_binary_destroy(tester.test_bin[i]);
    }

    for (i = 0; i < tester.bson_count; i++) {
        bson_destroy(&tester.test_bson[i]);
    }

    for (i = 0; i < tester.blob_count; i++) {
        bson_free(tester.test_blob[i]);
    }

    _mongocrypt_buffer_cleanup(&tester.encrypted_doc);
}

void _test_ctx_wrap_and_feed_key(mongocrypt_ctx_t *ctx,
                                 const _mongocrypt_buffer_t *id,
                                 _mongocrypt_buffer_t *key,
                                 mongocrypt_status_t *status) {
    mc_kms_creds_t kc;
    ASSERT(_mongocrypt_opts_kms_providers_lookup(_mongocrypt_ctx_kms_providers(ctx), "local", &kc));
    // Wrap key using local provider.
    _mongocrypt_buffer_t kek = kc.value.local.key;
    _mongocrypt_buffer_t encrypted_key;
    _mongocrypt_buffer_init(&encrypted_key);
    ASSERT_OK_STATUS(_mongocrypt_wrap_key(ctx->crypt->crypto, &kek, key, &encrypted_key, status), status);

    bson_t doc;
    bson_init(&doc);
    ASSERT(bson_append_binary(&doc, "_id", (int)strlen("_id"), BSON_SUBTYPE_UUID, id->data, id->len));
    ASSERT(bson_append_binary(&doc,
                              "keyMaterial",
                              (int)strlen("keyMaterial"),
                              BSON_SUBTYPE_BINARY,
                              encrypted_key.data,
                              encrypted_key.len));
    ASSERT(bson_append_now_utc(&doc, "creationDate", (int)strlen("creationDate")));
    ASSERT(bson_append_now_utc(&doc, "updateDate", (int)strlen("updateDate")));
    ASSERT(bson_append_int32(&doc, "status", (int)strlen("status"), 0));
    bson_t masterKey;
    bson_init(&masterKey);
    ASSERT(bson_append_document_begin(&doc, "masterKey", (int)strlen("masterKey"), &masterKey));
    ASSERT(bson_append_utf8(&masterKey, "provider", (int)strlen("provider"), "local", (int)strlen("local")));
    ASSERT(bson_append_document_end(&doc, &masterKey));
    mongocrypt_binary_t *bin = mongocrypt_binary_new_from_data((uint8_t *)bson_get_data(&doc), doc.len);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, bin), ctx);
    mongocrypt_binary_destroy(bin);
    bson_destroy(&doc);

    _mongocrypt_buffer_cleanup(&encrypted_key);
}
