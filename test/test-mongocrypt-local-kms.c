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

#include "test-mongocrypt.h"

static void _test_local_roundtrip(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt;
    mongocrypt_ctx_t *ctx;
    mongocrypt_binary_t *bin;
    _mongocrypt_buffer_t encrypted_cmd;
    bson_t as_bson;
    bson_iter_t iter;

    bin = mongocrypt_binary_new();
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    /* Encrypt a document. */
    ASSERT_OK(mongocrypt_ctx_encrypt_init(ctx, "test", -1, TEST_FILE("./test/example/cmd.json")), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-local.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    /* Because this is local, we skip NEED_KMS and go right to READY. */
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_READY);
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);

    BSON_ASSERT(_mongocrypt_binary_to_bson(bin, &as_bson));
    /* Keep a copy to decrypt later. */
    _mongocrypt_buffer_copy_from_binary(&encrypted_cmd, bin);
    CRYPT_TRACEF(&crypt->log, "encrypted doc: %s", tmp_json(&as_bson));
    bson_iter_init(&iter, &as_bson);
    bson_iter_find_descendant(&iter, "filter.ssn", &iter);
    BSON_ASSERT(BSON_ITER_HOLDS_BINARY(&iter));
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt); /* destroy because of caching. */

    /* Decrypt it back. */
    crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);
    ctx = mongocrypt_ctx_new(crypt);
    _mongocrypt_buffer_to_binary(&encrypted_cmd, bin);
    ASSERT_OK(mongocrypt_ctx_decrypt_init(ctx, bin), ctx);
    _mongocrypt_tester_run_ctx_to(tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
    ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-local.json")), ctx);
    ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

    /* Because this is local, we skip NEED_KMS and go right to READY. */
    BSON_ASSERT(mongocrypt_ctx_state(ctx) == MONGOCRYPT_CTX_READY);
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);

    BSON_ASSERT(_mongocrypt_binary_to_bson(bin, &as_bson));
    CRYPT_TRACEF(&crypt->log, "decrypted doc: %s", tmp_json(&as_bson));
    bson_iter_init(&iter, &as_bson);
    bson_iter_find_descendant(&iter, "filter.ssn", &iter);
    BSON_ASSERT(BSON_ITER_HOLDS_UTF8(&iter));
    BSON_ASSERT(0 == strcmp(bson_iter_utf8(&iter, NULL), _mongocrypt_tester_plaintext(tester)));

    mongocrypt_binary_destroy(bin);
    _mongocrypt_buffer_cleanup(&encrypted_cmd);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_local_kms(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_local_roundtrip);
}