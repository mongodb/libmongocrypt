/*
 * Copyright 2024-present MongoDB, Inc.
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

/*
 * OSS-Fuzz fuzzing entry point for libmongocrypt.
 *
 * Exercises the libmongocrypt state machine by initializing contexts for
 * various operations and feeding fuzzed data through each state transition.
 */

#include "mongocrypt.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* MONGOCRYPT_KEY_LEN is 96 bytes (defined in mongocrypt-crypto-private.h). */
#define FUZZ_KEY_LEN 96

/* Maximum number of state transitions to prevent infinite loops. */
#define MAX_STATE_TRANSITIONS 32

/* Operation types selected by the first byte of fuzz input. */
enum {
    OP_ENCRYPT = 0,
    OP_DECRYPT = 1,
    OP_EXPLICIT_ENCRYPT = 2,
    OP_EXPLICIT_DECRYPT = 3,
    OP_DATAKEY = 4,
    OP_REWRAP_MANY_DATAKEY = 5,
    OP_EXPLICIT_ENCRYPT_EXPRESSION = 6,
    OP_COUNT = 7,
};

/* Helper: consume bytes from the fuzz input. */
static const uint8_t *fuzz_consume(const uint8_t **data, size_t *remaining, size_t n) {
    if (*remaining < n) {
        return NULL;
    }
    const uint8_t *ptr = *data;
    *data += n;
    *remaining -= n;
    return ptr;
}

/* Helper: consume one byte. */
static int fuzz_consume_byte(const uint8_t **data, size_t *remaining) {
    const uint8_t *p = fuzz_consume(data, remaining, 1);
    return p ? *p : -1;
}

/*
 * Drive the context state machine, feeding fuzzed data at each state.
 * Returns when the context reaches DONE, ERROR, or we run out of input.
 */
static void drive_ctx(mongocrypt_ctx_t *ctx, const uint8_t **data, size_t *remaining) {
    mongocrypt_ctx_state_t state;
    int transitions = 0;

    while (transitions++ < MAX_STATE_TRANSITIONS) {
        state = mongocrypt_ctx_state(ctx);

        switch (state) {
        case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB:
        case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
        case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
        case MONGOCRYPT_CTX_NEED_MONGO_KEYS: {
            /* Feed fuzzed BSON-like data as a mongo response. */
            size_t feed_len = 0;
            const uint8_t *len_bytes = fuzz_consume(data, remaining, 2);
            if (!len_bytes) {
                return;
            }
            feed_len = (size_t)len_bytes[0] | ((size_t)len_bytes[1] << 8);
            if (feed_len > *remaining) {
                feed_len = *remaining;
            }
            if (feed_len > 0) {
                const uint8_t *feed_data = fuzz_consume(data, remaining, feed_len);
                if (feed_data) {
                    mongocrypt_binary_t *bin =
                        mongocrypt_binary_new_from_data((uint8_t *)feed_data, (uint32_t)feed_len);
                    if (bin) {
                        mongocrypt_ctx_mongo_feed(ctx, bin);
                        mongocrypt_binary_destroy(bin);
                    }
                }
            }
            mongocrypt_ctx_mongo_done(ctx);
            break;
        }

        case MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS: {
            /* Feed fuzzed KMS provider credentials. */
            size_t feed_len = 0;
            const uint8_t *len_bytes = fuzz_consume(data, remaining, 2);
            if (!len_bytes) {
                return;
            }
            feed_len = (size_t)len_bytes[0] | ((size_t)len_bytes[1] << 8);
            if (feed_len > *remaining) {
                feed_len = *remaining;
            }
            if (feed_len > 0) {
                const uint8_t *feed_data = fuzz_consume(data, remaining, feed_len);
                if (feed_data) {
                    mongocrypt_binary_t *bin =
                        mongocrypt_binary_new_from_data((uint8_t *)feed_data, (uint32_t)feed_len);
                    if (bin) {
                        mongocrypt_ctx_provide_kms_providers(ctx, bin);
                        mongocrypt_binary_destroy(bin);
                    }
                }
            } else {
                /* Provide empty doc to advance past this state. */
                uint8_t empty_bson[] = {5, 0, 0, 0, 0}; /* empty BSON document */
                mongocrypt_binary_t *bin = mongocrypt_binary_new_from_data(empty_bson, sizeof(empty_bson));
                if (bin) {
                    mongocrypt_ctx_provide_kms_providers(ctx, bin);
                    mongocrypt_binary_destroy(bin);
                }
            }
            break;
        }

        case MONGOCRYPT_CTX_NEED_KMS: {
            /* Iterate KMS contexts and feed fuzzed response data. */
            mongocrypt_kms_ctx_t *kms_ctx;
            while ((kms_ctx = mongocrypt_ctx_next_kms_ctx(ctx)) != NULL) {
                uint32_t bytes_needed = mongocrypt_kms_ctx_bytes_needed(kms_ctx);
                if (bytes_needed == 0) {
                    continue;
                }
                size_t feed_len = bytes_needed;
                if (feed_len > *remaining) {
                    feed_len = *remaining;
                }
                if (feed_len == 0) {
                    return;
                }
                const uint8_t *feed_data = fuzz_consume(data, remaining, feed_len);
                if (feed_data) {
                    mongocrypt_binary_t *bin =
                        mongocrypt_binary_new_from_data((uint8_t *)feed_data, (uint32_t)feed_len);
                    if (bin) {
                        mongocrypt_kms_ctx_feed(kms_ctx, bin);
                        mongocrypt_binary_destroy(bin);
                    }
                }
            }
            mongocrypt_ctx_kms_done(ctx);
            break;
        }

        case MONGOCRYPT_CTX_READY: {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            if (out) {
                mongocrypt_ctx_finalize(ctx, out);
                mongocrypt_binary_destroy(out);
            }
            break;
        }

        case MONGOCRYPT_CTX_DONE:
        case MONGOCRYPT_CTX_ERROR:
        default: return;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /*
     * Need at least 1 byte for op selection + some data to feed.
     * Trivially small inputs won't exercise meaningful code paths.
     */
    if (size < 5) {
        return 0;
    }

    const uint8_t *cursor = data;
    size_t remaining = size;

    /* Consume first byte to select operation. */
    int op = fuzz_consume_byte(&cursor, &remaining) % OP_COUNT;

    /* Set up mongocrypt_t with a local KMS provider. */
    mongocrypt_t *crypt = mongocrypt_new();
    if (!crypt) {
        return 0;
    }

    /* Configure local KMS provider with a fixed 96-byte key. */
    uint8_t local_key[FUZZ_KEY_LEN];
    memset(local_key, 0xAB, FUZZ_KEY_LEN);
    mongocrypt_binary_t *key_bin = mongocrypt_binary_new_from_data(local_key, FUZZ_KEY_LEN);
    if (!key_bin) {
        mongocrypt_destroy(crypt);
        return 0;
    }
    mongocrypt_setopt_kms_provider_local(crypt, key_bin);
    mongocrypt_binary_destroy(key_bin);

    if (!mongocrypt_init(crypt)) {
        mongocrypt_destroy(crypt);
        return 0;
    }

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    if (!ctx) {
        mongocrypt_destroy(crypt);
        return 0;
    }

    /* Create a binary view of remaining fuzz data for init calls. */
    mongocrypt_binary_t *input_bin = NULL;
    if (remaining > 0) {
        input_bin = mongocrypt_binary_new_from_data((uint8_t *)cursor, (uint32_t)remaining);
    }

    bool init_ok = false;

    switch (op) {
    case OP_ENCRYPT:
        if (input_bin) {
            init_ok = mongocrypt_ctx_encrypt_init(ctx, "test", -1, input_bin);
        }
        break;

    case OP_DECRYPT:
        if (input_bin) {
            init_ok = mongocrypt_ctx_decrypt_init(ctx, input_bin);
        }
        break;

    case OP_EXPLICIT_ENCRYPT: {
        /* Set a fixed key id (16-byte UUID). */
        uint8_t key_id[16];
        memset(key_id, 0x61, sizeof(key_id)); /* matches "YWFhYWFhYWFhYWFhYWFhYQ==" */
        mongocrypt_binary_t *kid_bin = mongocrypt_binary_new_from_data(key_id, sizeof(key_id));
        if (kid_bin) {
            mongocrypt_ctx_setopt_key_id(ctx, kid_bin);
            mongocrypt_binary_destroy(kid_bin);
        }
        mongocrypt_ctx_setopt_algorithm(ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
        if (input_bin) {
            init_ok = mongocrypt_ctx_explicit_encrypt_init(ctx, input_bin);
        }
        break;
    }

    case OP_EXPLICIT_DECRYPT:
        if (input_bin) {
            init_ok = mongocrypt_ctx_explicit_decrypt_init(ctx, input_bin);
        }
        break;

    case OP_DATAKEY: {
        /* Set up key encryption key for local provider. */
        uint8_t kek_bson[] = {
            /* {"provider": "local"} as BSON */
            0x1b, 0x00, 0x00, 0x00,                                     /* doc len = 27 */
            0x02,                                                        /* type: string */
            'p', 'r', 'o', 'v', 'i', 'd', 'e', 'r', 0x00,              /* key */
            0x06, 0x00, 0x00, 0x00,                                      /* string len = 6 */
            'l', 'o', 'c', 'a', 'l', 0x00,                              /* value */
            0x00                                                         /* doc terminator */
        };
        mongocrypt_binary_t *kek_bin = mongocrypt_binary_new_from_data(kek_bson, sizeof(kek_bson));
        if (kek_bin) {
            mongocrypt_ctx_setopt_key_encryption_key(ctx, kek_bin);
            mongocrypt_binary_destroy(kek_bin);
        }
        init_ok = mongocrypt_ctx_datakey_init(ctx);
        break;
    }

    case OP_REWRAP_MANY_DATAKEY:
        if (input_bin) {
            init_ok = mongocrypt_ctx_rewrap_many_datakey_init(ctx, input_bin);
        }
        break;

    case OP_EXPLICIT_ENCRYPT_EXPRESSION: {
        uint8_t key_id[16];
        memset(key_id, 0x61, sizeof(key_id));
        mongocrypt_binary_t *kid_bin = mongocrypt_binary_new_from_data(key_id, sizeof(key_id));
        if (kid_bin) {
            mongocrypt_ctx_setopt_key_id(ctx, kid_bin);
            mongocrypt_binary_destroy(kid_bin);
        }
        mongocrypt_ctx_setopt_algorithm(ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
        if (input_bin) {
            init_ok = mongocrypt_ctx_explicit_encrypt_expression_init(ctx, input_bin);
        }
        break;
    }

    default: break;
    }

    if (input_bin) {
        mongocrypt_binary_destroy(input_bin);
    }

    /* If initialization succeeded, drive the state machine with fuzzed data. */
    if (init_ok) {
        drive_ctx(ctx, &cursor, &remaining);
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);

    return 0;
}

