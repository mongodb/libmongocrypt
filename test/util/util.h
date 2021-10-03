/*
 * Copyright 2020-present MongoDB, Inc.
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

#include <stdlib.h>

#include "mongocrypt.h"
#include <mongoc/mongoc.h>

void
_errexit_mongocrypt (mongocrypt_t *crypt, int line);
#define ERREXIT_MONGOCRYPT(crypt) _errexit_mongocrypt (crypt, __LINE__);

void
_errexit_ctx (mongocrypt_ctx_t *ctx, int line);
#define ERREXIT_CTX(ctx) _errexit_ctx (ctx, __LINE__);

void
_errexit_bson (bson_error_t *error, int line);
#define ERREXIT_BSON(err) _errexit_bson (err, __LINE__);

#define ERREXIT(...)              \
   do {                           \
      MONGOC_ERROR (__VA_ARGS__); \
      abort ();                   \
   } while (0)

void
_log_to_stdout (mongocrypt_log_level_t level,
                const char *message,
                uint32_t message_len,
                void *ctx);

char *
util_getenv (const char *key);

mongocrypt_binary_t *
util_bson_to_bin (bson_t *bson);

typedef struct {
   mongocrypt_ctx_t *ctx;
   mongoc_collection_t *keyvault_coll;
   mongoc_client_t *mongocryptd_client;
   mongoc_client_t *collinfo_client;
   const char *db_name;
   bool trace;
   const char *tls_ca_file;
   const char *tls_certificate_key_file;
} _state_machine_t;

bool
_state_machine_run (_state_machine_t *state_machine,
                    bson_t *result,
                    bson_error_t *error);

bson_t *
util_bin_to_bson (mongocrypt_binary_t *bin);

bson_t *
util_read_json_file (const char *path);

void
args_parse (bson_t *args, int argc, char **argv);

const char *
bson_get_utf8 (bson_t *bson, const char *key, const char *default_value);

const char *
bson_req_utf8 (bson_t *bson, const char *key);

const uint8_t *
bson_get_bin (bson_t *bson, const char *dotkey, uint32_t *len);

const uint8_t *
bson_req_bin (bson_t *bson, const char *dotkey, uint32_t *len);

bson_t *
bson_get_json (bson_t *bson, const char *key);

bson_t *
bson_req_json (bson_t *bson, const char *key);

bool
bson_get_bool (bson_t *bson, const char *key, bool default_value);