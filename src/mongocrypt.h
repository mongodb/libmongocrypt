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
#ifndef MONGOCCRYPT_H
#define MONGOCCRYPT_H

/** @file mongocrypt.h The top-level handle to libmongocrypt. */

#include <stdint.h>

#include "mongocrypt-binary.h"
#include "mongocrypt-compat.h"
#include "mongocrypt-export.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-status.h"

#define MONGOCRYPT_VERSION "0.2.0"

/**
 * Returns the version string x.y.z for libmongocrypt.
 *
 * @returns the version string x.y.z for libmongocrypt.
 */
MONGOCRYPT_EXPORT
const char *
mongocrypt_version (void);

/**
 * The top-level handle to libmongocrypt.
 *
 * Create a mongocrypt_t handle to perform operations within libmongocrypt:
 * encryption, decryption, registering log callbacks, etc.
 *
 * Functions on a mongocrypt_t are thread safe, though functions on derived
 * handle (e.g. mongocrypt_encryptor_t) are not and must be owned by a single
 * thread. See each handle's documentation for thread-safety considerations.
 *
 * Multiple mongocrypt_t handles may be created.
 */
typedef struct _mongocrypt_t mongocrypt_t;


MONGOCRYPT_EXPORT
void
mongocrypt_init (const mongocrypt_opts_t *opts);


MONGOCRYPT_EXPORT
void
mongocrypt_cleanup (void);


/**
 * Create a new mongocrypt_t handle.
 *
 * @param opts A pointer to a `mongocrypt_opts_t`. The following options may be
 * set:
 * - MONGOCRYPT_AWS_REGION Should be set to a char*, e.g. "us-east-1"
 * - MONGOCRYPT_AWS_SECRET_ACCESS_KEY Should be set to a char*
 * - MONGOCRYPT_AWS_ACCESS_KEY_ID Should be set to a char*
 * - MONGOCRYPT_LOG_FN An optional log handler. Should be set to a
 * mongocrypt_log_fn_t
 * - MONGOCRYPT_LOG_CTX An optional void* context that is passed to the
 * MONGOCRYPT_LOG_FN. Should be set to a void*.
 *
 * @returns A new mongocrypt_t handle which may be used for other operations.
 */
MONGOCRYPT_EXPORT
mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
void
mongocrypt_destroy (mongocrypt_t *crypt);

#endif /* MONGOCRYPT_H */
