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

#ifndef MONGOCRYPT_KEY_BROKER_PRIVATE_H
#define MONGOCRYPT_KEY_BROKER_PRIVATE_H

#include <bson/bson.h>

#include "kms_message/kms_message.h"
#include "mongocrypt.h"
#include "mongocrypt-cache-private.h"
#include "mongocrypt-kms-ctx-private.h"
#include "mongocrypt-cache-key-private.h"
#include "mongocrypt-binary-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-cache-private.h"

/* The key broker acts as a middle-man between an encrypt/decrypt request and
 * the key cache.
 * Each encrypt/decrypt request has one key broker. Key brokers are not shared.
 * It is responsible for:
 * - copying/taking leases on keys in the cache needed for the request
 * - generating find cmd filters to fetch keys that aren't cached or are expired
 * - generating KMS decrypt requests on newly fetched keys
 * - adding newly fetched keys back to the cache
 */

/* The state of a key item in the broker. */
typedef enum {
   /* has an id/keyAltName, but nothing else. */
   KEY_EMPTY,
   /* some other context is responsible for this key. We'll get it from the
      cache later. */
   KEY_WAITING_FOR_OTHER_CTX,
   /* has the key document from the key vault, with encrypted keyMaterial */
   KEY_ENCRYPTED,
   /* caller has iterated the kms context, but not fed everything yet. */
   KEY_DECRYPTING,
   /* has decrypted keyMaterial. */
   KEY_DECRYPTED
} _mongocrypt_key_state_t;

/*
 * Valid transitions are:
 * KEY_EMPTY => KEY_WAITING_FOR_OTHER_CTX
 * KEY_EMPTY => KEY_ENCRYPTED
 * KEY_WAITING_FOR_OTHER_CTX => KEY_EMPTY
 * KEY_WAITING_FOR_OTHER_CTX => KEY_DECRYPTED
 * KEY_ENCRYPTED => KEY_DECRYPTING
 * KEY_DECRYPTING => KEY_DECRYPTED
 */
typedef struct __mongocrypt_key_broker_entry_t _mongocrypt_key_broker_entry_t;

typedef struct {
   _mongocrypt_key_broker_entry_t *kb_entry; /* head of a linked-list. */
   _mongocrypt_key_broker_entry_t *decryptor_iter;
   _mongocrypt_key_broker_entry_t *ctx_id_iter;

   mongocrypt_status_t *status; /* TODO: remove this. */
   _mongocrypt_buffer_t filter;
   _mongocrypt_opts_t *crypt_opts;
   _mongocrypt_cache_t *cache_key;
   uint32_t owner_id;
} _mongocrypt_key_broker_t;


void
_mongocrypt_key_broker_init (_mongocrypt_key_broker_t *kb,
                             uint32_t owner_id,
                             _mongocrypt_opts_t *opts,
                             _mongocrypt_cache_t *cache_key);


/* Add an ID into the key broker. */
bool
_mongocrypt_key_broker_add_id (_mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id);


/* For testing only, add a decrypted key */
bool
_mongocrypt_key_broker_add_test_key (_mongocrypt_key_broker_t *kb,
                                     const _mongocrypt_buffer_t *key_id);


/* Get the find command filter. */
bool
_mongocrypt_key_broker_filter (_mongocrypt_key_broker_t *kb,
                               mongocrypt_binary_t *out);


/* Add keyAltName into the key broker.
   Key is added as KEY_EMPTY. */
bool
_mongocrypt_key_broker_add_name (_mongocrypt_key_broker_t *kb,
                                 const bson_value_t *key_alt_name);

bool
_mongocrypt_key_broker_all_state (_mongocrypt_key_broker_t *kb,
                                  _mongocrypt_key_state_t state);


bool
_mongocrypt_key_broker_any_state (_mongocrypt_key_broker_t *kb,
                                  _mongocrypt_key_state_t state);


/* Add a key document. */
bool
_mongocrypt_key_broker_add_doc (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc);


/* Iterate the keys needing KMS decryption. */
mongocrypt_kms_ctx_t *
_mongocrypt_key_broker_next_kms (_mongocrypt_key_broker_t *kb);


/* Indicate that all KMS requests are complete. */
bool
_mongocrypt_key_broker_kms_done (_mongocrypt_key_broker_t *kb);


/* Iterate the contexts we're waiting on for cache entries. */
uint32_t
_mongocrypt_key_broker_next_ctx_id (_mongocrypt_key_broker_t *kb);


bool
_mongocrypt_key_broker_check_cache_and_wait (_mongocrypt_key_broker_t *kb,
                                             bool blocking_wait);


void
_mongocrypt_key_broker_reset_iterators (_mongocrypt_key_broker_t *kb);

/* Get the final decrypted key material from a key. */
bool
_mongocrypt_key_broker_decrypted_key_by_id (_mongocrypt_key_broker_t *kb,
                                            const _mongocrypt_buffer_t *key_id,
                                            _mongocrypt_buffer_t *out);

bool
_mongocrypt_key_broker_decrypted_key_by_name (_mongocrypt_key_broker_t *kb,
                                              const bson_value_t *key_alt_name,
                                              _mongocrypt_buffer_t *out,
                                              _mongocrypt_buffer_t *key_id_out);


bool
_mongocrypt_key_broker_status (_mongocrypt_key_broker_t *kb,
                               mongocrypt_status_t *out);


void
_mongocrypt_key_broker_cleanup (_mongocrypt_key_broker_t *kb);

void
_mongocrypt_key_broker_debug (_mongocrypt_key_broker_t *kb);

#endif /* MONGOCRYPT_KEY_BROKER_PRIVATE_H */
