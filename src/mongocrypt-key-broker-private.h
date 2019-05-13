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
#include "mongocrypt-cache-private.h"
#include "mongocrypt-kms-ctx-private.h"
#include "mongocrypt-cache-key-private.h"
#include "mongocrypt-binary-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-cache-private.h"

typedef struct __mongocrypt_key_broker_t _mongocrypt_key_broker_t;
/* The key broker acts as a middle-man between an encrypt/decrypt request and
 * the key cache.
 * Each encrypt/decrypt request has one key broker. Key brokers are not shared.
 * It is responsible for:
 * - copying/taking leases on keys in the cache needed for the request
 * - generating find cmd filters to fetch keys that aren't cached or are expired
 * - generating KMS decrypt requests on newly fetched keys
 * - adding newly fetched keys back to the cache
 * TODO: for decryption, errors ought not be fatal. We should decrypt whatever
 * we can, and log an error.
 * TODO: integrate the cache.
 */

/* The state of the key item in the broker. */
typedef enum {
   KEY_EMPTY,      /* has an id/keyAltName, but nothing else. */
   KEY_ENCRYPTED,  /* has the key document from the key vault, with encrypted
                      keyMaterial */
   KEY_DECRYPTING, /* caller has iterated the kms context, but not fed
                      everything yet. */
   KEY_DECRYPTED,  /* has decrypted keyMaterial. */
   KEY_ERROR       /* unable to get this key. status is set. */
} _mongocrypt_key_state_t;


typedef struct __mongocrypt_key_broker_entry_t _mongocrypt_key_broker_entry_t;

struct __mongocrypt_key_broker_t {
   _mongocrypt_key_broker_entry_t *kb_entry; /* head of a linked-list. */
   _mongocrypt_key_broker_entry_t *decryptor_iter;

   mongocrypt_status_t *status;
   _mongocrypt_buffer_t filter;
   _mongocrypt_buffer_t find_cmd;
   bool all_keys_added;
   _mongocrypt_opts_t *crypt_opts;
   _mongocrypt_cache_t *cache_key;
};


void
_mongocrypt_key_broker_init (_mongocrypt_key_broker_t *kb,
                             _mongocrypt_opts_t *opts,
                             _mongocrypt_cache_t *cache_key);


bool
_mongocrypt_key_broker_filter (_mongocrypt_key_broker_t *kb,
                               mongocrypt_binary_t *out);


/* Returns true or false if the key broker has keys matching the passed state.
 */
bool
_mongocrypt_key_broker_has (_mongocrypt_key_broker_t *kb,
                            _mongocrypt_key_state_t state);

/* Returns true if there are keys. */
bool
_mongocrypt_key_broker_empty (_mongocrypt_key_broker_t *kb);


/* Add an ID or keyAltName into the key broker.
   Key is added as KEY_EMPTY. */
bool
_mongocrypt_key_broker_add_name (_mongocrypt_key_broker_t *kb,
                                 const bson_value_t *key_alt_name);

bool
_mongocrypt_key_broker_add_id (_mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id);

/* For testing only, add a decrypted key */
bool
_mongocrypt_key_broker_add_test_key (_mongocrypt_key_broker_t *kb,
                                     const _mongocrypt_buffer_t *key_id);


/* Add a document with encrypted key material, transitioning a KEY_EMPTY key to
 * KEY_ENCRYPTED (or KEY_ERROR). */
bool
_mongocrypt_key_broker_add_doc (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc);


bool
_mongocrypt_key_broker_done_adding_docs (_mongocrypt_key_broker_t *kb);


mongocrypt_kms_ctx_t *
_mongocrypt_key_broker_next_kms (_mongocrypt_key_broker_t *kb);


bool
_mongocrypt_key_broker_kms_done (_mongocrypt_key_broker_t *kb);


bool
_mongocrypt_key_broker_decrypted_key_by_id (_mongocrypt_key_broker_t *kb,
                                            const _mongocrypt_buffer_t *key_id,
                                            _mongocrypt_buffer_t *out);

bool
_mongocrypt_key_broker_decrypted_key_by_name (_mongocrypt_key_broker_t *kb,
                                              const bson_value_t *key_alt_name,
                                              _mongocrypt_buffer_t *out);


bool
_mongocrypt_key_broker_status (_mongocrypt_key_broker_t *kb,
                               mongocrypt_status_t *out);


void
_mongocrypt_key_broker_cleanup (_mongocrypt_key_broker_t *kb);


#endif /* MONGOCRYPT_KEY_BROKER_PRIVATE_H */
