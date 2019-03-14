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
#include "mongocrypt-key-broker.h"
#include "mongocrypt-key-decryptor-private.h"
#include "mongocrypt-key-cache-private.h"
#include "mongocrypt-binary-private.h"

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
   KEY_EMPTY,     /* has an id/keyAltName, but nothing else. */
   KEY_ENCRYPTED, /* has the key document from the key vault, with encrypted
                     keyMaterial */
   KEY_DECRYPTED, /* has decrypted keyMaterial. */
   KEY_ERROR      /* unable to get this key. status is set. */
} _mongocrypt_key_state_t;


typedef struct __mongocrypt_key_broker_entry_t _mongocrypt_key_broker_entry_t;


struct _mongocrypt_key_broker_t {
   struct __mongocrypt_key_broker_entry_t
      *kb_entry; /* head of a linked-list. */
   struct __mongocrypt_key_broker_entry_t *decryptor_iter;

   mongocrypt_status_t *status;
   mongocrypt_binary_t *filter;
   bool all_keys_added;
};


void
_mongocrypt_key_broker_init (mongocrypt_key_broker_t *kb);


/* Returns true or false if the key broker has keys matching the passed state.
 */
bool
_mongocrypt_key_broker_has (mongocrypt_key_broker_t *kb,
                            _mongocrypt_key_state_t state);

/* Returns true if there are keys. */
bool
_mongocrypt_key_broker_empty (mongocrypt_key_broker_t *kb);


/* Add an ID into the key broker. Key is added as KEY_EMPTY. */
bool
_mongocrypt_key_broker_add_id (mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id);


/* Add a document with encrypted key material, transitioning a KEY_EMPTY key to
 * KEY_ENCRYPTED (or KEY_ERROR). */
bool
_mongocrypt_key_broker_add_doc (mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc);


/* Return an the next decryption request. Pass NULL to get the first. */
mongocrypt_key_decryptor_t *
_mongocrypt_key_broker_next_key_decryptor (mongocrypt_key_broker_t *kb);


/* Transitions a key from KEY_ENCRYPTED to KEY_DECRYPTED (or KEY_ERROR) */
bool
_mongocrypt_key_broker_add_decrypted_key (mongocrypt_key_broker_t *kb,
                                          mongocrypt_key_decryptor_t *req);


const _mongocrypt_buffer_t *
_mongocrypt_key_broker_decrypted_key_material_by_id (
   mongocrypt_key_broker_t *kb,
   _mongocrypt_buffer_t *key_id);


/* TODO: provide an interface for getting a list of the keys in KEY_ERROR state?
 */

void
_mongocrypt_key_broker_cleanup (mongocrypt_key_broker_t *kb);


#endif /* MONGOCRYPT_KEY_BROKER_PRIVATE_H */
