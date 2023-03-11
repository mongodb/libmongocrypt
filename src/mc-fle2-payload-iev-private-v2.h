/*
 * Copyright 2023-present MongoDB, Inc.
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

#ifndef MONGOCRYPT_INDEXED_ENCRYPTED_VALUE_PRIVATE_V2_H
#define MONGOCRYPT_INDEXED_ENCRYPTED_VALUE_PRIVATE_V2_H

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-status-private.h"
#include "mongocrypt-crypto-private.h"
#include "mc-tokens-private.h"

/*
 * FLE2IndexedEqualityEncryptedValueV2 has the following data layout:
 *
 * struct FLE2IndexedEqualityEncryptedValueV2 {
 *   uint8_t fle_blob_subtype = 14;
 *   uint8_t S_KeyId[16];
 *   uint8_t original_bson_type;
 *   uint8_t ServerEncryptedValue[ServerEncryptedValue.length];
 *   FLE2TagAndEncryptedMetadataBlock metadata;
 * }
 *
 * ServerEncryptedValue :=
 *   EncryptCTR(ServerEncryptionToken, ClientEncryptedValue)
 * ClientEncryptedValue := EncryptCBCAEAD(K_Key, clientValue, AD=K_KeyId)
 *
 * The MetadataBlock is ignored by libmongocrypt,
 *   but has the following structure and a fixed size of 96 octets:
 *
 * struct FLE2TagAndEncryptedMetadataBlock {
 *   uint8_t encryptedCount[32]; // EncryptCTR(countEncryptionToken,
 *                               //            count || contentionFactor)
 *   uint8_t tag[32];            // HMAC-SHA256(count, edcTwiceDerived)
 *   uint8_t encryptedZeros[32]; // EncryptCTR(zerosEncryptionToken, 0*)
 * }
 */

typedef struct _mc_FLE2IndexedEqualityEncryptedValueV2_t
   mc_FLE2IndexedEqualityEncryptedValueV2_t;

mc_FLE2IndexedEqualityEncryptedValueV2_t *
mc_FLE2IndexedEqualityEncryptedValueV2_new (void);

bool
mc_FLE2IndexedEqualityEncryptedValueV2_parse (
   mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   const _mongocrypt_buffer_t *buf,
   mongocrypt_status_t *status);

bson_type_t
mc_FLE2IndexedEqualityEncryptedValueV2_get_bson_value_type (
   const mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   mongocrypt_status_t *status);

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValueV2_get_S_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   mongocrypt_status_t *status);

bool
mc_FLE2IndexedEqualityEncryptedValueV2_add_S_Key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   const _mongocrypt_buffer_t *S_Key,
   mongocrypt_status_t *status);

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValueV2_get_ClientEncryptedValue (
   const mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   mongocrypt_status_t *status);

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValueV2_get_K_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   mongocrypt_status_t *status);

bool
mc_FLE2IndexedEqualityEncryptedValueV2_add_K_Key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   const _mongocrypt_buffer_t *K_Key,
   mongocrypt_status_t *status);

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValueV2_get_ClientValue (
   const mc_FLE2IndexedEqualityEncryptedValueV2_t *iev,
   mongocrypt_status_t *status);

void
mc_FLE2IndexedEqualityEncryptedValueV2_destroy (
   mc_FLE2IndexedEqualityEncryptedValueV2_t *iev);

#endif /* MONGOCRYPT_INDEXED_ENCRYPTED_VALUE_PRIVATE_V2_H */
