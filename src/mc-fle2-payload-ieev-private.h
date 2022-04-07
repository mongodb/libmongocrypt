/*
 * Copyright 2022-present MongoDB, Inc.
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

#ifndef MONGOCRYPT_INDEXED_EQUALIY_ENCRYPTED_VALUE_PRIVATE_H
#define MONGOCRYPT_INDEXED_EQUALIY_ENCRYPTED_VALUE_PRIVATE_H

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-status-private.h"
#include "mongocrypt-crypto-private.h"

/**
 * FLE2IndexedEqualityEncryptedValue represents an FLE2 encrypted value. It is
 * created server side.
 */

/* clang-format off */
/*
 * FLE2IndexedEqualityEncryptedValue has the following data layout:
 *   
 * struct {
 *   uint8_t fle_blob_subtype = 7;
 *   uint8_t S_KeyId[16];
 *   uint8_t original_bson_type;
 *   uint8_t InnerEncrypted[InnerEncrypted_length];
 * } FLE2IndexedEqualityEncryptedValue
 * 
 * InnerEncrypted is the output of: Encrypt(key=ServerDataLevel1Token, plaintext=Inner)
 * ServerDataLevel1Token is created from the key identified by S_KeyId.
 *
 * struct {
 *   uint64_t length; // sizeof(K_KeyId) + ClientEncryptedValue_length;
 *   uint8_t K_KeyId[16];
 *   uint8_t ClientEncryptedValue[ClientEncryptedValue_length];
 *   uint64_t counter;
 *   uint8_t edc[32]; // EDCDerivedFromDataTokenAndContentionFactorToken
 *   uint8_t esc[32]; // ESCDerivedFromDataTokenAndContentionFactorToken
 *   uint8_t ecc[32]; // ECCDerivedFromDataTokenAndContentionFactorToken
 *} Inner
 *
 * ClientEncryptedValue is the output of: EncryptAEAD(key=K_Key, plaintext=ClientValue, associated_data=K_KeyId)
 * K_Key is the key identified by K_KeyId.
 */
/* clang-format on */

typedef struct _mc_FLE2IndexedEqualityEncryptedValue_t
   mc_FLE2IndexedEqualityEncryptedValue_t;

mc_FLE2IndexedEqualityEncryptedValue_t *
mc_FLE2IndexedEqualityEncryptedValue_new (void);

bool
mc_FLE2IndexedEqualityEncryptedValue_parse (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   const _mongocrypt_buffer_t *buf,
   mongocrypt_status_t *status);

/* mc_FLE2IndexedEqualityEncryptedValue_get_original_bson_type returns
 * original_bson_type. Returns 0 and sets @status on error.
 * It is an error to call before mc_FLE2IndexedEqualityEncryptedValue_parse. */
bson_type_t
mc_FLE2IndexedEqualityEncryptedValue_get_original_bson_type (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status);

/* mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId returns S_KeyId. Returns
 * NULL and sets @status on error. It is an error to call before
 * mc_FLE2IndexedEqualityEncryptedValue_parse. */
const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status);

/* mc_FLE2IndexedEqualityEncryptedValue_add_S_Key decrypts InnerEncrypted.
 * Returns false and sets @status on error. It is an error to call before
 * mc_FLE2IndexedEqualityEncryptedValue_parse. */
bool
mc_FLE2IndexedEqualityEncryptedValue_add_S_Key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   const _mongocrypt_buffer_t *S_Key,
   mongocrypt_status_t *status);

/* mc_FLE2IndexedEqualityEncryptedValue_get_K_KeyId returns Inner.K_KeyId.
 * Returns NULL and sets @status on error. It is an error to call before
 * mc_FLE2IndexedEqualityEncryptedValue_add_S_Key. */
const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_K_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status);

/* mc_FLE2IndexedEqualityEncryptedValue_add_K_Key decrypts
 * Inner.ClientEncryptedValue. Returns false and sets @status on error. Must
 * not be called before mc_FLE2IndexedEqualityEncryptedValue_add_S_Key. */
bool
mc_FLE2IndexedEqualityEncryptedValue_add_K_Key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   const _mongocrypt_buffer_t *K_Key,
   mongocrypt_status_t *status);

/* mc_FLE2IndexedEqualityEncryptedValue_get_ClientValue returns the decrypted
 * Inner.ClientEncryptedValue. Returns NULL and sets @status on error.
 * It is an error to call before mc_FLE2IndexedEqualityEncryptedValue_add_K_Key.
 */
const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_ClientValue (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status);

void
mc_FLE2IndexedEqualityEncryptedValue_destroy (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev);

#endif /* MONGOCRYPT_INDEXED_EQUALIY_ENCRYPTED_VALUE_PRIVATE_H */
