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
#ifndef MONGOCRYPT_TOKENS_PRIVATE_H
#define MONGOCRYPT_TOKENS_PRIVATE_H

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-crypto-private.h"

typedef struct _mc_CollectionsLevel1Token_t mc_CollectionsLevel1Token_t;
mc_CollectionsLevel1Token_t *
mc_CollectionsLevel1Token_new (_mongocrypt_crypto_t *crypto,
                               const _mongocrypt_buffer_t *RootKey,
                               mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_CollectionsLevel1Token_get (mc_CollectionsLevel1Token_t *t);
void
mc_CollectionsLevel1Token_destroy (mc_CollectionsLevel1Token_t *t);


typedef struct _mc_ServerDataEncryptionLevel1Token_t
   mc_ServerDataEncryptionLevel1Token_t;
mc_ServerDataEncryptionLevel1Token_t *
mc_ServerDataEncryptionLevel1Token_new (_mongocrypt_crypto_t *crypto,
                                        const _mongocrypt_buffer_t *RootKey,
                                        mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ServerDataEncryptionLevel1Token_get (
   mc_ServerDataEncryptionLevel1Token_t *t);
void
mc_ServerDataEncryptionLevel1Token_destroy (
   mc_ServerDataEncryptionLevel1Token_t *t);


typedef struct _mc_EDCToken_t mc_EDCToken_t;
mc_EDCToken_t *
mc_EDCToken_new (_mongocrypt_crypto_t *crypto,
                 const mc_CollectionsLevel1Token_t *CollectionsLevel1Token,
                 mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_EDCToken_get (mc_EDCToken_t *t);
void
mc_EDCToken_destroy (mc_EDCToken_t *t);


typedef struct _mc_ESCToken_t mc_ESCToken_t;
mc_ESCToken_t *
mc_ESCToken_new (_mongocrypt_crypto_t *crypto,
                 const mc_CollectionsLevel1Token_t *CollectionsLevel1Token,
                 mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ESCToken_get (mc_ESCToken_t *t);
void
mc_ESCToken_destroy (mc_ESCToken_t *t);


typedef struct _mc_ECCToken_t mc_ECCToken_t;
mc_ECCToken_t *
mc_ECCToken_new (_mongocrypt_crypto_t *crypto,
                 const mc_CollectionsLevel1Token_t *CollectionsLevel1Token,
                 mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ECCToken_get (mc_ECCToken_t *t);
void
mc_ECCToken_destroy (mc_ECCToken_t *t);


typedef struct _mc_ECOCToken_t mc_ECOCToken_t;
mc_ECOCToken_t *
mc_ECOCToken_new (_mongocrypt_crypto_t *crypto,
                  const mc_CollectionsLevel1Token_t *CollectionsLevel1Token,
                  mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ECOCToken_get (mc_ECOCToken_t *t);
void
mc_ECOCToken_destroy (mc_ECOCToken_t *t);


typedef struct _mc_EDCDerivedFromDataToken_t mc_EDCDerivedFromDataToken_t;
mc_EDCDerivedFromDataToken_t *
mc_EDCDerivedFromDataToken_new (_mongocrypt_crypto_t *crypto,
                                const mc_EDCToken_t *EDCToken,
                                const _mongocrypt_buffer_t *v,
                                mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_EDCDerivedFromDataToken_get (mc_EDCDerivedFromDataToken_t *t);
void
mc_EDCDerivedFromDataToken_destroy (mc_EDCDerivedFromDataToken_t *t);


typedef struct _mc_ESCDerivedFromDataToken_t mc_ESCDerivedFromDataToken_t;
mc_ESCDerivedFromDataToken_t *
mc_ESCDerivedFromDataToken_new (_mongocrypt_crypto_t *crypto,
                                const mc_ESCToken_t *ESCToken,
                                const _mongocrypt_buffer_t *v,
                                mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ESCDerivedFromDataToken_get (mc_ESCDerivedFromDataToken_t *t);
void
mc_ESCDerivedFromDataToken_destroy (mc_ESCDerivedFromDataToken_t *t);


typedef struct _mc_ECCDerivedFromDataToken_t mc_ECCDerivedFromDataToken_t;
mc_ECCDerivedFromDataToken_t *
mc_ECCDerivedFromDataToken_new (_mongocrypt_crypto_t *crypto,
                                const mc_ECCToken_t *EDCToken,
                                const _mongocrypt_buffer_t *v,
                                mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ECCDerivedFromDataToken_get (mc_ECCDerivedFromDataToken_t *t);
void
mc_ECCDerivedFromDataToken_destroy (mc_ECCDerivedFromDataToken_t *t);


typedef struct _mc_EDCDerivedFromDataTokenAndCounter_t
   mc_EDCDerivedFromDataTokenAndCounter_t;
mc_EDCDerivedFromDataTokenAndCounter_t *
mc_EDCDerivedFromDataTokenAndCounter_new (
   _mongocrypt_crypto_t *crypto,
   const mc_EDCDerivedFromDataToken_t *EDCDerivedFromDataToken,
   uint64_t u,
   mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_EDCDerivedFromDataTokenAndCounter_get (
   mc_EDCDerivedFromDataTokenAndCounter_t *t);
void
mc_EDCDerivedFromDataTokenAndCounter_destroy (
   mc_EDCDerivedFromDataTokenAndCounter_t *t);


typedef struct _mc_ESCDerivedFromDataTokenAndCounter_t
   mc_ESCDerivedFromDataTokenAndCounter_t;
mc_ESCDerivedFromDataTokenAndCounter_t *
mc_ESCDerivedFromDataTokenAndCounter_new (
   _mongocrypt_crypto_t *crypto,
   const mc_ESCDerivedFromDataToken_t *ESCDerivedFromDataToken,
   uint64_t u,
   mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ESCDerivedFromDataTokenAndCounter_get (
   mc_ESCDerivedFromDataTokenAndCounter_t *t);
void
mc_ESCDerivedFromDataTokenAndCounter_destroy (
   mc_ESCDerivedFromDataTokenAndCounter_t *t);


typedef struct _mc_ECCDerivedFromDataTokenAndCounter_t
   mc_ECCDerivedFromDataTokenAndCounter_t;
mc_ECCDerivedFromDataTokenAndCounter_t *
mc_ECCDerivedFromDataTokenAndCounter_new (
   _mongocrypt_crypto_t *crypto,
   const mc_ECCDerivedFromDataToken_t *ECCDerivedFromDataToken,
   uint64_t u,
   mongocrypt_status_t *status);
const _mongocrypt_buffer_t *
mc_ECCDerivedFromDataTokenAndCounter_get (
   mc_ECCDerivedFromDataTokenAndCounter_t *t);
void
mc_ECCDerivedFromDataTokenAndCounter_destroy (
   mc_ECCDerivedFromDataTokenAndCounter_t *t);


#endif /* MONGOCRYPT_TOKENS_PRIVATE_H */