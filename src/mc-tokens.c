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

#include "mc-tokens-private.h"

/// Define a token type of the given name, with constructor parameters given as
/// the remaining arguments. This macro usage should be followed by the
/// constructor body, with the implicit first argument '_mongocrypt_crypto_t*
/// crypto' and final argument 'mongocrypt_status_t* status'
#define DEF_TOKEN_TYPE(Name, ...) \
   DEF_TOKEN_TYPE_1 (Name, CONCAT (Name, _t), __VA_ARGS__)

#define DEF_TOKEN_TYPE_1(Prefix, T, ...)                             \
   /* Define the struct for the token */                             \
   struct T {                                                        \
      _mongocrypt_buffer_t data;                                     \
   };                                                                \
   /* Data-getter */                                                 \
   const _mongocrypt_buffer_t *CONCAT (Prefix, _get) (const T *self) \
   {                                                                 \
      return &self->data;                                            \
   }                                                                 \
   /* Destructor */                                                  \
   void CONCAT (Prefix, _destroy) (T * self)                         \
   {                                                                 \
      if (!self) {                                                   \
         return;                                                     \
      }                                                              \
      _mongocrypt_buffer_cleanup (&self->data);                      \
      bson_free (self);                                              \
   }                                                                 \
   /* Constructor. Parameter list given as variadic args. */         \
   T *CONCAT (Prefix, _new) (_mongocrypt_crypto_t * crypto,          \
                             __VA_ARGS__,                            \
                             mongocrypt_status_t * status)

DEF_TOKEN_TYPE (mc_CollectionsLevel1Token, const _mongocrypt_buffer_t *RootKey)
{
   mc_CollectionsLevel1Token_t *t =
      bson_malloc0 (sizeof (mc_CollectionsLevel1Token_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash, 1);

   if (!_mongocrypt_hmac_sha_256 (
          crypto, RootKey, &to_hash, &t->data, status)) {
      mc_CollectionsLevel1Token_destroy (t);
      _mongocrypt_buffer_cleanup (&to_hash);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_ServerDataEncryptionLevel1Token,
                const _mongocrypt_buffer_t *RootKey)
{
   mc_ServerDataEncryptionLevel1Token_t *t =
      bson_malloc0 (sizeof (mc_ServerDataEncryptionLevel1Token_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  3);

   if (!_mongocrypt_hmac_sha_256 (
          crypto, RootKey, &to_hash, &t->data, status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_ServerDataEncryptionLevel1Token_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_EDCToken,
                const mc_CollectionsLevel1Token_t *CollectionsLevel1Token)
{
   mc_EDCToken_t *t = bson_malloc0 (sizeof (mc_EDCToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  1);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_CollectionsLevel1Token_get (CollectionsLevel1Token),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_EDCToken_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_ESCToken,
                const mc_CollectionsLevel1Token_t *CollectionsLevel1Token)
{
   mc_ESCToken_t *t = bson_malloc0 (sizeof (mc_ESCToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  2);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_CollectionsLevel1Token_get (CollectionsLevel1Token),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_ESCToken_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_ECCToken,
                const mc_CollectionsLevel1Token_t *CollectionsLevel1Token)
{
   mc_ECCToken_t *t = bson_malloc0 (sizeof (mc_ECCToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  3);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_CollectionsLevel1Token_get (CollectionsLevel1Token),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_ECCToken_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_ECOCToken,
                const mc_CollectionsLevel1Token_t *CollectionsLevel1Token)
{
   mc_ECOCToken_t *t = bson_malloc0 (sizeof (mc_ECOCToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  4);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_CollectionsLevel1Token_get (CollectionsLevel1Token),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_ECOCToken_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_EDCDerivedFromDataToken,
                const mc_EDCToken_t *EDCToken,
                const _mongocrypt_buffer_t *v)
{
   mc_EDCDerivedFromDataToken_t *t =
      bson_malloc0 (sizeof (mc_EDCDerivedFromDataToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   if (!_mongocrypt_hmac_sha_256 (
          crypto, mc_EDCToken_get (EDCToken), v, &t->data, status)) {
      mc_EDCDerivedFromDataToken_destroy (t);
      return NULL;
   }
   return t;
}

DEF_TOKEN_TYPE (mc_ESCDerivedFromDataToken,
                const mc_ESCToken_t *ESCToken,
                const _mongocrypt_buffer_t *v)
{
   mc_ESCDerivedFromDataToken_t *t =
      bson_malloc0 (sizeof (mc_ESCDerivedFromDataToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   if (!_mongocrypt_hmac_sha_256 (
          crypto, mc_ESCToken_get (ESCToken), v, &t->data, status)) {
      mc_ESCDerivedFromDataToken_destroy (t);
      return NULL;
   }
   return t;
}

DEF_TOKEN_TYPE (mc_ECCDerivedFromDataToken,
                const mc_ECCToken_t *ECCToken,
                const _mongocrypt_buffer_t *v)
{
   mc_ECCDerivedFromDataToken_t *t =
      bson_malloc0 (sizeof (mc_ECCDerivedFromDataToken_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);

   if (!_mongocrypt_hmac_sha_256 (
          crypto, mc_ECCToken_get (ECCToken), v, &t->data, status)) {
      mc_ECCDerivedFromDataToken_destroy (t);
      return NULL;
   }
   return t;
}

DEF_TOKEN_TYPE (mc_EDCDerivedFromDataTokenAndCounter,
                const mc_EDCDerivedFromDataToken_t *EDCDerivedFromDataToken,
                uint64_t u)
{
   mc_EDCDerivedFromDataTokenAndCounter_t *t =
      bson_malloc0 (sizeof (mc_EDCDerivedFromDataTokenAndCounter_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);
   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  u);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_EDCDerivedFromDataToken_get (EDCDerivedFromDataToken),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_EDCDerivedFromDataTokenAndCounter_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_ESCDerivedFromDataTokenAndCounter,
                const mc_ESCDerivedFromDataToken_t *ESCDerivedFromDataToken,
                uint64_t u)
{
   mc_ESCDerivedFromDataTokenAndCounter_t *t =
      bson_malloc0 (sizeof (mc_ESCDerivedFromDataTokenAndCounter_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);
   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  u);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_ESCDerivedFromDataToken_get (ESCDerivedFromDataToken),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_ESCDerivedFromDataTokenAndCounter_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}

DEF_TOKEN_TYPE (mc_ECCDerivedFromDataTokenAndCounter,
                const mc_ECCDerivedFromDataToken_t *ECCDerivedFromDataToken,
                uint64_t u)
{
   mc_ECCDerivedFromDataTokenAndCounter_t *t =
      bson_malloc0 (sizeof (mc_ECCDerivedFromDataTokenAndCounter_t));
   _mongocrypt_buffer_init (&t->data);
   _mongocrypt_buffer_resize (&t->data, MONGOCRYPT_HMAC_SHA256_LEN);
   _mongocrypt_buffer_t to_hash;
   _mongocrypt_buffer_copy_from_uint64_le (&to_hash,  u);

   if (!_mongocrypt_hmac_sha_256 (
          crypto,
          mc_ECCDerivedFromDataToken_get (ECCDerivedFromDataToken),
          &to_hash,
          &t->data,
          status)) {
      _mongocrypt_buffer_cleanup (&to_hash);
      mc_ECCDerivedFromDataTokenAndCounter_destroy (t);
      return NULL;
   }
   _mongocrypt_buffer_cleanup (&to_hash);
   return t;
}
