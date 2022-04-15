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

#include "mc-fle-blob-subtype-private.h"
#include "mc-fle2-encryption-placeholder-private.h"
#include "mc-fle2-find-equality-payload-private.h"
#include "mc-fle2-insert-update-payload-private.h"
#include "mc-tokens-private.h"
#include "mongocrypt.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-marking-private.h"

static bool
_mongocrypt_marking_parse_fle1_placeholder (const bson_t *in,
                                            _mongocrypt_marking_t *out,
                                            mongocrypt_status_t *status)
{
   bson_iter_t iter;
   bool has_ki = false, has_ka = false, has_a = false, has_v = false;

   out->type = MONGOCRYPT_MARKING_FLE1_BY_ID;

   if (!bson_iter_init (&iter, in)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   while (bson_iter_next (&iter)) {
      const char *field;

      field = bson_iter_key (&iter);
      BSON_ASSERT (field);
      if (0 == strcmp ("ki", field)) {
         has_ki = true;
         if (!_mongocrypt_buffer_from_uuid_iter (&out->key_id, &iter)) {
            CLIENT_ERR ("key id must be a UUID");
            return false;
         }
         continue;
      }

      if (0 == strcmp ("ka", field)) {
         has_ka = true;
         /* Some bson_value types are not allowed to be key alt names */
         const bson_value_t *value;

         value = bson_iter_value (&iter);

         if (!BSON_ITER_HOLDS_UTF8 (&iter)) {
            CLIENT_ERR ("key alt name must be a UTF8");
            return false;
         }
         /* CDRIVER-3100 We must make a copy of this value; the result of
          * bson_iter_value is ephemeral. */
         bson_value_copy (value, &out->key_alt_name);
         out->type = MONGOCRYPT_MARKING_FLE1_BY_ALTNAME;
         continue;
      }

      if (0 == strcmp ("v", field)) {
         has_v = true;
         memcpy (&out->v_iter, &iter, sizeof (bson_iter_t));
         continue;
      }


      if (0 == strcmp ("a", field)) {
         int32_t algorithm;

         has_a = true;
         if (!BSON_ITER_HOLDS_INT32 (&iter)) {
            CLIENT_ERR ("invalid marking, 'a' must be an int32");
            return false;
         }
         algorithm = bson_iter_int32 (&iter);
         if (algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC &&
             algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM) {
            CLIENT_ERR ("invalid algorithm value: %d", algorithm);
            return false;
         }
         out->algorithm = (mongocrypt_encryption_algorithm_t) algorithm;
         continue;
      }

      CLIENT_ERR ("unrecognized field '%s'", field);
      return false;
   }

   if (!has_v) {
      CLIENT_ERR ("no 'v' specified");
      return false;
   }

   if (!has_ki && !has_ka) {
      CLIENT_ERR ("neither 'ki' nor 'ka' specified");
      return false;
   }

   if (has_ki && has_ka) {
      CLIENT_ERR ("both 'ki' and 'ka' specified");
      return false;
   }

   if (!has_a) {
      CLIENT_ERR ("no 'a' specified");
      return false;
   }

   return true;
}

static bool
_mongocrypt_marking_parse_fle2_placeholder (const bson_t *in,
                                            _mongocrypt_marking_t *out,
                                            mongocrypt_status_t *status)
{
   out->type = MONGOCRYPT_MARKING_FLE2_ENCRYPTION;
   return mc_FLE2EncryptionPlaceholder_parse (&out->fle2, in, status);
}

bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status)
{
   bson_t bson;

   _mongocrypt_marking_init (out);
   /* 5 for minimal BSON object, plus one for blob subtype */
   if (in->len < 6) {
      CLIENT_ERR ("invalid marking, length < 6");
      return false;
   }

   if (!bson_init_static (&bson, in->data + 1, in->len - 1) ||
       !bson_validate (&bson, BSON_VALIDATE_NONE, NULL)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   if (in->data[0] == MC_SUBTYPE_FLE1EncryptionPlaceholder) {
      return _mongocrypt_marking_parse_fle1_placeholder (&bson, out, status);
   } else if (in->data[0] == MC_SUBTYPE_FLE2EncryptionPlaceholder) {
      return _mongocrypt_marking_parse_fle2_placeholder (&bson, out, status);
   } else {
      CLIENT_ERR ("invalid marking, first byte must be 0 or 3");
      return false;
   }
}


void
_mongocrypt_marking_init (_mongocrypt_marking_t *marking)
{
   memset (marking, 0, sizeof (*marking));
}


void
_mongocrypt_marking_cleanup (_mongocrypt_marking_t *marking)
{
   if (marking->type == MONGOCRYPT_MARKING_FLE2_ENCRYPTION) {
      mc_FLE2EncryptionPlaceholder_cleanup (&marking->fle2);
      return;
   }

   // else FLE1
   _mongocrypt_buffer_cleanup (&marking->key_id);
   bson_value_destroy (&marking->key_alt_name);
}


/**
 * Calculates:
 * E?CToken = HMAC(collectionLevel1Token, n)
 * E?CDerivedFromDataToken = HMAC(E?CToken, value)
 * E?CDerivedFromDataTokenAndCounter = HMAC(E?CDerivedFromDataToken, c)
 *
 * E?C = EDC|ESC|ECC
 * n = 1 for EDC, 2 for ESC, 3 for ECC
 * c = maxContentionCounter
 *
 * E?CDerivedFromDataTokenAndCounter is saved to out,
 * which is initialized even on failure.
 */
#define DERIVE_TOKEN_IMPL(Name)                                                \
   static bool _fle2_derive_##Name##_token (                                   \
      _mongocrypt_crypto_t *crypto,                                            \
      _mongocrypt_buffer_t *out,                                               \
      const mc_CollectionsLevel1Token_t *level1Token,                          \
      const _mongocrypt_buffer_t *value,                                       \
      int64_t counter,                                                         \
      mongocrypt_status_t *status)                                             \
   {                                                                           \
      _mongocrypt_buffer_init (out);                                           \
                                                                               \
      mc_##Name##Token_t *token =                                              \
         mc_##Name##Token_new (crypto, level1Token, status);                   \
      if (!token) {                                                            \
         return false;                                                         \
      }                                                                        \
                                                                               \
      mc_##Name##DerivedFromDataToken_t *fromDataToken =                       \
         mc_##Name##DerivedFromDataToken_new (crypto, token, value, status);   \
      mc_##Name##Token_destroy (token);                                        \
      if (!fromDataToken) {                                                    \
         return false;                                                         \
      }                                                                        \
                                                                               \
      mc_##Name##DerivedFromDataTokenAndCounter_t *fromTokenAndCounter =       \
         mc_##Name##DerivedFromDataTokenAndCounter_new (                       \
            crypto, fromDataToken, counter, status);                           \
      mc_##Name##DerivedFromDataToken_destroy (fromDataToken);                 \
      if (!fromTokenAndCounter) {                                              \
         return false;                                                         \
      }                                                                        \
                                                                               \
      _mongocrypt_buffer_copy_to (                                             \
         mc_##Name##DerivedFromDataTokenAndCounter_get (fromTokenAndCounter),  \
         out);                                                                 \
      mc_##Name##DerivedFromDataTokenAndCounter_destroy (fromTokenAndCounter); \
                                                                               \
      return true;                                                             \
   }

DERIVE_TOKEN_IMPL (EDC)
DERIVE_TOKEN_IMPL (ESC)
DERIVE_TOKEN_IMPL (ECC)

#undef DERIVE_TOKEN_IMPL

static bool
_fle2_placeholder_aes_ctr_encrypt (_mongocrypt_key_broker_t *kb,
                                   const _mongocrypt_buffer_t *key,
                                   const _mongocrypt_buffer_t *in,
                                   _mongocrypt_buffer_t *out,
                                   mongocrypt_status_t *status)
{
   _mongocrypt_crypto_t *crypto = kb->crypt->crypto;
   _mongocrypt_buffer_t iv;
   const uint32_t cipherlen =
      _mongocrypt_fle2_calculate_ciphertext_len (in->len);
   uint32_t written = 0;

   _mongocrypt_buffer_init_size (out, cipherlen);

   BSON_ASSERT (
      _mongocrypt_buffer_from_subrange (&iv, out, 0, MONGOCRYPT_IV_LEN));
   if (!_mongocrypt_random (crypto, &iv, MONGOCRYPT_IV_LEN, status)) {
      return false;
   }

   if (!_mongocrypt_fle2_do_encryption (
          crypto, &iv, key, in, out, &written, status)) {
      _mongocrypt_buffer_cleanup (out);
      _mongocrypt_buffer_init (out);
      return false;
   }

   return true;
}


static bool
_fle2_placeholder_aead_encrypt (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *keyId,
                                const _mongocrypt_buffer_t *in,
                                _mongocrypt_buffer_t *out,
                                mongocrypt_status_t *status)
{
   _mongocrypt_crypto_t *crypto = kb->crypt->crypto;
   _mongocrypt_buffer_t iv, key;
   const uint32_t cipherlen =
      _mongocrypt_fle2aead_calculate_ciphertext_len (in->len);
   uint32_t written = 0;
   bool res;

   if (!_mongocrypt_key_broker_decrypted_key_by_id (kb, keyId, &key)) {
      CLIENT_ERR ("unable to retrieve key");
      return false;
   }

   _mongocrypt_buffer_init_size (&iv, MONGOCRYPT_IV_LEN);
   if (!_mongocrypt_random (crypto, &iv, iv.len, status)) {
      _mongocrypt_buffer_cleanup (&key);
      return false;
   }

   _mongocrypt_buffer_init_size (out, cipherlen);
   res = _mongocrypt_fle2aead_do_encryption (
      crypto, &iv, keyId, &key, in, out, &written, status);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);

   if (!res) {
      _mongocrypt_buffer_cleanup (out);
      _mongocrypt_buffer_init (out);
      return false;
   }

   return true;
}


// Field derivations shared by both INSERT and FIND payloads.
typedef struct {
   _mongocrypt_buffer_t tokenKey;
   mc_CollectionsLevel1Token_t *collectionsLevel1Token;
   _mongocrypt_buffer_t edcDerivedToken;
   _mongocrypt_buffer_t escDerivedToken;
   _mongocrypt_buffer_t eccDerivedToken;
} _FLE2EncryptedPayloadCommon_t;

static void
_FLE2EncryptedPayloadCommon_cleanup (_FLE2EncryptedPayloadCommon_t *common)
{
   _mongocrypt_buffer_cleanup (&common->tokenKey);
   mc_CollectionsLevel1Token_destroy (common->collectionsLevel1Token);
   _mongocrypt_buffer_cleanup (&common->edcDerivedToken);
   _mongocrypt_buffer_cleanup (&common->escDerivedToken);
   _mongocrypt_buffer_cleanup (&common->eccDerivedToken);
   memset (common, 0, sizeof (*common));
}


static bool
_mongocrypt_fle2_placeholder_common (_mongocrypt_key_broker_t *kb,
                                     _FLE2EncryptedPayloadCommon_t *ret,
                                     const _mongocrypt_buffer_t *indexKeyId,
                                     const _mongocrypt_buffer_t *value,
                                     int64_t maxContentionCounter,
                                     mongocrypt_status_t *status)
{
   _mongocrypt_crypto_t *crypto = kb->crypt->crypto;
   _mongocrypt_buffer_t indexKey = {0};
   memset (ret, 0, sizeof (*ret));

   if (!_mongocrypt_key_broker_decrypted_key_by_id (
          kb, indexKeyId, &indexKey)) {
      CLIENT_ERR ("unable to retreive key");
      goto fail;
   }

   if (indexKey.len != MONGOCRYPT_KEY_LEN) {
      CLIENT_ERR ("invalid indexKey, expected len=%" PRIu32
                  ", got len=%" PRIu32,
                  MONGOCRYPT_KEY_LEN,
                  indexKey.len);
      goto fail;
   }

   // indexKey is 3 equal sized keys: [Ke][Km][TokenKey]
   BSON_ASSERT (MONGOCRYPT_KEY_LEN == (3 * MONGOCRYPT_TOKEN_KEY_LEN));
   if (!_mongocrypt_buffer_copy_from_data_and_size (
          &ret->tokenKey,
          indexKey.data + (2 * MONGOCRYPT_TOKEN_KEY_LEN),
          MONGOCRYPT_TOKEN_KEY_LEN)) {
      CLIENT_ERR ("failed allocating memory for token key");
      goto fail;
   }

   ret->collectionsLevel1Token =
      mc_CollectionsLevel1Token_new (crypto, &ret->tokenKey, status);
   if (!ret->collectionsLevel1Token) {
      CLIENT_ERR ("unable to derive collectionLevel1Token");
      goto fail;
   }

   if (!_fle2_derive_EDC_token (crypto,
                                &ret->edcDerivedToken,
                                ret->collectionsLevel1Token,
                                value,
                                maxContentionCounter,
                                status)) {
      goto fail;
   }

   if (!_fle2_derive_ESC_token (crypto,
                                &ret->escDerivedToken,
                                ret->collectionsLevel1Token,
                                value,
                                maxContentionCounter,
                                status)) {
      goto fail;
   }

   if (!_fle2_derive_ECC_token (crypto,
                                &ret->eccDerivedToken,
                                ret->collectionsLevel1Token,
                                value,
                                maxContentionCounter,
                                status)) {
      goto fail;
   }

   return true;
fail:
   _FLE2EncryptedPayloadCommon_cleanup (ret);
   _mongocrypt_buffer_cleanup (&indexKey);
   return false;
}


static bool
_mongocrypt_fle2_placeholder_to_insert_update_ciphertext (
   _mongocrypt_key_broker_t *kb,
   _mongocrypt_marking_t *marking,
   _mongocrypt_ciphertext_t *ciphertext,
   mongocrypt_status_t *status)
{
   _mongocrypt_crypto_t *crypto = kb->crypt->crypto;
   _FLE2EncryptedPayloadCommon_t common = {{0}};
   _mongocrypt_buffer_t value = {0};
   mc_FLE2EncryptionPlaceholder_t *placeholder = &marking->fle2;
   mc_FLE2InsertUpdatePayload_t payload;
   bool res = false;

   BSON_ASSERT (marking->type == MONGOCRYPT_MARKING_FLE2_ENCRYPTION);
   BSON_ASSERT (placeholder->type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT);
   _mongocrypt_ciphertext_init (ciphertext);
   _mongocrypt_buffer_init (&value);
   mc_FLE2InsertUpdatePayload_init (&payload);

   _mongocrypt_buffer_from_iter (&value, &placeholder->v_iter);

   if (!_mongocrypt_fle2_placeholder_common (kb,
                                             &common,
                                             &placeholder->index_key_id,
                                             &value,
                                             placeholder->maxContentionCounter,
                                             status)) {
      goto fail;
   }

   // d := EDCDerivedToken
   _mongocrypt_buffer_steal (&payload.edcDerivedToken, &common.edcDerivedToken);
   // s := ESCDerivedToken
   _mongocrypt_buffer_steal (&payload.escDerivedToken, &common.escDerivedToken);
   // c := ECCDerivedToken
   _mongocrypt_buffer_steal (&payload.eccDerivedToken, &common.eccDerivedToken);

   // p := EncryptCTR(ECOCToken, ESCDerivedFromDataTokenAndCounter ||
   // ECCDerivedFromDataTokenAndCounter)
   {
      _mongocrypt_buffer_t tokens[] = {payload.escDerivedToken,
                                       payload.eccDerivedToken};
      _mongocrypt_buffer_t p;
      _mongocrypt_buffer_concat (&p, tokens, 2);
      mc_ECOCToken_t *ecocToken =
         mc_ECOCToken_new (crypto, common.collectionsLevel1Token, status);
      if (!ecocToken) {
         _mongocrypt_buffer_cleanup (&p);
         goto fail;
      }
      res = _fle2_placeholder_aes_ctr_encrypt (kb,
                                               mc_ECOCToken_get (ecocToken),
                                               &p,
                                               &payload.encryptedTokens,
                                               status);
      _mongocrypt_buffer_cleanup (&p);
      mc_ECOCToken_destroy (ecocToken);
      if (!res) {
         goto fail;
      }
   }

   _mongocrypt_buffer_copy_to (&placeholder->index_key_id,
                               &payload.indexKeyId);          // u
   payload.valueType = bson_iter_type (&placeholder->v_iter); // t

   // v := UserKeyId + EncryptAEAD(UserKey, value)
   {
      _mongocrypt_buffer_t tmp[2] = {placeholder->user_key_id, {0}};
      if (!_fle2_placeholder_aead_encrypt (
             kb, &placeholder->user_key_id, &value, &tmp[1], status)) {
         goto fail;
      }
      res = _mongocrypt_buffer_concat (&payload.value, tmp, 2);
      _mongocrypt_buffer_cleanup (&tmp[1]);
      if (!res) {
         goto fail;
      }
   }

   // e := collectionLevel1Token
   {
      mc_ServerDataEncryptionLevel1Token_t *serverToken =
         mc_ServerDataEncryptionLevel1Token_new (
            crypto, &common.tokenKey, status);
      if (!serverToken) {
         goto fail;
      }
      _mongocrypt_buffer_copy_to (
         mc_ServerDataEncryptionLevel1Token_get (serverToken),
         &payload.serverEncryptionToken);
      mc_ServerDataEncryptionLevel1Token_destroy (serverToken);
   }

   {
      bson_t out;
      bson_init (&out);
      mc_FLE2InsertUpdatePayload_serialize (&out, &payload);
      _mongocrypt_buffer_steal_from_bson (&ciphertext->data, &out);
   }
   _mongocrypt_buffer_steal (&ciphertext->key_id, &payload.indexKeyId);
   ciphertext->original_bson_type =
      (uint8_t) bson_iter_type (&placeholder->v_iter);
   ciphertext->blob_subtype = MC_SUBTYPE_FLE2InsertUpdatePayload;

   res = true;
fail:
   mc_FLE2InsertUpdatePayload_cleanup (&payload);
   _mongocrypt_buffer_cleanup (&value);
   _FLE2EncryptedPayloadCommon_cleanup (&common);

   return res;
}


static bool
_mongocrypt_fle2_placeholder_to_find_ciphertext (
   _mongocrypt_key_broker_t *kb,
   _mongocrypt_marking_t *marking,
   _mongocrypt_ciphertext_t *ciphertext,
   mongocrypt_status_t *status)
{
   _FLE2EncryptedPayloadCommon_t common = {{0}};
   _mongocrypt_buffer_t value = {0};
   mc_FLE2EncryptionPlaceholder_t *placeholder = &marking->fle2;
   mc_FLE2FindEqualityPayload_t payload;
   bool res = false;

   BSON_ASSERT (marking->type == MONGOCRYPT_MARKING_FLE2_ENCRYPTION);
   BSON_ASSERT (placeholder->type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND);
   _mongocrypt_ciphertext_init (ciphertext);
   _mongocrypt_buffer_init (&value);
   mc_FLE2FindEqualityPayload_init (&payload);

   _mongocrypt_buffer_from_iter (&value, &placeholder->v_iter);

   if (!_mongocrypt_fle2_placeholder_common (kb,
                                             &common,
                                             &placeholder->index_key_id,
                                             &value,
                                             placeholder->maxContentionCounter,
                                             status)) {
      goto fail;
   }

   // d := EDCDerivedToken
   _mongocrypt_buffer_steal (&payload.edcDerivedToken, &common.edcDerivedToken);
   // s := ESCDerivedToken
   _mongocrypt_buffer_steal (&payload.escDerivedToken, &common.escDerivedToken);
   // c := ECCDerivedToken
   _mongocrypt_buffer_steal (&payload.eccDerivedToken, &common.eccDerivedToken);

   payload.maxContentionCounter = placeholder->maxContentionCounter;

   {
      bson_t out;
      bson_init (&out);
      mc_FLE2FindEqualityPayload_serialize (&out, &payload);
      _mongocrypt_buffer_steal_from_bson (&ciphertext->data, &out);
   }
   _mongocrypt_buffer_steal (&ciphertext->key_id, &placeholder->index_key_id);
   ciphertext->original_bson_type =
      (uint8_t) bson_iter_type (&placeholder->v_iter);
   ciphertext->blob_subtype = MC_SUBTYPE_FLE2FindEqualityPayload;

   res = true;
fail:
   mc_FLE2FindEqualityPayload_cleanup (&payload);
   _mongocrypt_buffer_cleanup (&value);
   _FLE2EncryptedPayloadCommon_cleanup (&common);

   return res;
}

static bool
_mongocrypt_fle1_marking_to_ciphertext (_mongocrypt_key_broker_t *kb,
                                        _mongocrypt_marking_t *marking,
                                        _mongocrypt_ciphertext_t *ciphertext,
                                        mongocrypt_status_t *status)
{
   _mongocrypt_buffer_t plaintext;
   _mongocrypt_buffer_t iv;
   _mongocrypt_buffer_t associated_data;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_buffer_t key_id;
   bool ret = false;
   bool key_found;
   uint32_t bytes_written;

   BSON_ASSERT ((marking->type == MONGOCRYPT_MARKING_FLE1_BY_ID) ||
                (marking->type == MONGOCRYPT_MARKING_FLE1_BY_ALTNAME));

   _mongocrypt_buffer_init (&plaintext);
   _mongocrypt_buffer_init (&associated_data);
   _mongocrypt_buffer_init (&iv);
   _mongocrypt_buffer_init (&key_id);
   _mongocrypt_buffer_init (&key_material);

   /* Get the decrypted key for this marking. */
   if (marking->type == MONGOCRYPT_MARKING_FLE1_BY_ALTNAME) {
      key_found = _mongocrypt_key_broker_decrypted_key_by_name (
         kb, &marking->key_alt_name, &key_material, &key_id);
   } else if (!_mongocrypt_buffer_empty (&marking->key_id)) {
      key_found = _mongocrypt_key_broker_decrypted_key_by_id (
         kb, &marking->key_id, &key_material);
      _mongocrypt_buffer_copy_to (&marking->key_id, &key_id);
   } else {
      CLIENT_ERR ("marking must have either key_id or key_alt_name");
      goto fail;
   }

   if (!key_found) {
      _mongocrypt_status_copy_to (kb->status, status);
      goto fail;
   }

   _mongocrypt_ciphertext_init (ciphertext);
   ciphertext->original_bson_type = (uint8_t) bson_iter_type (&marking->v_iter);
   if (marking->algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC) {
      ciphertext->blob_subtype = MC_SUBTYPE_FLE1DeterministicEncryptedValue;
   } else {
      BSON_ASSERT (marking->algorithm ==
                   MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
      ciphertext->blob_subtype = MC_SUBTYPE_FLE1RandomEncryptedValue;
   }
   _mongocrypt_buffer_copy_to (&key_id, &ciphertext->key_id);
   if (!_mongocrypt_ciphertext_serialize_associated_data (ciphertext,
                                                          &associated_data)) {
      CLIENT_ERR ("could not serialize associated data");
      goto fail;
   }

   _mongocrypt_buffer_from_iter (&plaintext, &marking->v_iter);
   ciphertext->data.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext->data.data = bson_malloc (ciphertext->data.len);
   BSON_ASSERT (ciphertext->data.data);

   ciphertext->data.owned = true;

   switch (marking->algorithm) {
   case MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC:
      /* Use deterministic encryption. */
      _mongocrypt_buffer_resize (&iv, MONGOCRYPT_IV_LEN);
      ret = _mongocrypt_calculate_deterministic_iv (kb->crypt->crypto,
                                                    &key_material,
                                                    &plaintext,
                                                    &associated_data,
                                                    &iv,
                                                    status);
      if (!ret) {
         goto fail;
      }

      ret = _mongocrypt_do_encryption (kb->crypt->crypto,
                                       &iv,
                                       &associated_data,
                                       &key_material,
                                       &plaintext,
                                       &ciphertext->data,
                                       &bytes_written,
                                       status);
      break;
   case MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM:
      /* Use randomized encryption.
       * In this case, we must generate a new, random iv. */
      _mongocrypt_buffer_resize (&iv, MONGOCRYPT_IV_LEN);
      if (!_mongocrypt_random (
             kb->crypt->crypto, &iv, MONGOCRYPT_IV_LEN, status)) {
         goto fail;
      }
      ret = _mongocrypt_do_encryption (kb->crypt->crypto,
                                       &iv,
                                       &associated_data,
                                       &key_material,
                                       &plaintext,
                                       &ciphertext->data,
                                       &bytes_written,
                                       status);
      break;
   default:
      /* Error. */
      CLIENT_ERR ("Unsupported value for encryption algorithm");
      goto fail;
   }

   if (!ret) {
      goto fail;
   }

   BSON_ASSERT (bytes_written == ciphertext->data.len);

   ret = true;

fail:
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&key_id);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&key_material);
   return ret;
}

bool
_mongocrypt_marking_to_ciphertext (void *ctx,
                                   _mongocrypt_marking_t *marking,
                                   _mongocrypt_ciphertext_t *ciphertext,
                                   mongocrypt_status_t *status)
{
   _mongocrypt_key_broker_t *kb = (_mongocrypt_key_broker_t *) ctx;
   BSON_ASSERT (marking);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);
   BSON_ASSERT (ctx);

   if (marking->type == MONGOCRYPT_MARKING_FLE2_ENCRYPTION) {
      if (marking->fle2.type == MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT) {
         return _mongocrypt_fle2_placeholder_to_insert_update_ciphertext (
            kb, marking, ciphertext, status);
      } else {
         BSON_ASSERT (marking->fle2.type ==
                      MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND);
         return _mongocrypt_fle2_placeholder_to_find_ciphertext (
            kb, marking, ciphertext, status);
      }
   } else {
      return _mongocrypt_fle1_marking_to_ciphertext (
         kb, marking, ciphertext, status);
   }
}
