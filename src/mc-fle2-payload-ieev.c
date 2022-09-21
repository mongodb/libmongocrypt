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

#include "mongocrypt-private.h"

#include "mc-fle2-payload-ieev-private.h"
#include "mc-tokens-private.h"

struct _mc_FLE2IndexedEqualityEncryptedValue_t {
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t InnerEncrypted;
   _mongocrypt_buffer_t Inner;
   _mongocrypt_buffer_t K_KeyId;
   _mongocrypt_buffer_t ClientValue;
   _mongocrypt_buffer_t ClientEncryptedValue;
   uint8_t original_bson_type;
   bool parsed;
   bool inner_decrypted;
   bool client_value_decrypted;
};

mc_FLE2IndexedEqualityEncryptedValue_t *
mc_FLE2IndexedEqualityEncryptedValue_new (void)
{
   return bson_malloc0 (sizeof (mc_FLE2IndexedEqualityEncryptedValue_t));
}

bool
mc_FLE2IndexedEqualityEncryptedValue_parse (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   const _mongocrypt_buffer_t *buf,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (ieev);
   BSON_ASSERT_PARAM (buf);

   if (ieev->parsed) {
      CLIENT_ERR (
         "mc_FLE2IndexedEqualityEncryptedValue_parse must not be called twice");
      return false;
   }

   uint32_t offset = 0;
   /* Read fle_blob_subtype. */
   if (offset + 1 > buf->len) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse expected byte "
                  "length >= %" PRIu32 " got: %" PRIu32,
                  offset + 1,
                  buf->len);
      return false;
   }
   uint8_t fle_blob_subtype = buf->data[offset];
   if (fle_blob_subtype != 7) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse expected "
                  "fle_blob_subtype=7 got: %" PRIu8,
                  fle_blob_subtype);
      return false;
   }
   offset += 1;

   /* Read S_KeyId. */
   if (offset + 16 > buf->len) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse expected byte "
                  "length >= %" PRIu32 " got: %" PRIu32,
                  offset + 16,
                  buf->len);
      return false;
   }
   if (!_mongocrypt_buffer_copy_from_data_and_size (
          &ieev->S_KeyId, buf->data + offset, 16)) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse failed to copy "
                  "data for S_KeyId");
      return false;
   }
   ieev->S_KeyId.subtype = BSON_SUBTYPE_UUID;
   offset += 16;

   /* Read original_bson_type. */
   if (offset + 1 > buf->len) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse expected byte "
                  "length >= %" PRIu32 " got: %" PRIu32,
                  offset + 1,
                  buf->len);
      return false;
   }
   ieev->original_bson_type = buf->data[offset];
   offset += 1;

   /* Read InnerEncrypted. */
   if (!_mongocrypt_buffer_copy_from_data_and_size (
          &ieev->InnerEncrypted,
          buf->data + offset,
          (size_t) (buf->len - offset))) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse failed to copy "
                  "data for InnerEncrypted");
      return false;
   }

   ieev->parsed = true;
   return true;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (ieev);

   if (!ieev->parsed) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId must be "
                  "called after mc_FLE2IndexedEqualityEncryptedValue_parse");
      return NULL;
   }

   return &ieev->S_KeyId;
}

bool
mc_FLE2IndexedEqualityEncryptedValue_add_S_Key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   const _mongocrypt_buffer_t *S_Key,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (crypto);
   BSON_ASSERT_PARAM (ieev);
   BSON_ASSERT_PARAM (S_Key);

   if (!ieev->parsed) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key must be "
                  "called after mc_FLE2IndexedEqualityEncryptedValue_parse");
      return false;
   }

   if (ieev->inner_decrypted) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key must not be "
                  "called twice");
      return false;
   }

   /* Attempt to decrypt InnerEncrypted */
   if (S_Key->len != MONGOCRYPT_KEY_LEN) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key expected "
                  "S_Key to be %d bytes, got: %" PRIu32,
                  MONGOCRYPT_KEY_LEN,
                  S_Key->len);
      return false;
   }

   /* Get the TokenKey from the last 32 bytes of S_Key */
   _mongocrypt_buffer_t TokenKey;
   if (!_mongocrypt_buffer_from_subrange (&TokenKey,
                                          S_Key,
                                          S_Key->len - MONGOCRYPT_TOKEN_KEY_LEN,
                                          MONGOCRYPT_TOKEN_KEY_LEN)) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key unable to "
                  "parse TokenKey from S_Key");
      return false;
   }

   /* Use TokenKey to create ServerDataEncryptionLevel1Token and decrypt
    * InnerEncrypted. */
   {
      mc_ServerDataEncryptionLevel1Token_t *token =
         mc_ServerDataEncryptionLevel1Token_new (crypto, &TokenKey, status);
      if (!token) {
         return false;
      }

      const _mongocrypt_buffer_t *token_buf =
         mc_ServerDataEncryptionLevel1Token_get (token);
      uint32_t bytes_written;

      _mongocrypt_buffer_resize (
         &ieev->Inner,
         _mongocrypt_fle2_calculate_plaintext_len (ieev->InnerEncrypted.len));

      /* Decrypt InnerEncrypted. */
      if (!_mongocrypt_fle2_do_decryption (crypto,
                                           token_buf,
                                           &ieev->InnerEncrypted,
                                           &ieev->Inner,
                                           &bytes_written,
                                           status)) {
         mc_ServerDataEncryptionLevel1Token_destroy (token);
         return false;
      }
      mc_ServerDataEncryptionLevel1Token_destroy (token);
   }

   /* Parse Inner for K_KeyId. */
   uint32_t offset = 0;
   /* Read uint64_t length. */
   if (offset + 8 > ieev->Inner.len) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key expected "
                  "Inner byte length >= %" PRIu32 " got: %" PRIu32,
                  offset + 8,
                  ieev->Inner.len);
      return false;
   }
   uint64_t
      length; /* length is sizeof(K_KeyId) + ClientEncryptedValue_length. */
   memcpy (&length, ieev->Inner.data, sizeof (uint64_t));
   length = BSON_UINT64_FROM_LE (length);
   offset += 8;

   /* Read K_KeyId. */
   if (offset + UUID_LEN > ieev->Inner.len) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key expected "
                  "Inner byte length >= %" PRIu32 " got: %" PRIu32,
                  offset + UUID_LEN,
                  ieev->Inner.len);
      return false;
   }
   if (!_mongocrypt_buffer_copy_from_data_and_size (
          &ieev->K_KeyId, ieev->Inner.data + offset, 16)) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key failed to "
                  "copy data for K_KeyId");
      return false;
   }
   offset += 16;
   ieev->K_KeyId.subtype = BSON_SUBTYPE_UUID;

   /* Read ClientEncryptedValue. */
   if (offset + (length - 16) > ieev->Inner.len) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_S_Key expected "
                  "Inner byte length >= %" PRIu32 " got: %" PRIu32,
                  offset + (length - 16),
                  ieev->Inner.len);
      return false;
   }
   if (!_mongocrypt_buffer_copy_from_data_and_size (&ieev->ClientEncryptedValue,
                                                    ieev->Inner.data + offset,
                                                    (size_t) (length - 16))) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_parse failed to copy "
                  "data for ClientEncryptedValue");
      return false;
   }

   ieev->inner_decrypted = true;
   return true;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_K_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (ieev);

   if (!ieev->inner_decrypted) {
      CLIENT_ERR (
         "mc_FLE2IndexedEqualityEncryptedValue_get_K_KeyId must be called "
         "after mc_FLE2IndexedEqualityEncryptedValue_add_S_Key");
      return NULL;
   }
   return &ieev->K_KeyId;
}

bool
mc_FLE2IndexedEqualityEncryptedValue_add_K_Key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   const _mongocrypt_buffer_t *K_Key,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (crypto);
   BSON_ASSERT_PARAM (ieev);
   BSON_ASSERT_PARAM (K_Key);

   if (!ieev->inner_decrypted) {
      CLIENT_ERR (
         "mc_FLE2IndexedEqualityEncryptedValue_add_K_Key must be called after "
         "mc_FLE2IndexedEqualityEncryptedValue_add_S_Key");
      return false;
   }
   if (ieev->client_value_decrypted) {
      CLIENT_ERR ("mc_FLE2IndexedEqualityEncryptedValue_add_K_Key must not be "
                  "called twice");
      return false;
   }
   /* Attempt to decrypt ClientEncryptedValue */
   _mongocrypt_buffer_resize (&ieev->ClientValue,
                              _mongocrypt_fle2aead_calculate_plaintext_len (
                                 ieev->ClientEncryptedValue.len));
   uint32_t bytes_written;
   if (!_mongocrypt_fle2aead_do_decryption (crypto,
                                            &ieev->K_KeyId,
                                            K_Key,
                                            &ieev->ClientEncryptedValue,
                                            &ieev->ClientValue,
                                            &bytes_written,
                                            status)) {
      return false;
   }
   ieev->client_value_decrypted = true;
   return true;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_ClientValue (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (ieev);

   if (!ieev->client_value_decrypted) {
      CLIENT_ERR (
         "mc_FLE2IndexedEqualityEncryptedValue_getClientValue must be called "
         "after mc_FLE2IndexedEqualityEncryptedValue_add_K_Key");
      return NULL;
   }
   return &ieev->ClientValue;
}

void
mc_FLE2IndexedEqualityEncryptedValue_destroy (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev)
{
   if (!ieev) {
      return;
   }
   _mongocrypt_buffer_cleanup (&ieev->S_KeyId);
   _mongocrypt_buffer_cleanup (&ieev->InnerEncrypted);
   _mongocrypt_buffer_cleanup (&ieev->Inner);
   _mongocrypt_buffer_cleanup (&ieev->K_KeyId);
   _mongocrypt_buffer_cleanup (&ieev->ClientValue);
   _mongocrypt_buffer_cleanup (&ieev->ClientEncryptedValue);
   bson_free (ieev);
}

bson_type_t
mc_FLE2IndexedEqualityEncryptedValue_get_original_bson_type (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (ieev);

   if (!ieev->parsed) {
      CLIENT_ERR (
         "mc_FLE2IndexedEqualityEncryptedValue_get_original_bson_type must be "
         "called after mc_FLE2IndexedEqualityEncryptedValue_parse");
      return 0;
   }
   return ieev->original_bson_type;
}
