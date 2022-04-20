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

#include <bson.h>

#include "mc-fle2-insert-update-payload-private.h"
#include "mongocrypt.h"
#include "mongocrypt-buffer-private.h"

void
mc_FLE2InsertUpdatePayload_init (mc_FLE2InsertUpdatePayload_t *payload)
{
   memset (payload, 0, sizeof (mc_FLE2InsertUpdatePayload_t));
}

void
mc_FLE2InsertUpdatePayload_cleanup (mc_FLE2InsertUpdatePayload_t *payload)
{
   _mongocrypt_buffer_cleanup (&payload->edcDerivedToken);
   _mongocrypt_buffer_cleanup (&payload->escDerivedToken);
   _mongocrypt_buffer_cleanup (&payload->eccDerivedToken);
   _mongocrypt_buffer_cleanup (&payload->encryptedTokens);
   _mongocrypt_buffer_cleanup (&payload->indexKeyId);
   _mongocrypt_buffer_cleanup (&payload->value);
   _mongocrypt_buffer_cleanup (&payload->serverEncryptionToken);
   _mongocrypt_buffer_cleanup (&payload->plaintext);
}

#define IF_FIELD(Name)                                               \
   if (0 == strcmp (field, #Name)) {                                 \
      if (has_##Name) {                                              \
         CLIENT_ERR ("Duplicate field '" #Name "' in payload bson"); \
         goto fail;                                                  \
      }                                                              \
      has_##Name = true;

#define END_IF_FIELD \
   continue;         \
   }

#define PARSE_BINDATA(Name, Type, Dest)                                    \
   IF_FIELD (Name)                                                         \
   {                                                                       \
      bson_subtype_t subtype;                                              \
      uint32_t len;                                                        \
      const uint8_t *data;                                                 \
      if (bson_iter_type (&iter) != BSON_TYPE_BINARY) {                    \
         CLIENT_ERR ("Field '" #Name "' expected to be bindata, got: %d",  \
                     bson_iter_type (&iter));                              \
         goto fail;                                                        \
      }                                                                    \
      bson_iter_binary (&iter, &subtype, &len, &data);                     \
      if (subtype != Type) {                                               \
         CLIENT_ERR ("Field '" #Name                                       \
                     "' expected to be bindata subtype %d, got: %d",       \
                     Type,                                                 \
                     subtype);                                             \
         goto fail;                                                        \
      }                                                                    \
      if (!_mongocrypt_buffer_copy_from_binary_iter (&out->Dest, &iter)) { \
         CLIENT_ERR ("Unable to create mongocrypt buffer for BSON binary " \
                     "field in '" #Name "'");                              \
         goto fail;                                                        \
      }                                                                    \
   }                                                                       \
   END_IF_FIELD

#define PARSE_BINARY(Name, Dest) PARSE_BINDATA (Name, BSON_SUBTYPE_BINARY, Dest)

#define CHECK_HAS(Name)                                    \
   if (!has_##Name) {                                      \
      CLIENT_ERR ("Missing field '" #Name "' in payload"); \
      goto fail;                                           \
   }

bool
mc_FLE2InsertUpdatePayload_parse (mc_FLE2InsertUpdatePayload_t *out,
                                  const _mongocrypt_buffer_t *in,
                                  mongocrypt_status_t *status)
{
   bson_iter_t iter;
   bool has_d = false, has_s = false, has_c = false;
   bool has_p = false, has_u = false, has_t = false;
   bool has_v = false, has_e = false;
   bson_t in_bson;

   if (in->len < 1) {
      CLIENT_ERR ("FLE2InsertUpdatePayload_parse got too short input");
      return false;
   }

   if (!bson_init_static (&in_bson, in->data + 1, in->len - 1)) {
      CLIENT_ERR ("FLE2InsertUpdatePayload_parse got invalid BSON");
      return false;
   }

   mc_FLE2InsertUpdatePayload_init (out);
   if (!bson_validate (&in_bson, BSON_VALIDATE_NONE, NULL) ||
       !bson_iter_init (&iter, &in_bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   while (bson_iter_next (&iter)) {
      const char *field = bson_iter_key (&iter);
      BSON_ASSERT (field);

      PARSE_BINARY (d, edcDerivedToken)
      PARSE_BINARY (s, escDerivedToken)
      PARSE_BINARY (c, eccDerivedToken)
      PARSE_BINARY (p, encryptedTokens)
      PARSE_BINDATA (u, BSON_SUBTYPE_UUID, indexKeyId)
      IF_FIELD (t)
      {
         int32_t type = bson_iter_int32 (&iter);
         if (!BSON_ITER_HOLDS_INT32 (&iter)) {
            CLIENT_ERR ("Field 't' expected to hold an int32");
            goto fail;
         }
         if ((type < 0) || (type > 0xFF)) {
            CLIENT_ERR ("Field 't' must be a valid BSON type, got: %d", type);
            goto fail;
         }
         out->valueType = (bson_type_t) type;
      }
      END_IF_FIELD
      PARSE_BINARY (v, value)
      PARSE_BINARY (e, serverEncryptionToken)
   }

   CHECK_HAS (d);
   CHECK_HAS (s);
   CHECK_HAS (c);
   CHECK_HAS (p);
   CHECK_HAS (u);
   CHECK_HAS (t);
   CHECK_HAS (v);
   CHECK_HAS (e);

   if (!_mongocrypt_buffer_from_subrange (&out->userKeyId, &out->value, 0, UUID_LEN)) {
      CLIENT_ERR ("failed to create userKeyId buffer");
      goto fail;
   }
   out->userKeyId.subtype = BSON_SUBTYPE_UUID;

   return true;
fail:
   mc_FLE2InsertUpdatePayload_cleanup (out);
   return false;
}

#define IUPS_APPEND_BINDATA(name, subtype, value)           \
   if (!_mongocrypt_buffer_append (                         \
          &(value), out, name, (uint32_t) strlen (name))) { \
      return false;                                         \
   }

bool
mc_FLE2InsertUpdatePayload_serialize (
   bson_t *out, const mc_FLE2InsertUpdatePayload_t *payload)
{
   IUPS_APPEND_BINDATA ("d", BSON_SUBTYPE_BINARY, payload->edcDerivedToken);
   IUPS_APPEND_BINDATA ("s", BSON_SUBTYPE_BINARY, payload->escDerivedToken);
   IUPS_APPEND_BINDATA ("c", BSON_SUBTYPE_BINARY, payload->eccDerivedToken);
   IUPS_APPEND_BINDATA ("p", BSON_SUBTYPE_BINARY, payload->encryptedTokens);
   IUPS_APPEND_BINDATA ("u", BSON_SUBTYPE_UUID, payload->indexKeyId);
   if (!BSON_APPEND_INT32 (out, "t", payload->valueType)) {
      return false;
   }
   IUPS_APPEND_BINDATA ("v", BSON_SUBTYPE_BINARY, payload->value);
   IUPS_APPEND_BINDATA (
      "e", BSON_SUBTYPE_BINARY, payload->serverEncryptionToken);
   return true;
}
#undef IUPS_APPEND_BINDATA

const _mongocrypt_buffer_t *
mc_FLE2InsertUpdatePayload_decrypt (_mongocrypt_crypto_t *crypto,
                                    mc_FLE2InsertUpdatePayload_t *iup,
                                    const _mongocrypt_buffer_t *user_key,
                                    mongocrypt_status_t *status)
{
   if (iup->value.len == 0) {
      CLIENT_ERR ("FLE2InsertUpdatePayload value not parsed");
      return NULL;
   }

   _mongocrypt_buffer_t ciphertext;
   if (!_mongocrypt_buffer_from_subrange (&ciphertext, &iup->value, UUID_LEN, iup->value.len - UUID_LEN)) {
      CLIENT_ERR ("Failed to create ciphertext buffer");
      return NULL;
   }

   _mongocrypt_buffer_resize (&iup->plaintext, _mongocrypt_fle2aead_calculate_plaintext_len (ciphertext.len));
   uint32_t bytes_written; /* ignored */

   if (!_mongocrypt_fle2aead_do_decryption (crypto, &iup->userKeyId, user_key, &ciphertext, &iup->plaintext, &bytes_written, status)) {
      return NULL;
   }
   return &iup->plaintext;
}