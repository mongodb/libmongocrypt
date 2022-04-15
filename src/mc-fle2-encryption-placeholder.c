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

#include "mc-fle2-encryption-placeholder-private.h"
#include "mongocrypt.h"
#include "mongocrypt-buffer-private.h"

// Common logic for testing field name, tracking duplication, and presence.
#define IF_FIELD(Name)                                                   \
   if (0 == strcmp (field, #Name)) {                                     \
      if (has_##Name) {                                                  \
         CLIENT_ERR ("Duplicate field '" #Name "' in placeholder bson"); \
         goto fail;                                                      \
      }                                                                  \
      has_##Name = true;

#define END_IF_FIELD \
   continue;         \
   }

#define CHECK_HAS(Name)                                        \
   if (!has_##Name) {                                          \
      CLIENT_ERR ("Missing field '" #Name "' in placeholder"); \
      goto fail;                                               \
   }

void
mc_FLE2EncryptionPlaceholder_init (mc_FLE2EncryptionPlaceholder_t *placeholder)
{
   memset (placeholder, 0, sizeof (mc_FLE2EncryptionPlaceholder_t));
}

bool
mc_FLE2EncryptionPlaceholder_parse (mc_FLE2EncryptionPlaceholder_t *out,
                                    const bson_t *in,
                                    mongocrypt_status_t *status)
{
   bson_iter_t iter;
   bool has_t = false, has_a = false, has_v = false, has_cm = false;
   bool has_ki = false, has_ku = false;

   mc_FLE2EncryptionPlaceholder_init (out);
   if (!bson_validate (in, BSON_VALIDATE_NONE, NULL) ||
       !bson_iter_init (&iter, in)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   while (bson_iter_next (&iter)) {
      const char *field = bson_iter_key (&iter);
      BSON_ASSERT (field);

      IF_FIELD (t)
      {
         int32_t type;
         if (!BSON_ITER_HOLDS_INT32 (&iter)) {
            CLIENT_ERR ("invalid marking, 't' must be an int32");
            goto fail;
         }
         type = bson_iter_int32 (&iter);
         if ((type != MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_INSERT) &&
             (type != MONGOCRYPT_FLE2_PLACEHOLDER_TYPE_FIND)) {
            CLIENT_ERR ("invalid placeholder type value: %d", type);
            goto fail;
         }
         out->type = (mongocrypt_fle2_placeholder_type_t) type;
      }
      END_IF_FIELD

      IF_FIELD (a)
      {
         int32_t algorithm;
         if (!BSON_ITER_HOLDS_INT32 (&iter)) {
            CLIENT_ERR ("invalid marking, 'a' must be an int32");
            goto fail;
         }
         algorithm = bson_iter_int32 (&iter);
         if (algorithm != MONGOCRYPT_FLE2_ALGORITHM_UNINDEXED &&
             algorithm != MONGOCRYPT_FLE2_ALGORITHM_EQUALITY) {
            CLIENT_ERR ("invalid algorithm value: %d", algorithm);
            goto fail;
         }
         out->algorithm = (mongocrypt_fle2_encryption_algorithm_t) algorithm;
      }
      END_IF_FIELD

      IF_FIELD (ki)
      {
         if (!_mongocrypt_buffer_from_uuid_iter (&out->index_key_id, &iter)) {
            CLIENT_ERR ("index key id must be a UUID");
            goto fail;
         }
      }
      END_IF_FIELD

      IF_FIELD (ku)
      {
         if (!_mongocrypt_buffer_from_uuid_iter (&out->user_key_id, &iter)) {
            CLIENT_ERR ("user key id must be a UUID");
            goto fail;
         }
      }
      END_IF_FIELD

      IF_FIELD (v)
      {
         memcpy (&out->v_iter, &iter, sizeof (bson_iter_t));
      }
      END_IF_FIELD

      IF_FIELD (cm)
      {
         if (!BSON_ITER_HOLDS_INT64 (&iter)) {
            CLIENT_ERR ("invalid maeking, 'cm' must be an int64");
            goto fail;
         }
         out->maxContentionCounter = bson_iter_int64 (&iter);
      }
      END_IF_FIELD
   }

   CHECK_HAS (t)
   CHECK_HAS (a)
   CHECK_HAS (ki)
   CHECK_HAS (ku)
   CHECK_HAS (v)
   CHECK_HAS (cm)

   return true;

fail:
   mc_FLE2EncryptionPlaceholder_cleanup (out);
   return false;
}

void
mc_FLE2EncryptionPlaceholder_cleanup (
   mc_FLE2EncryptionPlaceholder_t *placeholder)
{
   _mongocrypt_buffer_cleanup (&placeholder->index_key_id);
   _mongocrypt_buffer_cleanup (&placeholder->user_key_id);
   mc_FLE2EncryptionPlaceholder_init (placeholder);
}
