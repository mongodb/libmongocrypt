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

#include "mc-fle2-payload-uev-private.h"
#include "mongocrypt-private.h"

struct _mc_FLE2UnindexedEncryptedValue_t {

};

mc_FLE2UnindexedEncryptedValue_t *
mc_FLE2UnindexedEncryptedValue_new (void) {
   mc_FLE2UnindexedEncryptedValue_t *uev = bson_malloc0 (sizeof (mc_FLE2UnindexedEncryptedValue_t));
   return uev;
}

bool
mc_FLE2UnindexedEncryptedValue_parse (
   mc_FLE2UnindexedEncryptedValue_t *uev,
   const _mongocrypt_buffer_t *buf,
   mongocrypt_status_t *status) {
   CLIENT_ERR ("TODO");
   return false;
}

bson_type_t
mc_FLE2UnindexedEncryptedValue_get_original_bson_type (
   const mc_FLE2UnindexedEncryptedValue_t *uev,
   mongocrypt_status_t *status) {
   CLIENT_ERR ("TODO");
   return 0;
}

const _mongocrypt_buffer_t *
mc_FLE2UnindexedEncryptedValue_get_key_uuid (
   const mc_FLE2UnindexedEncryptedValue_t *uev,
   mongocrypt_status_t *status) {
   CLIENT_ERR ("TODO");
   return NULL;
}

bool
mc_FLE2UnindexedEncryptedValue_add_key (
   _mongocrypt_crypto_t *crypto,
   mc_FLE2UnindexedEncryptedValue_t *uev,
   const _mongocrypt_buffer_t *key,
   mongocrypt_status_t *status) {
   CLIENT_ERR ("TODO");
   return false;
}

const _mongocrypt_buffer_t *
mc_FLE2UnindexedEncryptedValue_get_plaintext (
   const mc_FLE2UnindexedEncryptedValue_t *uev,
   mongocrypt_status_t *status) {
   CLIENT_ERR ("TODO");
   return false;
}

void
mc_FLE2UnindexedEncryptedValue_destroy (
   mc_FLE2UnindexedEncryptedValue_t *uev) {
   if (NULL == uev) {
      return;
   }
   bson_free (uev);
}