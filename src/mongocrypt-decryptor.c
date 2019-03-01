/*
 * Copyright 2018-present MongoDB, Inc.
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

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-binary-private.h"
#include "mongocrypt-decryptor-private.h"
#include "mongocrypt-schema-cache-private.h"


mongocrypt_decryptor_t *
mongocrypt_decryptor_new (mongocrypt_t *crypt,
			  const mongocrypt_opts_t *opts)
{
   mongocrypt_decryptor_t *decryptor;

   decryptor = (mongocrypt_decryptor_t *) bson_malloc0 (sizeof *decryptor);

   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC;
   decryptor->crypt = crypt;

   return decryptor;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_add_doc (mongocrypt_decryptor_t *decryptor,
			      mongocrypt_binary_t *encrypted_doc,
			      const mongocrypt_opts_t *opts)
{
   BSON_ASSERT (decryptor);

   /* TODO determine if we can skip decryption */

   decryptor->encrypted_doc = encrypted_doc;
   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS;

   return decryptor->state;
}


const mongocrypt_binary_t *
mongocrypt_decryptor_get_key_filter (mongocrypt_decryptor_t *decryptor,
				    const mongocrypt_opts_t *opts)
{
   BSON_ASSERT (decryptor);

   /* TODO */

   return NULL;
}


void
mongocrypt_decryptor_add_key (mongocrypt_decryptor_t *decryptor,
			      const mongocrypt_opts_t *opts,
			      const mongocrypt_binary_t *key,
			      mongocrypt_status_t *status)
{
   BSON_ASSERT (decryptor);

   if (decryptor->state != MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS) {
      return;
   }

   /* TODO */

   return;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_done_adding_keys (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   /* TODO check if we have all keys, error if not */

   /* TODO check if we actually need keys decrypted */
   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS_DECRYPTED;

   return decryptor->state;
}



mongocrypt_key_decryptor_t *
mongocrypt_decryptor_next_key_decryptor (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   /* TODO */

   return NULL;
}

mongocrypt_decryptor_state_t
mongocrypt_decryptor_add_decrypted_key (mongocrypt_decryptor_t *decryptor,
					mongocrypt_key_decryptor_t *key)
{
   BSON_ASSERT (decryptor);

   if (decryptor->state != MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS_DECRYPTED) {
      return decryptor->state;
   }
   
   /* TODO: add logic to only advance the state once all
      decrypted keys have been added */

   decryptor->state = MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED;

   return decryptor->state;
}


mongocrypt_decryptor_state_t
mongocrypt_decryptor_state (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   return decryptor->state;
}


mongocrypt_status_t *
mongocrypt_decryptor_status (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   return decryptor->status;
}


mongocrypt_binary_t *
mongocrypt_decryptor_decrypted_doc (mongocrypt_decryptor_t *decryptor)
{
   BSON_ASSERT (decryptor);

   return decryptor->decrypted_doc;
}


void
mongocrypt_decryptor_destroy (mongocrypt_decryptor_t *decryptor)
{
   if (!decryptor) {
      return;
   }

   mongocrypt_binary_destroy (decryptor->encrypted_doc);

   /* TODO: ownership of this buffer? */
   mongocrypt_binary_destroy (decryptor->decrypted_doc);

   bson_free (decryptor);
}
