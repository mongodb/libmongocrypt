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
#include "mongocrypt-encryptor-private.h"
#include "mongocrypt-schema-cache-private.h"


mongocrypt_encryptor_t *
mongocrypt_encryptor_new (mongocrypt_t *crypt,
			  const mongocrypt_opts_t *opts)
{
   mongocrypt_encryptor_t *request;

   request = (mongocrypt_encryptor_t *) bson_malloc0 (sizeof *request);

   request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS;
   request->crypt = crypt;

   return request;
}

mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_ns (mongocrypt_encryptor_t *request,
			     const char *ns,
			     const mongocrypt_opts_t *opts)
{
   _mongocrypt_schema_cache_t *cache;
   _mongocrypt_schema_handle_t *handle;

   if (request->state != MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS) {
      return request->state;
   }

   request->ns = ns;

   cache = request->crypt->schema_cache;
   /* TODO reader lock while using the schema handle */
   handle = _mongocrypt_schema_cache_lookup_ns (cache, ns);

   if (handle) {
      /* If we already have a cached schema, proceed to mongocryptd
	 if we need to, otherwise done if we don't need encryption. */
      if (handle->needs_encryption) {
	 request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS;
      } else {
	 request->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
      }
   } else {
      request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA;
   }

   return request->state;
}

mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_schema(mongocrypt_encryptor_t *request,
				mongocrypt_binary_t *schema,
				const mongocrypt_opts_t *opts)
{
   BSON_ASSERT (request);
   if (!(schema && request->state == MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA)) {
      return request->state;
   }

   /* Append the schema to the request, but don't add it to the cache
      until we know whether or not it requires encryption. */

   /* Ownership: right now, encryptor takes control of schema and
      will free it later. Should we keep it this way and document,
      or make our own copy? */
   request->schema = schema;
   request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS;

   return request->state;
}

mongocrypt_binary_t *
mongocrypt_encryptor_get_schema (mongocrypt_encryptor_t *request,
				 const mongocrypt_opts_t *opts)
{
   mongocrypt_status_t *status = request->status;

   /* We can only do this at a stage where we are guaranteed to
      have what we need (the schema) */
   if (request->state != MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS) {
      CLIENT_ERR ("wrong stage for fetching schema");
      return NULL;
   }

   /* TODO */

   return request->schema;
}

mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_markings (mongocrypt_encryptor_t *request,
				   mongocrypt_binary_t *marked_reply,
				   const mongocrypt_opts_t *opts)
{
   _mongocrypt_schema_handle_t *handle;
   mongocrypt_status_t *status = request->status;
   bson_iter_t iter;
   bson_t parsed_schema;
   bson_t parsed_reply;
   bool res;

   BSON_ASSERT (request);

   // todo this is for the sake of the test, remove it
   if (!marked_reply) {
      request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS;
      goto done;
   }

   if (!(marked_reply &&
	 request->state == MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS)) {
      goto done;
   }

   mongocrypt_binary_to_bson (marked_reply, &parsed_reply);
   bson_iter_init (&iter, &parsed_reply);

   // TODO also check that the reply wasn't an error.
   if (!bson_iter_find (&iter, "ok") || !BSON_ITER_HOLDS_INT (&iter)) {
      request->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      CLIENT_ERR ("malformatted mongocryptd reply");
      goto done;
   }

   if (bson_iter_find (&iter, "schemaRequiresEncryption")) {
      if (!BSON_ITER_HOLDS_BOOL (&iter)) {
	 request->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
	 CLIENT_ERR ("malformatted schemaRequiredEncryption field");
	 goto done;
      }

      /* TODO add the schema to the schema cache */
   }

   /* If we don't need to encrypt, we're done. */
   if (!bson_iter_find (&iter, "hasEncryptedPlaceholders")) {
      request->state = MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED;
      goto done;
   }
   
   if (!BSON_ITER_HOLDS_BOOL (&iter)) {
      request->state = MONGOCRYPT_ENCRYPTOR_STATE_ERROR;
      CLIENT_ERR ("malformed hasEncryptedPlaceholders field");
      goto done;
   }

   /* TODO check if we actually need keys here. */
   request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS;
   request->marked_reply = marked_reply;

 done:
   return request->state;
}


const mongocrypt_key_query_t *
mongocrypt_encryptor_get_key_query (mongocrypt_encryptor_t *request,
				    const mongocrypt_opts_t *opts)
{
   BSON_ASSERT (request);

   /* TODO */

   return NULL;
}


void
mongocrypt_encryptor_add_key (mongocrypt_encryptor_t *request,
			      const mongocrypt_opts_t *opts,
			      mongocrypt_binary_t *key,
			      mongocrypt_status_t *status)
{
   BSON_ASSERT (request);

   if (request->state != MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS) {
      return;
   }

   /* TODO */

   return;
}


mongocrypt_encryptor_state_t
mongocrypt_encryptor_done_adding_keys (mongocrypt_encryptor_t *request)
{
   BSON_ASSERT (request);

   /* TODO check if we have all keys, error if not */

   /* TODO check if we actually need keys decrypted */
   request->state = MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS_DECRYPTED;

   return request->state;
}



mongocrypt_key_decrypt_request_t *
mongocrypt_encryptor_next_kms_request (mongocrypt_encryptor_t *request)
{
   BSON_ASSERT (request);

   /* TODO */

   return NULL;
}

mongocrypt_encryptor_state_t
mongocrypt_encryptor_add_decrypted_key (mongocrypt_encryptor_t *request,
					mongocrypt_key_decrypt_request_t *key)
{
   BSON_ASSERT (request);

   if (request->state != MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS_DECRYPTED) {
      return request->state;
   }
   
   /* TODO: add logic to only advance the state once all
      decrypted keys have been added */

   request->state = MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED;

   return request->state;
}


mongocrypt_encryptor_state_t
mongocrypt_encryptor_state (mongocrypt_encryptor_t *request)
{
   BSON_ASSERT (request);

   return request->state;
}


mongocrypt_status_t *
mongocrypt_encryptor_status (mongocrypt_encryptor_t *request)
{
   BSON_ASSERT (request);

   return request->status;
}


mongocrypt_binary_t *
mongocrypt_encryptor_encrypted_cmd (mongocrypt_encryptor_t *request)
{
   BSON_ASSERT (request);

   return request->encrypted_cmd;
}


void
mongocrypt_encryptor_destroy (mongocrypt_encryptor_t *request)
{
   if (!request) {
      return;
   }

   mongocrypt_binary_destroy (request->schema);
   mongocrypt_binary_destroy (request->marked_reply);
   mongocrypt_binary_destroy (request->encrypted_cmd);

   bson_free (request);
}
