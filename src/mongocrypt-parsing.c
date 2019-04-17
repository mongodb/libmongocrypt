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

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"

/* TODO: be very careful. Audit this.
 * Consider if copying is potentially worth the easier debuggability?
 * I think the marking + encrypted parse should explicitly say "unowned".
 * Parsing does not copy, but requires the BSON to be around.
 */

/* TODO: I wonder if this file really serves any purpose, or if we should split
 * this up. Address in CDRIVER-2947 */
/* out should be zeroed, TODO: instead of bson, take a buffer */
bool
_mongocrypt_marking_parse_unowned (const _mongocrypt_buffer_t *in,
                                   _mongocrypt_marking_t *out,
                                   mongocrypt_status_t *status)
{
   bson_t bson;
   bson_iter_t iter;
   bool ret = false;
   int algorithm;

   if (in->len < 5) {
      CLIENT_ERR ("invalid marking, length < 5");
      goto cleanup;
   }

   /* Confirm that this is indeed a marking */
   if (in->data[0] != 0) {
      CLIENT_ERR ("invalid marking, first byte must be 0");
      goto cleanup;
   }

   bson_init_static (&bson, in->data + 1, in->len - 1);

   if (bson_iter_init_find (&iter, &bson, "ki")) {
      if (!BSON_ITER_HOLDS_BINARY (&iter)) {
         CLIENT_ERR ("key id must be a binary type");
      }
      _mongocrypt_buffer_from_iter (&out->key_id, &iter);
      if (out->key_id.subtype != BSON_SUBTYPE_UUID) {
         CLIENT_ERR ("key id must be a UUID");
         goto cleanup;
      }
   } else if (bson_iter_init_find (&iter, &bson, "ka")) {
      out->key_alt_name = bson_iter_value (&iter);
   } else {
      CLIENT_ERR ("marking must include 'ki' or 'ka'");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, &bson, "iv")) {
      CLIENT_ERR ("'iv' not part of marking. C driver does not support "
                  "generating iv yet. (TODO)");
      goto cleanup;
   } else if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      CLIENT_ERR ("invalid marking, 'iv' is not binary");
      goto cleanup;
   }
   _mongocrypt_buffer_from_iter (&out->iv, &iter);

   if (out->iv.len != 16) {
      CLIENT_ERR ("iv must be 16 bytes");
      goto cleanup;
   }

   if (!bson_iter_init_find (&iter, &bson, "v")) {
      CLIENT_ERR ("invalid marking, no 'v'");
      goto cleanup;
   }
   memcpy (&out->v_iter, &iter, sizeof (bson_iter_t));

   if (!bson_iter_init_find (&iter, &bson, "a")) {
      CLIENT_ERR ("invalid marking, no 'a'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_INT32 (&iter)) {
      CLIENT_ERR ("invalid marking, 'a' must be an integer");
      goto cleanup;
   }

   algorithm = bson_iter_int32 (&iter);
   switch (algorithm) {
   case 0:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE;
      break;
   case 1:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC;
      break;
   case 2:
      out->algorithm = MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM;
      break;
   default:
      CLIENT_ERR ("invalid algorithm value %d", algorithm);
   }

   ret = true;
cleanup:
   return ret;
}


void
_mongocrypt_marking_init (_mongocrypt_marking_t *marking)
{
   memset (marking, 0, sizeof (*marking));
}


void
_mongocrypt_marking_cleanup (_mongocrypt_marking_t *marking)
{
   _mongocrypt_buffer_cleanup (&marking->iv);
   _mongocrypt_buffer_cleanup (&marking->key_id);
}


/* Takes ownership of all fields. */
bool
_mongocrypt_key_parse_owned (const bson_t *bson,
                             _mongocrypt_key_doc_t *out,
                             mongocrypt_status_t *status)
{
   bson_iter_t iter, subiter;
   bool ret = false;

   memset (out, 0, sizeof (_mongocrypt_key_doc_t));

   /* _id */
   if (!bson_iter_init_find (&iter, bson, "_id")) {
      CLIENT_ERR ("invalid key, no '_id'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      CLIENT_ERR ("invalid key, no 'k' is not binary");
      goto cleanup;
   }

   _mongocrypt_buffer_copy_from_iter (&out->id, &iter);
   if (out->id.subtype != BSON_SUBTYPE_UUID) {
      CLIENT_ERR ("key id must be a UUID");
      goto cleanup;
   }

   /* keyMaterial */
   if (!bson_iter_init_find (&iter, bson, "keyMaterial")) {
      CLIENT_ERR ("invalid key, no 'keyMaterial'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_BINARY (&iter)) {
      CLIENT_ERR ("invalid key material is not binary");
      goto cleanup;
   }

   _mongocrypt_buffer_copy_from_iter (&out->key_material, &iter);
   if (out->key_material.subtype != BSON_SUBTYPE_BINARY) {
      CLIENT_ERR ("key material must be a binary");
      goto cleanup;
   }

   /* masterKey */
   if (!bson_iter_init_find (&iter, bson, "masterKey")) {
      CLIENT_ERR ("invalid key, no 'masterKey'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
      CLIENT_ERR ("invalid 'masterKey', expected document");
      goto cleanup;
   }

   if (!bson_iter_recurse (&iter, &subiter)) {
      CLIENT_ERR ("invalid 'masterKey', malformed BSON");
      goto cleanup;
   }

   if (!bson_iter_find (&subiter, "provider")) {
      CLIENT_ERR ("invalid 'masterKey', expected 'provider'");
      goto cleanup;
   }

   if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
      CLIENT_ERR ("invalid 'masterKey.provider', expected string");
      goto cleanup;
   }

   if (0 == strcmp (bson_iter_utf8 (&subiter, NULL), "aws")) {
      out->masterkey_provider = MONGOCRYPT_KMS_PROVIDER_AWS;
   } else if (0 == strcmp (bson_iter_utf8 (&subiter, NULL), "local")) {
      out->masterkey_provider = MONGOCRYPT_KMS_PROVIDER_LOCAL;
   } else {
      CLIENT_ERR ("invalid 'masterKey.provider', expected 'aws' or 'local'");
      goto cleanup;
   }

   if (!bson_iter_recurse (&iter, &subiter)) {
      CLIENT_ERR ("invalid 'masterKey', malformed BSON");
      goto cleanup;
   }
   if (bson_iter_find (&subiter, "region")) {
      if (!BSON_ITER_HOLDS_UTF8 (&subiter)) {
         CLIENT_ERR ("invalid 'masterKey.region', expected string");
         goto cleanup;
      }
      out->masterkey_region = bson_strdup (bson_iter_utf8 (&subiter, NULL));
   }


   ret = true;
cleanup:
   return ret;
}

void
_mongocrypt_key_cleanup (_mongocrypt_key_doc_t *key)
{
   _mongocrypt_buffer_cleanup (&key->id);
   _mongocrypt_buffer_cleanup (&key->key_material);
   bson_free (key->masterkey_region);
}

typedef struct {
   void *ctx;
   bson_iter_t iter;
   bson_t *copy; /* implies transform */
   char *path;   /* only enabled during tracing. */
   _mongocrypt_traverse_callback_t traverse_cb;
   _mongocrypt_transform_callback_t transform_cb;
   mongocrypt_status_t *status;
   traversal_match_t match;
   bson_t child;
} _recurse_state_t;

static bool
_check_first_byte (uint8_t byte, traversal_match_t match)
{
#define FIRST_BYTE_MARKING 0
#define FIRST_BYTE_DETERMINISTIC 1
#define FIRST_BYTE_RANDOMIZED 2

   switch (match) {
   case TRAVERSE_MATCH_MARKING:
      return byte == FIRST_BYTE_MARKING;
   case TRAVERSE_MATCH_CIPHERTEXT:
      return byte == FIRST_BYTE_DETERMINISTIC || byte == FIRST_BYTE_RANDOMIZED;
   }
   return false;
}

static bool
_recurse (_recurse_state_t *state)
{
   mongocrypt_status_t *status;

   status = state->status;
   while (bson_iter_next (&state->iter)) {
      if (BSON_ITER_HOLDS_BINARY (&state->iter)) {
         _mongocrypt_buffer_t value;

         _mongocrypt_buffer_from_iter (&value, &state->iter);

         if (value.subtype == 6 && value.len > 0 &&
             _check_first_byte (value.data[0], state->match)) {
            bool ret;
            /* call the right callback. */
            if (state->copy) {
               bson_value_t value_out;
               ret =
                  state->transform_cb (state->ctx, &value, &value_out, status);
               bson_append_value (state->copy,
                                  bson_iter_key (&state->iter),
                                  bson_iter_key_len (&state->iter),
                                  &value_out);
               bson_value_destroy (&value_out);
            } else {
               ret = state->traverse_cb (state->ctx, &value, status);
            }

            if (!ret) {
               return false;
            }
         }
      } else if (BSON_ITER_HOLDS_ARRAY (&state->iter)) {
         _recurse_state_t child_state;
         bool ret;

         memcpy (&child_state, state, sizeof (_recurse_state_t));
         bson_iter_recurse (&state->iter, &child_state.iter);

         if (state->copy) {
            bson_append_array_begin (state->copy,
                                     bson_iter_key (&state->iter),
                                     bson_iter_key_len (&state->iter),
                                     &state->child);
            child_state.copy = &state->child;
         }
         ret = _recurse (&child_state);

         if (state->copy) {
            bson_append_array_end (state->copy, &state->child);
         }
         if (!ret) {
            return false;
         }
      } else if (BSON_ITER_HOLDS_DOCUMENT (&state->iter)) {
         _recurse_state_t child_state;
         bool ret;

         memcpy (&child_state, state, sizeof (_recurse_state_t));
         if (!bson_iter_recurse (&state->iter, &child_state.iter)) {
            CLIENT_ERR ("error recursing into array");
            return false;
         }
         /* TODO: check for errors everywhere. */
         if (state->copy) {
            bson_append_document_begin (state->copy,
                                        bson_iter_key (&state->iter),
                                        bson_iter_key_len (&state->iter),
                                        &state->child);
            child_state.copy = &state->child;
         }

         ret = _recurse (&child_state);

         if (state->copy) {
            bson_append_document_end (state->copy, &state->child);
         }

         if (!ret) {
            return false;
         }
      } else {
         if (state->copy) {
            bson_append_value (state->copy,
                               bson_iter_key (&state->iter),
                               bson_iter_key_len (&state->iter),
                               bson_iter_value (&state->iter));
         }
      }
   }
   return true;
}

bool
_mongocrypt_transform_binary_in_bson (_mongocrypt_transform_callback_t cb,
                                      void *ctx,
                                      traversal_match_t match,
                                      bson_iter_t *iter,
                                      bson_t *out,
                                      mongocrypt_status_t *status)
{
   _recurse_state_t starting_state = {ctx,
                                      *iter,
                                      out /* copy */,
                                      NULL /* path */,
                                      NULL /* traverse callback */,
                                      cb,
                                      status,
                                      match,
                                      0};

   return _recurse (&starting_state);
}


/*-----------------------------------------------------------------------------
 *
 * _mongocrypt_traverse_binary_in_bson
 *
 *    Traverse the BSON being iterated with iter, and call cb for every binary
 *    subtype 06 value where the first byte corresponds to 'match'.
 *
 * Return:
 *    True on success. Returns false on failure and sets error.
 *
 *-----------------------------------------------------------------------------
 */
bool
_mongocrypt_traverse_binary_in_bson (_mongocrypt_traverse_callback_t cb,
                                     void *ctx,
                                     traversal_match_t match,
                                     bson_iter_t *iter,
                                     mongocrypt_status_t *status)
{
   _recurse_state_t starting_state = {ctx,
                                      *iter,
                                      NULL /* copy */,
                                      NULL /* path */,
                                      cb,
                                      NULL /* transform callback */,
                                      status,
                                      match,
                                      0};

   return _recurse (&starting_state);
}
