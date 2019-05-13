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

#include "mongocrypt-cache-key-private.h"
/* The key cache.
 *
 * Attribute is a UUID in the form of a _mongocrypt_buffer_t.
 * Value contains a key document and decrypted key material.
 */


static int
_cmp_attr (void *a, void *b)
{
   return _mongocrypt_buffer_cmp ((_mongocrypt_buffer_t *) a,
                                  (_mongocrypt_buffer_t *) b);
}


static void *
_copy_attr (void *attr)
{
   _mongocrypt_buffer_t *dst;

   dst = bson_malloc (sizeof (*dst));
   _mongocrypt_buffer_init (dst);
   _mongocrypt_buffer_copy_to ((_mongocrypt_buffer_t *) attr, dst);
   return dst;
}


static void
_destroy_attr (void *attr)
{
   _mongocrypt_buffer_cleanup ((_mongocrypt_buffer_t *) attr);
   bson_free (attr);
}


static void *
_copy_contents (void *value)
{
   _mongocrypt_cache_key_value_t *key_value;

   key_value = (_mongocrypt_cache_key_value_t *) value;
   return _mongocrypt_cache_key_value_new (key_value->key_doc,
                                           &key_value->decrypted_key_material);
}


_mongocrypt_cache_key_value_t *
_mongocrypt_cache_key_value_new (_mongocrypt_key_doc_t *key_doc,
                                 _mongocrypt_buffer_t *decrypted_key_material)
{
   _mongocrypt_cache_key_value_t *key_value;

   BSON_ASSERT (key_doc);
   BSON_ASSERT (decrypted_key_material);

   key_value = bson_malloc0 (sizeof (*key_value));
   _mongocrypt_buffer_copy_to (decrypted_key_material,
                               &key_value->decrypted_key_material);

   key_value->key_doc = _mongocrypt_key_new ();
   _mongocrypt_key_doc_copy_to (key_doc, key_value->key_doc);

   return key_value;
}


void
_mongocrypt_cache_key_value_destroy (void *value)
{
   _mongocrypt_cache_key_value_t *key_value;

   if (!value) {
      return;
   }
   key_value = (_mongocrypt_cache_key_value_t *) value;
   _mongocrypt_key_destroy (key_value->key_doc);
   _mongocrypt_buffer_cleanup (&key_value->decrypted_key_material);
   bson_free (key_value);
}

void
_mongocrypt_cache_key_init (_mongocrypt_cache_t *cache)
{
   cache->cmp_attr = _cmp_attr;
   cache->copy_attr = _copy_attr;
   cache->destroy_attr = _destroy_attr;
   cache->copy_value = _copy_contents;
   cache->destroy_value = _mongocrypt_cache_key_value_destroy;
   _mongocrypt_mutex_init (&cache->mutex);
   cache->pair = NULL;
}
