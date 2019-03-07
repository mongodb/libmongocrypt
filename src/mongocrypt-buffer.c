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

/* TODO: actually make this code consistent. */
void
_mongocrypt_owned_buffer_from_iter (bson_iter_t *iter,
                                    _mongocrypt_buffer_t *out)
{
   bson_iter_binary (
      iter, &out->subtype, &out->len, (const uint8_t **) &out->data);
   out->owned = false;
}


/* copies */
void
_mongocrypt_unowned_buffer_from_iter (bson_iter_t *iter,
                                      _mongocrypt_buffer_t *out)
{
   const uint8_t *data;
   bson_iter_binary (iter, &out->subtype, &out->len, &data);
   out->data = bson_malloc (out->len);
   memcpy (out->data, data, out->len);
   out->owned = true;
}


void
_mongocrypt_unowned_buffer_from_binary (const mongocrypt_binary_t *binary,
                                        _mongocrypt_buffer_t *out)
{
   out->data = binary->data;
   out->len = binary->len;
   out->owned = false;
   out->subtype = 0;
}


void
_mongocrypt_buffer_cleanup (_mongocrypt_buffer_t *buffer)
{
   if (buffer->owned) {
      bson_free (buffer->data);
   }
}


void
_mongocrypt_bson_append_buffer (bson_t *bson,
                                const char *key,
                                uint32_t key_len,
                                _mongocrypt_buffer_t *in)
{
   bson_append_binary (bson, key, key_len, in->subtype, in->data, in->len);
}


void
_mongocrypt_buffer_copy_to (const _mongocrypt_buffer_t *src,
                            _mongocrypt_buffer_t *dst)
{
   if (src == dst) {
      return;
   }
   BSON_ASSERT (src);
   BSON_ASSERT (dst);
   dst->data = bson_malloc ((size_t) src->len);
   memcpy (dst->data, src->data, src->len);
   dst->len = src->len;
   dst->subtype = src->subtype;
   dst->owned = true;
}


void
_mongocrypt_buffer_to_unowned_bson (const _mongocrypt_buffer_t *buf,
                                    bson_t *bson)
{
   bson_init_static (bson, buf->data, buf->len);
}


int
_mongocrypt_buffer_cmp (const _mongocrypt_buffer_t *a,
                        const _mongocrypt_buffer_t *b)
{
   if (a->len != b->len) {
      return a->len - b->len;
   }
   return memcmp (a->data, b->data, a->len);
}