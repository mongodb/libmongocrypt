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
#include "mongocrypt-binary-private.h"
#include "mongocrypt-buffer-private.h"

void
_mongocrypt_buffer_init (_mongocrypt_buffer_t *buf)
{
   memset (buf, 0, sizeof (*buf));
}

void
_mongocrypt_buffer_copy_from_iter (_mongocrypt_buffer_t *buf, bson_iter_t *iter)
{
   const uint8_t *tmp;

   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (iter));
   _mongocrypt_buffer_init (buf);
   bson_iter_binary (iter, &buf->subtype, &buf->len, &tmp);
   buf->data = bson_malloc (buf->len);
   memcpy (buf->data, tmp, buf->len);
   buf->owned = true;
}


void
_mongocrypt_buffer_from_iter (_mongocrypt_buffer_t *buf, bson_iter_t *iter)
{
   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (iter));
   _mongocrypt_buffer_init (buf);
   bson_iter_binary (
      iter, &buf->subtype, &buf->len, (const uint8_t **) &buf->data);
   buf->owned = false;
}


void
_mongocrypt_buffer_from_document_iter (_mongocrypt_buffer_t *buf,
                                       bson_iter_t *iter)
{
   BSON_ASSERT (BSON_ITER_HOLDS_DOCUMENT (iter));
   _mongocrypt_buffer_init (buf);
   bson_iter_document (iter, &buf->len, (const uint8_t **) &buf->data);
   buf->owned = false;
}


void
_mongocrypt_buffer_copy_from_document_iter (_mongocrypt_buffer_t *buf,
                                            bson_iter_t *iter)
{
   const uint8_t *tmp;

   BSON_ASSERT (BSON_ITER_HOLDS_DOCUMENT (iter));
   _mongocrypt_buffer_init (buf);
   bson_iter_document (iter, &buf->len, &tmp);
   buf->data = bson_malloc (buf->len);
   memcpy (buf->data, tmp, buf->len);
   buf->owned = true;
}


void
_mongocrypt_buffer_steal_from_bson (_mongocrypt_buffer_t *buf, bson_t *bson)
{
   _mongocrypt_buffer_init (buf);
   buf->data = bson_destroy_with_steal (bson, true, &buf->len);
   buf->owned = true;
}


void
_mongocrypt_buffer_from_bson (_mongocrypt_buffer_t *buf, const bson_t *bson)
{
   _mongocrypt_buffer_init (buf);
   buf->data = (uint8_t *) bson_get_data (bson);
   buf->len = bson->len;
   buf->owned = false;
}


void
_mongocrypt_buffer_to_bson (const _mongocrypt_buffer_t *buf, bson_t *bson)
{
   bson_init_static (bson, buf->data, buf->len);
}


void
_mongocrypt_buffer_append (const _mongocrypt_buffer_t *buf,
                           bson_t *bson,
                           const char *key,
                           uint32_t key_len)
{
   bson_append_binary (bson, key, key_len, buf->subtype, buf->data, buf->len);
}


void
_mongocrypt_buffer_from_binary (_mongocrypt_buffer_t *buf,
                                const mongocrypt_binary_t *binary)
{
   _mongocrypt_buffer_init (buf);
   buf->data = binary->data;
   buf->len = binary->len;
   buf->owned = false;
}


void
_mongocrypt_buffer_copy_from_binary (_mongocrypt_buffer_t *buf,
                                     const struct _mongocrypt_binary_t *binary)
{
   _mongocrypt_buffer_init (buf);
   buf->data = bson_malloc (binary->len);
   buf->len = binary->len;
   memcpy (buf->data, binary->data, buf->len);
   buf->owned = true;
}


void
_mongocrypt_buffer_to_binary (_mongocrypt_buffer_t *buf, mongocrypt_binary_t* binary)
{
   binary->data = buf->data;
   binary->len = buf->len;
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


int
_mongocrypt_buffer_cmp (const _mongocrypt_buffer_t *a,
                        const _mongocrypt_buffer_t *b)
{
   if (a->len != b->len) {
      return a->len - b->len;
   }
   return memcmp (a->data, b->data, a->len);
}


void
_mongocrypt_buffer_cleanup (_mongocrypt_buffer_t *buf)
{
   if (buf->owned) {
      bson_free (buf->data);
   }
}


bool
_mongocrypt_buffer_empty (_mongocrypt_buffer_t *buf)
{
   return buf->data == NULL;
}