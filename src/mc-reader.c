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

#include "mc-reader-private.h"

#define CHECK_AND_RETURN(x) \
   if (!(x)) {              \
      return false;         \
   }

#define CHECK_REMAINING_BUFFER_AND_RET(read_size)        \
   if ((reader->pos + (read_size)) > reader->len) {      \
      CLIENT_ERR ("%s expected byte "                    \
                  "length >= %" PRIu32 " got: %" PRIu32, \
                  reader->parser_name,                   \
                  reader->pos + (read_size),             \
                  reader->len);                          \
      return false;                                      \
   }

void
mc_reader_init (mc_reader_t *reader,
                const uint8_t *ptr,
                uint32_t len,
                const char *parser_name)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (ptr);
   BSON_ASSERT_PARAM (parser_name);

   reader->pos = 0;
   reader->ptr = ptr;
   reader->len = len;
   reader->parser_name = parser_name;
}

void
mc_reader_init_from_buffer (mc_reader_t *reader,
                            const _mongocrypt_buffer_t *buf,
                            const char *parser_name)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (buf);
   BSON_ASSERT_PARAM (parser_name);

   mc_reader_init (reader, buf->data, buf->len, parser_name);
}

mc_reader_t *
mc_reader_new (const uint8_t *ptr, uint32_t len, const char *parser_name)
{
   BSON_ASSERT_PARAM (ptr);
   BSON_ASSERT_PARAM (parser_name);

   mc_reader_t *reader = bson_malloc (sizeof (mc_reader_t));
   mc_reader_init (reader, ptr, len, parser_name);
   return reader;
}

void
mc_reader_destroy (mc_reader_t *reader)
{
   free (reader);
}

bool
mc_reader_has_data (mc_reader_t *reader)
{
   BSON_ASSERT_PARAM (reader);

   return reader->pos < reader->len;
}

uint32_t
mc_reader_get_remaining_length (mc_reader_t *reader)
{
   BSON_ASSERT_PARAM (reader);

   return reader->len - reader->pos;
}

uint32_t
mc_reader_get_consumed_length (mc_reader_t *reader)
{
   BSON_ASSERT_PARAM (reader);

   return reader->pos;
}

bool
mc_reader_read_u8 (mc_reader_t *reader,
                   uint8_t *value,
                   mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (value);
   BSON_ASSERT_PARAM (status);

   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint8_t));

   *value = *(reader->ptr + reader->pos);
   reader->pos += sizeof (uint8_t);

   return true;
}

bool
mc_reader_read_u32 (mc_reader_t *reader,
                    uint32_t *value,
                    mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (value);
   BSON_ASSERT_PARAM (status);

   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint32_t));

   uint32_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint32_t));
   *value = BSON_UINT32_FROM_LE (temp);
   reader->pos += sizeof (uint32_t);

   return true;
}

bool
mc_reader_read_u64 (mc_reader_t *reader,
                    uint64_t *value,
                    mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (value);
   BSON_ASSERT_PARAM (status);

   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint64_t));

   uint64_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint64_t));
   *value = BSON_UINT64_FROM_LE (temp);
   reader->pos += sizeof (uint64_t);

   return true;
}

bool
mc_reader_read_bytes (mc_reader_t *reader,
                      const uint8_t **ptr,
                      uint32_t length,
                      mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (ptr);
   BSON_ASSERT_PARAM (status);

   CHECK_REMAINING_BUFFER_AND_RET (length);

   *ptr = reader->ptr + reader->pos;
   reader->pos += length;

   return true;
}

bool
mc_reader_read_buffer (mc_reader_t *reader,
                       _mongocrypt_buffer_t *buf,
                       uint32_t length,
                       mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (buf);
   BSON_ASSERT_PARAM (status);


   const uint8_t *ptr;
   CHECK_AND_RETURN (mc_reader_read_bytes (reader, &ptr, length, status));

   if (!_mongocrypt_buffer_copy_from_data_and_size (buf, ptr, length)) {
      CLIENT_ERR ("%s failed to copy "
                  "data of length %" PRIu32,
                  reader->parser_name);
      return false;
   }

   return true;
}


bool
mc_reader_read_uuid_buffer (mc_reader_t *reader,
                            _mongocrypt_buffer_t *buf,
                            mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (buf);
   BSON_ASSERT_PARAM (status);

   CHECK_AND_RETURN (mc_reader_read_buffer (reader, buf, 16, status));
   buf->subtype = BSON_SUBTYPE_UUID;

   return true;
}

bool
mc_reader_read_buffer_to_end (mc_reader_t *reader,
                              _mongocrypt_buffer_t *buf,
                              mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (reader);
   BSON_ASSERT_PARAM (buf);
   BSON_ASSERT_PARAM (status);

   const uint8_t *ptr;
   uint32_t length = reader->len - reader->pos;
   CHECK_AND_RETURN (mc_reader_read_bytes (reader, &ptr, length, status));

   if (!_mongocrypt_buffer_copy_from_data_and_size (buf, ptr, length)) {
      CLIENT_ERR ("%s failed to copy "
                  "data of length %" PRIu32,
                  reader->parser_name);
      return false;
   }

   return true;
}