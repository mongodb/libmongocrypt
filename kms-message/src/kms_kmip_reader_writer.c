/*
 * Copyright 2021-present MongoDB, Inc.
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

#include "kms_kmip_reader_writer_private.h"

#include "kms_message/kms_b64.h"
#include "kms_message_private.h"
#include "kms_request_opt_private.h"
#include "kms_request_str.h"
#include <stdint.h>

#define BSON_BIG_ENDIAN 4321
#define BSON_LITTLE_ENDIAN 1234

#if defined(__sun)
#define BSON_UINT16_SWAP_LE_BE(v) BSWAP_16 ((uint16_t) v)
#define BSON_UINT32_SWAP_LE_BE(v) BSWAP_32 ((uint32_t) v)
#define BSON_UINT64_SWAP_LE_BE(v) BSWAP_64 ((uint64_t) v)
#elif defined(__clang__) && defined(__clang_major__) &&  \
   defined(__clang_minor__) && (__clang_major__ >= 3) && \
   (__clang_minor__ >= 1)
#if __has_builtin(__builtin_bswap16)
#define BSON_UINT16_SWAP_LE_BE(v) __builtin_bswap16 (v)
#endif
#if __has_builtin(__builtin_bswap32)
#define BSON_UINT32_SWAP_LE_BE(v) __builtin_bswap32 (v)
#endif
#if __has_builtin(__builtin_bswap64)
#define BSON_UINT64_SWAP_LE_BE(v) __builtin_bswap64 (v)
#endif
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#if __GNUC__ > 4 || (defined(__GNUC_MINOR__) && __GNUC_MINOR__ >= 3)
#define BSON_UINT32_SWAP_LE_BE(v) __builtin_bswap32 ((uint32_t) v)
#define BSON_UINT64_SWAP_LE_BE(v) __builtin_bswap64 ((uint64_t) v)
#endif
#if __GNUC__ > 4 || (defined(__GNUC_MINOR__) && __GNUC_MINOR__ >= 8)
#define BSON_UINT16_SWAP_LE_BE(v) __builtin_bswap16 ((uint32_t) v)
#endif
#endif

// KMIPTODO
#if 1 // BSON_BYTE_ORDER == BSON_LITTLE_ENDIAN
#define BSON_UINT16_FROM_LE(v) ((uint16_t) v)
#define BSON_UINT16_TO_LE(v) ((uint16_t) v)
#define BSON_UINT16_FROM_BE(v) BSON_UINT16_SWAP_LE_BE (v)
#define BSON_UINT16_TO_BE(v) BSON_UINT16_SWAP_LE_BE (v)
#define BSON_UINT32_FROM_LE(v) ((uint32_t) v)
#define BSON_UINT32_TO_LE(v) ((uint32_t) v)
#define BSON_UINT32_FROM_BE(v) BSON_UINT32_SWAP_LE_BE (v)
#define BSON_UINT32_TO_BE(v) BSON_UINT32_SWAP_LE_BE (v)
#define BSON_UINT64_FROM_LE(v) ((uint64_t) v)
#define BSON_UINT64_TO_LE(v) ((uint64_t) v)
#define BSON_UINT64_FROM_BE(v) BSON_UINT64_SWAP_LE_BE (v)
#define BSON_UINT64_TO_BE(v) BSON_UINT64_SWAP_LE_BE (v)
#define BSON_DOUBLE_FROM_LE(v) ((double) v)
#define BSON_DOUBLE_TO_LE(v) ((double) v)
#elif BSON_BYTE_ORDER == BSON_BIG_ENDIAN
#define BSON_UINT16_FROM_LE(v) BSON_UINT16_SWAP_LE_BE (v)
#define BSON_UINT16_TO_LE(v) BSON_UINT16_SWAP_LE_BE (v)
#define BSON_UINT16_FROM_BE(v) ((uint16_t) v)
#define BSON_UINT16_TO_BE(v) ((uint16_t) v)
#define BSON_UINT32_FROM_LE(v) BSON_UINT32_SWAP_LE_BE (v)
#define BSON_UINT32_TO_LE(v) BSON_UINT32_SWAP_LE_BE (v)
#define BSON_UINT32_FROM_BE(v) ((uint32_t) v)
#define BSON_UINT32_TO_BE(v) ((uint32_t) v)
#define BSON_UINT64_FROM_LE(v) BSON_UINT64_SWAP_LE_BE (v)
#define BSON_UINT64_TO_LE(v) BSON_UINT64_SWAP_LE_BE (v)
#define BSON_UINT64_FROM_BE(v) ((uint64_t) v)
#define BSON_UINT64_TO_BE(v) ((uint64_t) v)
#define BSON_DOUBLE_FROM_LE(v) (__bson_double_swap_slow (v))
#define BSON_DOUBLE_TO_LE(v) (__bson_double_swap_slow (v))
#else
#error "The endianness of target architecture is unknown."
#endif

#define MAX_POSITIONS 10

struct _kmip_writer_t {
   kms_request_str_t *buffer;

   size_t positions[MAX_POSITIONS];
   size_t cur_pos;
};

kmip_writer_t *
kmip_writer_new ()
{
   kmip_writer_t *writer = calloc (1, sizeof (kmip_writer_t));
   writer->buffer = kms_request_str_new ();
   return writer;
}

void
kmip_writer_destroy (kmip_writer_t *writer)
{
   kms_request_str_destroy (writer->buffer);
   free (writer);
}

void
kmip_writer_write_u8 (kmip_writer_t *writer, uint8_t value)
{
   char *c = (char *) &value;

   kms_request_str_append_chars (writer->buffer, c, 1);
}

void
kmip_writer_write_u16 (kmip_writer_t *writer, uint16_t value)
{
   uint16_t v = BSON_UINT16_TO_BE (value);
   char *c = (char *) &v;

   kms_request_str_append_chars (writer->buffer, c, 2);
}

void
kmip_writer_write_u32 (kmip_writer_t *writer, uint32_t value)
{
   uint32_t v = BSON_UINT32_TO_BE (value);
   char *c = (char *) &v;

   kms_request_str_append_chars (writer->buffer, c, 4);
}

void
kmip_writer_write_u64 (kmip_writer_t *writer, uint64_t value)
{
   uint64_t v = BSON_UINT64_TO_BE (value);
   char *c = (char *) &v;

   kms_request_str_append_chars (writer->buffer, c, 8);
}

void
kmip_writer_write_tag_enum (kmip_writer_t *writer, int32_t tag)
{
   // 0x42 for tags built into the protocol
   // 0x54 for extension tags
   kmip_writer_write_u8 (writer, 0x42);
   kmip_writer_write_u16 (writer, tag);
}

static int
compute_padding (int len)
{
   if (len % 8 == 0) {
      return len;
   }

   int padding = 8 - (len % 8);
   return len + padding;
}

void
kmip_writer_write_string (kmip_writer_t *writer, int32_t tag, const char *str, int len)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, ITEM_TYPE_TextString);
   kmip_writer_write_u32 (writer, len);

   int i;
   for (i = 0; i < len; i++) {
      kmip_writer_write_u8 (writer, str[i]);
   }

   int padded_length = compute_padding (len);
   for (i = 0; i < padded_length - len; i++) {
      kmip_writer_write_u8 (writer, 0);
   }
}

void
kmip_writer_write_bytes (kmip_writer_t *writer, int32_t tag, const char *str, int len)
{
   kmip_writer_write_tag_enum (writer, tag);

   kmip_writer_write_u8 (writer, ITEM_TYPE_ByteString);
   kmip_writer_write_u32 (writer, len);

   int i;
   for (i = 0; i < len; i++) {
      kmip_writer_write_u8 (writer, str[i]);
   }

   int padded_length = compute_padding (len);
   for (i = 0; i < padded_length - len; i++) {
      kmip_writer_write_u8 (writer, 0);
   }
}

void
kmip_writer_write_i32 (kmip_writer_t *writer, int32_t tag, int32_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, ITEM_TYPE_Integer);
   kmip_writer_write_u32 (writer, 4);
   kmip_writer_write_u32 (writer, value);
   kmip_writer_write_u32 (writer, 0);
}

void
kmip_writer_write_i64 (kmip_writer_t *writer, int32_t tag, int64_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, ITEM_TYPE_LongInteger);
   kmip_writer_write_u32 (writer, 8);
   kmip_writer_write_u64 (writer, value);
}

void
kmip_writer_write_enumeration (kmip_writer_t *writer, int32_t tag, int32_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, ITEM_TYPE_Enumeration);
   kmip_writer_write_u32 (writer, 4);
   kmip_writer_write_u32 (writer, value);
   kmip_writer_write_u32 (writer, 0);
}

void
kmip_writer_write_i64_datetime (kmip_writer_t *writer, int32_t tag, int64_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, ITEM_TYPE_DateTime);
   kmip_writer_write_u32 (writer, 8);
   kmip_writer_write_u64 (writer, value);
}

void
kmip_writer_begin_struct (kmip_writer_t *writer, int32_t tag)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, ITEM_TYPE_Structure);

   size_t pos = writer->buffer->len;

   kmip_writer_write_u32 (writer, 0);
   if (writer->cur_pos == MAX_POSITIONS) {
      abort ();
   }
   writer->cur_pos++;
   writer->positions[writer->cur_pos] = pos;
}

void
kmip_writer_close_struct (kmip_writer_t *writer)
{
   size_t current_pos = writer->buffer->len;
   if (writer->cur_pos == 0) {
      abort ();
   }
   size_t start_pos = writer->positions[writer->cur_pos];
   writer->cur_pos--;
   // offset by 4
   size_t len = current_pos - start_pos - 4;

   uint32_t v = BSON_UINT32_TO_BE (len);
   char *c = (char *) &v;
   memcpy (writer->buffer->str + start_pos, c, 4);
}

struct _kmip_reader_t {
   uint8_t *ptr;
   size_t pos;
   size_t len;
};

kmip_reader_t *
kmip_reader_new (uint8_t *ptr, size_t len)
{
   kmip_reader_t *reader = calloc (1, sizeof (kmip_reader_t));
   reader->ptr = ptr;
   reader->len = len;
   return reader;
}

void
kmip_reader_destroy (kmip_reader_t *reader)
{
   free (reader);
}

bool
kmip_reader_in_place (kmip_reader_t *reader,
                      size_t pos,
                      size_t len,
                      kmip_reader_t *out_reader)
{
   // Everything should be padding to 8 byte boundaries
   len = compute_padding (len);
   if ((pos + len) > reader->len) {
      return false;
   }

   memset (out_reader, 0, sizeof (kmip_reader_t));
   out_reader->ptr = reader->ptr + reader->pos;
   out_reader->len = len;
   return true;
}

size_t
kmip_reader_save_position (kmip_reader_t *reader)
{
   return reader->pos;
}

void
kmip_reader_restore_position (kmip_reader_t *reader, size_t pos)
{
   reader->pos = pos;
}

bool
kmip_reader_has_data (kmip_reader_t *reader)
{
   return reader->pos < reader->len;
}

#define CHECK_REMAINING_BUFFER_AND_RET(read_size)   \
   if ((reader->pos + (read_size)) > reader->len) { \
      return false;                                 \
   }

bool
kmip_reader_read_u8 (kmip_reader_t *reader, uint8_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint8_t));

   *value = *(reader->ptr + reader->pos);
   reader->pos += sizeof (uint8_t);

   return true;
}

bool
kmip_reader_read_u16 (kmip_reader_t *reader, uint16_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint16_t));

   uint16_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint16_t));
   *value = BSON_UINT16_FROM_BE (temp);
   reader->pos += sizeof (uint16_t);

   return true;
}

bool
kmip_reader_read_u32 (kmip_reader_t *reader, uint32_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint32_t));

   uint32_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint32_t));
   *value = BSON_UINT32_FROM_BE (temp);
   reader->pos += sizeof (uint32_t);

   return true;
}

bool
kmip_reader_read_u64 (kmip_reader_t *reader, uint64_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint64_t));

   uint64_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint64_t));
   *value = BSON_UINT64_FROM_BE (temp);
   reader->pos += sizeof (uint64_t);

   return true;
}

bool
kmip_reader_read_bytes (kmip_reader_t *reader, uint8_t **ptr, size_t length)
{
   size_t advance_length = compute_padding (length);
   CHECK_REMAINING_BUFFER_AND_RET (advance_length);

   *ptr = reader->ptr + reader->pos;
   reader->pos += advance_length;

   return true;
}

#define READER_CHECK_AND_RET(x) \
   if (!(x)) {                  \
      return false;             \
   }

bool
kmip_reader_read_tag (kmip_reader_t *reader, uint32_t *tag)
{
   uint8_t tag_first;

   READER_CHECK_AND_RET (kmip_reader_read_u8 (reader, &tag_first));

   if (tag_first != 0x42) {
      return false;
   }

   uint16_t tag_second;
   READER_CHECK_AND_RET (kmip_reader_read_u16 (reader, &tag_second));

   *tag = (0x420000 + tag_second);
   return true;
}

bool
kmip_reader_read_length (kmip_reader_t *reader, uint32_t *length)
{
   return kmip_reader_read_u32 (reader, length);
}

bool
kmip_reader_read_type (kmip_reader_t *reader, uint8_t *type)
{
   return kmip_reader_read_u8 (reader, type);
}

bool
kmip_reader_read_enumeration (kmip_reader_t *reader, uint32_t *enum_value)
{
   READER_CHECK_AND_RET (kmip_reader_read_u32 (reader, enum_value));

   // Skip 4 bytes becase enums are padded
   uint32_t ignored;

   return kmip_reader_read_u32 (reader, &ignored);
}

bool
kmip_reader_read_integer (kmip_reader_t *reader, uint32_t *value)
{
   READER_CHECK_AND_RET (kmip_reader_read_u32 (reader, value));

   // Skip 4 bytes becase integers are padded
   uint32_t ignored;

   return kmip_reader_read_u32 (reader, &ignored);
}

bool
kmip_reader_read_long_integer (kmip_reader_t *reader, uint64_t *value)
{
   return kmip_reader_read_u64 (reader, value);
}

bool
kmip_reader_read_bytes (kmip_reader_t *reader, uint8_t **ptr, size_t length)
{
   return kmip_reader_read_bytes (reader, ptr, length);
}

bool
kmip_reader_read_string (kmip_reader_t *reader, uint8_t **ptr, size_t length)
{
   return kmip_reader_read_bytes (reader, ptr, length);
}

#define FIND_CHECK_AND_RET(x) \
   if (!(x)) {                \
      return false;           \
   }

// Note: does not descend structures
bool
kmip_reader_find (kmip_reader_t *reader,
                  size_t search_tag,
                  uint8_t type,
                  size_t *pos,
                  size_t *length)
{
   reader->pos = 0;
   // size_t saved_pos = kmip_reader_save_position(reader);

   while (kmip_reader_has_data (reader)) {
      uint32_t read_tag;
      FIND_CHECK_AND_RET (kmip_reader_read_tag (reader, &read_tag));

      uint8_t read_type;
      FIND_CHECK_AND_RET (kmip_reader_read_type (reader, &read_type));

      uint32_t read_length;
      FIND_CHECK_AND_RET (kmip_reader_read_length (reader, &read_length));


      if (read_tag == search_tag && read_type == type) {
         *pos = reader->pos;
         *length = read_length;
         return true;
      }

      size_t advance_length = read_length;
      // if(read_type == ITEM_TYPE_ByteString || read_type ==
      // ITEM_TYPE_TextString ) {
      advance_length = compute_padding (advance_length);
      //}

      CHECK_REMAINING_BUFFER_AND_RET (advance_length);

      // Skip to the next type,
      reader->pos += advance_length;
   }

   return false;
}

kmip_reader_t *
kmip_reader_find_and_get_struct_reader (kmip_reader_t *reader, size_t tag)
{
   size_t pos;
   size_t length;

   if (!kmip_reader_find (reader, tag, ITEM_TYPE_Structure, &pos, &length)) {
      return NULL;
   }

   return kmip_reader_new (reader->ptr + pos, length);
}

bool
kmip_reader_find_and_read_enum (kmip_reader_t *reader,
                                size_t tag,
                                uint32_t *value)
{
   size_t pos;
   size_t length;

   if (!kmip_reader_find (reader, tag, ITEM_TYPE_Enumeration, &pos, &length)) {
      return NULL;
   }

   kmip_reader_t temp_reader;
   if (!kmip_reader_in_place (reader, pos, length, &temp_reader)) {
      return false;
   }

   return kmip_reader_read_enumeration (&temp_reader, value);
}

bool
kmip_reader_find_and_read_bytes (kmip_reader_t *reader,
                                 size_t tag,
                                 uint8_t **out_ptr,
                                 size_t *out_len)
{
   size_t pos;

   if (!kmip_reader_find (reader, tag, ITEM_TYPE_ByteString, &pos, out_len)) {
      return NULL;
   }

   kmip_reader_t temp_reader;
   if (!kmip_reader_in_place (reader, pos, *out_len, &temp_reader)) {
      return false;
   }

   return kmip_reader_read_bytes (&temp_reader, out_ptr, *out_len);
}
