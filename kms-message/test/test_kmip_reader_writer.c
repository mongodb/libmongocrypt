#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "src/hexlify.h"
#include "src/kms_kmip_reader_writer_private.h"
#include "test_kms_request.h"

typedef struct {
   char *desc;
   char *expected_hex;
} kms_kmip_writer_test_case_t;

/* Return a copy of @hex with the following characters removed: ' ', '|' */
static char *
copy_and_filter_hex (const char *hex)
{
   size_t i, j;

   char *filtered = malloc (strlen (hex) + 1);
   j = 0;
   for (i = 0; i < strlen (hex); i++) {
      if (hex[i] != ' ' && hex[i] != '|') {
         filtered[j] = (char) tolower (hex[i]);
         j++;
      }
   }
   filtered[j] = '\0';
   return filtered;
}

static void
kms_kmip_writer_test_evaluate (kmip_writer_t *writer,
                               const char *expected_hex_in,
                               char *desc)
{
   char *expected_hex;
   const uint8_t *actual_buf;
   size_t actual_len;
   char *actual_hex;

   expected_hex = copy_and_filter_hex (expected_hex_in);
   actual_buf = kmip_writer_get_buffer (writer, &actual_len);
   actual_hex = hexlify (actual_buf, actual_len);

   if (0 != strcmp (expected_hex, actual_hex)) {
      fprintf (stderr,
               "expected '%s' but got '%s' for test description: %s\n",
               expected_hex,
               actual_hex,
               desc);
      abort ();
   }

   free (actual_hex);
   free (expected_hex);
}

void
kms_kmip_writer_test (void)
{
   kmip_writer_t *writer;

   /* The following test cases come from section 9.1.2 of
    * http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html */
   writer = kmip_writer_new ();
   kmip_writer_write_integer (writer, TAG_CompromiseDate, 8);
   kms_kmip_writer_test_evaluate (
      writer,
      "42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00",
      "An Integer containing the decimal value 8");
   kmip_writer_destroy (writer);

   writer = kmip_writer_new ();
   kmip_writer_write_long_integer (
      writer, TAG_CompromiseDate, 123456789000000000LL);
   kms_kmip_writer_test_evaluate (
      writer,
      "42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00",
      "A Long Integer containing the decimal value 123456789000000000");
   kmip_writer_destroy (writer);

   /* BigInteger is not implemented. */

   writer = kmip_writer_new ();
   kmip_writer_write_enumeration (writer, TAG_CompromiseDate, 255);
   kms_kmip_writer_test_evaluate (
      writer,
      "42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00",
      "An Enumeration with value 255");
   kmip_writer_destroy (writer);

   /* Boolean is not implemented. */

   writer = kmip_writer_new ();
   kmip_writer_write_string (writer, TAG_CompromiseDate, "Hello World", 11);
   kms_kmip_writer_test_evaluate (writer,
                                  "42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C "
                                  "6F 20 57 6F 72 6C 64 00 00 00 00 00",
                                  "A Text String with the value 'Hello World'");
   kmip_writer_destroy (writer);

   writer = kmip_writer_new ();
   kmip_writer_write_bytes (writer, TAG_CompromiseDate, "\01\02\03", 3);
   kms_kmip_writer_test_evaluate (
      writer,
      "42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00",
      "A Byte String with the value { 0x01, 0x02, 0x03 }");
   kmip_writer_destroy (writer);

   writer = kmip_writer_new ();
   kmip_writer_write_datetime (
      writer, TAG_CompromiseDate, 0x0000000047DA67F8LL);
   kms_kmip_writer_test_evaluate (
      writer,
      "42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8",
      "A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 "
      "GMT");
   kmip_writer_destroy (writer);

   /* Interval is not implemented. */

   writer = kmip_writer_new ();
   kmip_writer_begin_struct (writer, TAG_CompromiseDate);
   kmip_writer_write_enumeration (
      writer, TAG_ApplicationSpecificInformation, 254);
   kmip_writer_write_integer (writer, TAG_ArchiveDate, 255);
   kmip_writer_close_struct (writer);
   kms_kmip_writer_test_evaluate (
      writer,
      "42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE "
      "00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00",
      "A Structure containing an Enumeration, value 254, followed by an "
      "Integer, value 255, having tags 420004 and 420005 respectively");
   kmip_writer_destroy (writer);
}

static uint8_t *
kms_kmip_reader_test_new_data (char *hex, size_t *outlen)
{
   char *filtered_hex;
   uint8_t *bytes;
   size_t i;

   filtered_hex = copy_and_filter_hex (hex);
   *outlen = strlen (filtered_hex) / 2;
   bytes = malloc (*outlen);
   for (i = 0; i < *outlen; i++) {
      bytes[i] = unhexlify (filtered_hex + (i * 2), 2);
   }

   free (filtered_hex);
   return bytes;
}

void
kms_kmip_reader_test (void)
{
   uint8_t *data;
   size_t datalen;
   kmip_reader_t *reader;
   enum TAG_TYPE tag;
   enum ITEM_TYPE type;
   uint32_t length;
   int32_t i32;
   int64_t i64;
   uint32_t u32;
   uint8_t *ptr;

   /* The following test cases come from section 9.1.2 of
    * http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html */
   /* An Integer containing the decimal value 8 */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Integer);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 4);
   ASSERT (kmip_reader_read_integer (reader, &i32));
   ASSERT (i32 == 8);
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* A Long Integer containing the decimal value 123456789000000000 */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_LongInteger);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 8);
   ASSERT (kmip_reader_read_long_integer (reader, &i64));
   ASSERT (i64 == 123456789000000000LL);
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* Big Integer is not implemented. */

   /* An Enumeration with value 255 */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Enumeration);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 4);
   ASSERT (kmip_reader_read_enumeration (reader, &u32));
   ASSERT (u32 == 255);
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* Boolean is not implemented */

   /* A Text String with the value 'Hello World' */
   data =
      kms_kmip_reader_test_new_data ("42 00 20 | 07 | 00 00 00 0B | 48 65 6C "
                                     "6C 6F 20 57 6F 72 6C 64 00 00 00 00 00",
                                     &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_TextString);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 11);
   ASSERT (kmip_reader_read_string (reader, &ptr, length));
   ASSERT (0 == strncmp ("Hello World", (const char *) ptr, length));
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* A Byte String with the value { 0x01, 0x02, 0x03 } */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_ByteString);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 3);
   ASSERT (kmip_reader_read_bytes (reader, &ptr, length));
   ASSERT (0 == strncmp ("\01\02\03", (const char *) ptr, length));
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT
    */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_DateTime);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 8);
   kmip_reader_read_long_integer (reader, &i64);
   ASSERT (i64 == 0x47DA67F8);
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* Interval is not implemented. */

   /* A Structure containing an Enumeration, value 254, followed by an Integer,
    * value 255, having tags 420004 and 420005 respectively */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE "
      "00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00",
      &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Structure);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 0x20);

   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_ApplicationSpecificInformation);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Enumeration);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 4);
   ASSERT (kmip_reader_read_enumeration (reader, &u32));
   ASSERT (u32 == 254);

   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_ArchiveDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Integer);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 4);
   ASSERT (kmip_reader_read_integer (reader, &i32));
   ASSERT (i32 == 255);

   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);
}

void
kms_kmip_reader_negative_int_test (void)
{
   uint8_t *data;
   size_t datalen;
   kmip_reader_t *reader;
   uint32_t tag;
   enum ITEM_TYPE type;
   uint32_t length;
   int32_t i32;

   /* Test reading the integer -1. */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 02 | 00 00 00 04 | FF FF FF FF 00 00 00 00", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Integer);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 4);
   ASSERT (kmip_reader_read_integer (reader, &i32));
   ASSERT (i32 == -1);
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);

   /* Test reading the integer INT32_MIN (-2^31). */
   data = kms_kmip_reader_test_new_data (
      "42 00 20 | 02 | 00 00 00 04 | 80 00 00 00 00 00 00 00", &datalen);
   reader = kmip_reader_new (data, datalen);
   ASSERT (kmip_reader_read_tag (reader, &tag));
   ASSERT (tag == TAG_CompromiseDate);
   ASSERT (kmip_reader_read_type (reader, &type));
   ASSERT (type == ITEM_TYPE_Integer);
   ASSERT (kmip_reader_read_length (reader, &length));
   ASSERT (length == 4);
   ASSERT (kmip_reader_read_integer (reader, &i32));
   ASSERT (i32 == INT32_MIN);
   ASSERT (!kmip_reader_has_data (reader));
   kmip_reader_destroy (reader);
   free (data);
}
