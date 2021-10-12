#include "test_kms_assert.h"
#include "test_kms_util.h"

#include "kms_message/kms_kmip_response_parser.h"

void
kms_kmip_response_parser_test (void)
{
#define LARGE_LENGTH 1024 /* a byte size larger than the message. */
#define FIRST_LENGTH \
   32 /* length of message after the first tag, type, and length. */
   kms_response_parser_t *parser;
   uint8_t *data;
   size_t outlen;
   int32_t want_bytes;
   kms_response_t *res;


   /* The following sample data come from section 9.1.2 of
    * http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html. The
    * data describes "A Structure containing an Enumeration, value 254, followed
    * by an Integer, value 255, having tags 420004 and 420005 respectively." */
   data = hex_to_data (
      "42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE "
      "00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00",
      &outlen);
   parser = kms_kmip_response_parser_new (NULL);

   /* Expect the parser to initially request only 8 bytes.
    * The 8 bytes = 3 byte tag + 1 byte type + 4 byte length. */
   want_bytes = kms_response_parser_wants_bytes (parser, LARGE_LENGTH);
   ASSERT_CMPINT (8, ==, want_bytes);

   /* A smaller maximum size caps the requested bytes. */
   want_bytes = kms_response_parser_wants_bytes (parser, 1);
   ASSERT_CMPINT (1, ==, want_bytes);

   /* Feed one byte */
   kms_response_parser_feed (parser, data, 1);
   // ASSERT_STATUS_OK (status);

   want_bytes = kms_response_parser_wants_bytes (parser, LARGE_LENGTH);
   ASSERT_CMPINT (7, ==, want_bytes);

   /* Feed the remaining 7 bytes. */
   kms_response_parser_feed (parser, data + 1, 7);
   // ASSERT_STATUS_OK (status);

   /* The parser knows first length. Expect the parser knows to want exactly the
    * remaining length. */
   want_bytes = kms_response_parser_wants_bytes (parser, LARGE_LENGTH);
   ASSERT_CMPINT (want_bytes, ==, FIRST_LENGTH);

   kms_response_parser_feed (parser, data + 8, FIRST_LENGTH);
   // ASSERT_STATUS_OK (status);

   /* Parser has full message. */
   want_bytes = kms_response_parser_wants_bytes (parser, LARGE_LENGTH);
   ASSERT_CMPINT (want_bytes, ==, 0);

   res = kms_response_parser_get_response (parser);
   // ASSERT_STATUS_OK (status);
   ASSERT (res);
   kms_response_destroy (res);

   kms_response_parser_destroy (parser);
   free (data);

#undef LARGE_LENGTH
#undef FIRST_LENGTH
}
