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

#include "kms_message/kms_kmip_response_parser.h"

#include "kms_request_str.h"
#include "kms_endian_private.h"
#include "kms_status_private.h"
#include "kms_kmip_response_private.h"

struct _kms_kmip_response_parser_t {
   uint32_t first_len;
   uint32_t bytes_fed;
   kms_request_str_t *buf;
};

/* FIRST_LENGTH is the number of bytes needed to determine the length of the remaining message. */
#define FIRST_LENGTH 8
/* FIRST_LENGTH_OFFSET is the offset of the first four byte length. */
#define FIRST_LENGTH_OFFSET 4

kms_kmip_response_parser_t *
kms_kmip_response_parser_new (void)
{
   kms_kmip_response_parser_t *parser;

   parser = calloc (1, sizeof (kms_kmip_response_parser_t));
   parser->buf = kms_request_str_new ();
   return parser;
}

int32_t
kms_kmip_response_parser_wants_bytes (kms_kmip_response_parser_t *parser,
                                      int32_t max)
{
   int32_t wants_bytes;
   if (parser->bytes_fed < FIRST_LENGTH) {
      wants_bytes = FIRST_LENGTH - parser->bytes_fed;
   } else {
      wants_bytes = (parser->first_len + FIRST_LENGTH) - parser->bytes_fed;
   }
   if (max < wants_bytes) {
      return max;
   }
   return wants_bytes;
}

bool
kms_kmip_response_parser_feed (kms_kmip_response_parser_t *parser,
                               uint8_t *buf,
                               uint32_t len,
                               kms_status_t *status)
{
   kms_request_str_append_chars (parser->buf, (char*) buf, len);
   parser->bytes_fed += len;

   if (parser->first_len == 0 && parser->bytes_fed >= FIRST_LENGTH) {
      uint32_t temp;
      memcpy (&temp, parser->buf->str + FIRST_LENGTH_OFFSET, sizeof (uint32_t));
      parser->first_len = KMS_UINT32_FROM_BE (temp);
   }
   return true;
}

kms_kmip_response_t *
kms_kmip_response_parser_get_response (kms_kmip_response_parser_t *parser,
                                       kms_status_t *status)
{
   kms_kmip_response_t *res;

   if (kms_kmip_response_parser_wants_bytes (parser, 1) != 0) {
      kms_status_errorf (status, "KMIP parser does not have complete message");
      return NULL;
   }

   res = calloc (1, sizeof (kms_kmip_response_t));
   res->data = malloc (parser->buf->len);
   memcpy (res->data, parser->buf->str, parser->buf->len);
   res->len = parser->buf->len;
   return res;
}

void
kms_kmip_response_parser_destroy (kms_kmip_response_parser_t *parser)
{
   if (!parser) {
      return;
   }
   kms_request_str_destroy (parser->buf);
   free (parser);
}
