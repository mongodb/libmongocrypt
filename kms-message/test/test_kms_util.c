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

#include "test_kms_util.h"

#include "hexlify.h"

#include <ctype.h> /* tolower */

char *
copy_and_filter_hex (const char *unfiltered_hex)
{
   size_t i, j;

   char *filtered = malloc (strlen (unfiltered_hex) + 1);
   j = 0;
   for (i = 0; i < strlen (unfiltered_hex); i++) {
      if (unfiltered_hex[i] != ' ' && unfiltered_hex[i] != '|') {
         filtered[j] = (char) tolower (unfiltered_hex[i]);
         j++;
      }
   }
   filtered[j] = '\0';
   return filtered;
}

uint8_t *
hex_to_data (char *unfiltered_hex, size_t *outlen)
{
   char *filtered_hex;
   uint8_t *bytes;
   size_t i;

   filtered_hex = copy_and_filter_hex (unfiltered_hex);
   *outlen = strlen (filtered_hex) / 2;
   bytes = malloc (*outlen);
   for (i = 0; i < *outlen; i++) {
      bytes[i] = unhexlify (filtered_hex + (i * 2), 2);
   }

   free (filtered_hex);
   return bytes;
}

char *
data_to_hex (const uint8_t *buf, size_t len) {
   return hexlify (buf, len);
}
