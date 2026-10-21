/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"){}
 *
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

#include "kms_message/kms_message.h"
#include "kms_message_private.h"
#include "kms_message/kms_b64.h"
#include "kms_request_str.h"

#define KMS_PRINTABLE_ASCII_START ' '
#define KMS_PRINTABLE_ASCII_END '~'

/* _key_id_chars_are_valid returns true if `key_id` is safe to interpolate into the JSON body of the AWS
 * Encrypt request. Reject non-printable ASCII, double quotes, and backslashes: those end the JSON string
 * and let the caller add request members of their own, which are then signed with the SigV4 signature.
 *
 * A key identifier may be a key ID, an ARN, or an alias, none of which contain those characters.
 *
 * `key_id` is not included in the error message: it is untrusted, and the error may be logged.
 *
 * This duplicates _oauth_field_chars_are_valid in kms_gcp_request.c. */
static bool
_key_id_chars_are_valid (kms_request_t *req, const char *key_id)
{
   for (const char *i = key_id; *i != '\0'; i++) {
      const unsigned char uc = (unsigned char) *i;

      if (uc < KMS_PRINTABLE_ASCII_START || uc > KMS_PRINTABLE_ASCII_END ||
          uc == '"' || uc == '\\') {
         KMS_ERROR (req, "Invalid character in AWS KMS key identifier");
         return false;
      }
   }
   return true;
}

kms_request_t *
kms_encrypt_request_new (const uint8_t *plaintext,
                         size_t plaintext_length,
                         const char *key_id,
                         const kms_request_opt_t *opt)
{
   kms_request_t *request;
   size_t b64_len;
   char *b64 = NULL;
   kms_request_str_t *payload = NULL;

   request = kms_request_new ("POST", "/", opt);
   if (kms_request_get_error (request)) {
      goto done;
   }

   if (!_key_id_chars_are_valid (request, key_id)) {
      goto done;
   }

   if (!(kms_request_add_header_field (
            request, "Content-Type", "application/x-amz-json-1.1") &&
         kms_request_add_header_field (
            request, "X-Amz-Target", "TrentService.Encrypt"))) {
      goto done;
   }

   b64_len = (plaintext_length / 3 + 1) * 4 + 1;
   if (!(b64 = malloc (b64_len))) {
      KMS_ERROR (request,
                 "Could not allocate %d bytes for base64-encoding payload",
                 (int) b64_len);
      goto done;
   }

   if (kms_message_b64_ntop (
          (const uint8_t *) plaintext, plaintext_length, b64, b64_len) == -1) {
      KMS_ERROR (request, "Could not base64-encode plaintext");
      goto done;
   }

   payload = kms_request_str_new ();
   kms_request_str_appendf (
      payload, "{\"Plaintext\": \"%s\", \"KeyId\": \"%s\"}", b64, key_id);
   if (!kms_request_append_payload (request, payload->str, payload->len)) {
      KMS_ERROR (request, "Could not append payload");
      goto done;
   }

done:
   free (b64);
   kms_request_str_destroy (payload);

   return request;
}
