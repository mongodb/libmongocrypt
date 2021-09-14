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

#include <stdint.h>

#include "kms_kmip_reader_writer_private.h"

#include "kms_kmip_request.h"

struct _kmip_request_t {
    uint8_t *data;
    uint32_t len;
};

kmip_request_t *
kmip_request_create_new (void* reserved, kms_status_t *status) {
   kmip_writer_t *writer;

   // Write an encryption request

   // <RequestMessage>
   //   <RequestHeader>
   //     <ProtocolVersion>
   //       <ProtocolVersionMajor type="Integer" value="1"/>
   //       <ProtocolVersionMinor type="Integer" value="4"/>
   //     </ProtocolVersion>
   //     <BatchCount type="Integer" value="1"/>
   //   </RequestHeader>
   //   <BatchItem>
   //     <Operation type="Enumeration" value="Encrypt"/>
   //     <RequestPayload>
   //       <UniqueIdentifier type="TextString" value="1"/>
   //       <CryptographicParameters>
   //         <BlockCipherMode type="Enumeration" value="CBC"/>
   //         <PaddingMethod type="Enumeration" value="None"/>
   //       </CryptographicParameters>
   //       <Data type="ByteString" value="01020304050607080910111213141516"/>
   //       <IVCounterNonce type="ByteString"
   //       value="01020304050607080910111213141516"/>
   //     </RequestPayload>
   //   </BatchItem>
   // </RequestMessage>
   // clang-format: off
   begin_struct (writer, TAG_RequestMessage);
   begin_struct (writer, TAG_RequestHeader);
   begin_struct (writer, TAG_ProtocolVersion);
   write_i32 (writer, TAG_ProtocolVersionMajor, 1);
   write_i32 (writer, TAG_ProtocolVersionMinor, 2);
   close_struct (writer);
   write_i32 (writer, TAG_BatchCount, 1);
   close_struct (writer);
   begin_struct (writer, TAG_BatchItem);
   write_enumeration (writer, TAG_Operation, 0x1F);
   begin_struct (writer, TAG_RequestPayload);
   write_string (writer, TAG_UniqueIdentifier, id, strlen (id));
   begin_struct (writer, TAG_CryptographicParameters);
   write_enumeration (writer, TAG_BlockCipherMode, 1); // CBC
   write_enumeration (writer, TAG_PaddingMethod, 1);   // None
   close_struct (writer);
   write_bytes (writer, TAG_Data, (const char *) plaintext, plaintext_len);
   write_bytes (
      writer, TAG_IVCounterNonce, (const char *) iv_nonce, iv_nonce_len);
   close_struct (writer);
   close_struct (writer);
   close_struct (writer);
   // clang-format: on


done:
   kmip_writer_destroy (writer);

   return req;
}
