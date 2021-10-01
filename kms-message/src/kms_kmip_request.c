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

#include <inttypes.h>
#include <stdint.h>

#include "kms_kmip_reader_writer_private.h"
#include "kms_status_private.h"

#include "kms_message/kms_kmip_request.h"
#include "kms_message/kms_status.h"

struct _kms_kmip_request_t {
    uint8_t *data;
    uint32_t len;
};

void
kms_kmip_request_destroy (kms_kmip_request_t *req) {
   if (!req) {
      return;
   }
   free (req->data);
   free (req);
}

/* TODO: remove unused request. */
kms_kmip_request_t *
kms_kmip_request_discover_versions_new (void *reserved, kms_status_t *status) {
   kms_kmip_request_t *req;
   kmip_writer_t *writer;
   const uint8_t *buf;
   size_t len;

   /*
   <RequestMessage>
      <RequestHeader>
         <ProtocolVersion>
            <ProtocolVersionMajor type="Integer" value="1" />
            <ProtocolVersionMinor type="Integer" value="4" />
         </ProtocolVersion>
         <BatchCount type="Integer" value="1" />
      </RequestHeader>
      <BatchItem>
         <Operation type="Enumeration" value="0000001E" />
      </BatchItem>
   */
   writer = kmip_writer_new ();
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestMessage);

   kmip_writer_begin_struct (writer, KMIP_TAG_RequestHeader);
   kmip_writer_begin_struct (writer, KMIP_TAG_ProtocolVersion);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMajor, 1);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMinor, 4);
   kmip_writer_close_struct (writer); /* KMIP_TAG_ProtocolVersion */
   kmip_writer_write_integer(writer, KMIP_TAG_BatchCount, 1);
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestHeader */
   
   kmip_writer_begin_struct (writer, KMIP_TAG_BatchItem);
   /* 0x1E == Discover Versions */
   kmip_writer_write_enumeration (writer, KMIP_TAG_Operation, 0x0000001E);
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestPayload);
   /* Empty payload */
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestPayload */
   kmip_writer_close_struct (writer); /* KMIP_TAG_BatchItem */
   kmip_writer_close_struct (writer);
   
   /* Copy the KMIP writer buffer to a KMIP request. */
   buf = kmip_writer_get_buffer (writer, &len);
   req = calloc (1, sizeof (kms_kmip_request_t));
   req->data = malloc (len);
   memcpy (req->data, buf, len);
   req->len = (uint32_t) len;
   
   kmip_writer_destroy (writer);

   return req;
}


kms_kmip_request_t *
kms_kmip_request_register_secretdata_new (void *reserved,
                                                       uint8_t *data,
                                                       uint32_t len,
                                                       kms_status_t *status)
{
   kmip_writer_t *writer;
   kms_kmip_request_t *req;
   const uint8_t *buf;
   size_t buflen;

   if (len != 96) {
      kms_status_errorf (status, "expected SecretData length of 96, got %" PRIu32, len);
      return NULL;
   }

   /*
   // The following is the XML representation of the request.
   <RequestMessage>
      <RequestHeader>
         <ProtocolVersion>
            <ProtocolVersionMajor type="Integer" value="1" />
            <ProtocolVersionMinor type="Integer" value="4" />
         </ProtocolVersion>
         <BatchCount type="Integer" value="1" />
      </RequestHeader>
      <BatchItem>
         <Operation type="Enumeration" value="00000003" />
         <UniqueBatchItemID type="ByteString" value="A" />
         <RequestPayload>
            <ObjectType type="Enumeration" value="00000007" />
            <TemplateAttribute>
            TODO: are any attributes required by vault?
            </TemplateAttribute>
            <SecretData>
               TODO:
               00000001 is "Password".
               00000002 is type "Seed".
               Should I use an extension?
               <SecretDataType type="Enumeration" value="00000002" />
               <KeyBlock>
                  00000001 = Raw
                  <KeyFormatType type="Enumeration" value="00000001" />
                  <KeyValue>
                     <KeyMaterial type="ByteString" value="..." />
                  </KeyValue>
               </KeyBlock>
            </SecretData>
         </RequestPayload>
      </BatchItem>
   */

   writer = kmip_writer_new ();
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestMessage);

   kmip_writer_begin_struct (writer, KMIP_TAG_RequestHeader);
   kmip_writer_begin_struct (writer, KMIP_TAG_ProtocolVersion);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMajor, 1);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMinor, 4);
   kmip_writer_close_struct (writer); /* KMIP_TAG_ProtocolVersion */
   kmip_writer_write_integer(writer, KMIP_TAG_BatchCount, 1);
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestHeader */
   
   kmip_writer_begin_struct (writer, KMIP_TAG_BatchItem);
   /* 0x03 == Register */
   kmip_writer_write_enumeration (writer, KMIP_TAG_Operation, 0x03);
   kmip_writer_write_bytes (writer, KMIP_TAG_UniqueBatchItemID, "A", 1);
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestPayload);
   /* 0x07 == SecretData */
   kmip_writer_write_enumeration (writer, KMIP_TAG_ObjectType, 0x07);
   kmip_writer_begin_struct (writer, KMIP_TAG_TemplateAttribute);
   kmip_writer_close_struct (writer); /* KMIP_TAG_TemplateAttribute */
   kmip_writer_begin_struct (writer, KMIP_TAG_SecretData);
   /* 0x02 = Seed */
   kmip_writer_write_enumeration (writer, KMIP_TAG_SecretDataType, 0x02);
   kmip_writer_begin_struct (writer, KMIP_TAG_KeyBlock);
   /* 0x01 = Raw */
   kmip_writer_write_enumeration (writer, KMIP_TAG_KeyFormatType, 0x01);
   kmip_writer_begin_struct (writer, KMIP_TAG_KeyValue);
   kmip_writer_write_bytes (writer, KMIP_TAG_KeyMaterial, (char*) data, len);
   kmip_writer_close_struct (writer); /* KMIP_TAG_KeyValue */
   kmip_writer_close_struct (writer); /* KMIP_TAG_KeyBlock */
   kmip_writer_close_struct (writer); /* KMIP_TAG_SecretData */
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestPayload */
   kmip_writer_close_struct (writer); /* KMIP_TAG_BatchItem */
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestMessage */

   /* Copy the KMIP writer buffer to a KMIP request. */
   buf = kmip_writer_get_buffer (writer, &buflen);
   req = calloc (1, sizeof (kms_kmip_request_t));
   req->data = malloc (buflen);
   memcpy (req->data, buf, buflen);
   req->len = (uint32_t) buflen;
   kmip_writer_destroy (writer);
   return req;
}

kms_kmip_request_t *
kms_kmip_request_activate_new (void *reserved, char* uid, kms_status_t *status) {
   /*
   // The following is the XML representation of the request.
   <RequestMessage>
      <RequestHeader>
         <ProtocolVersion>
            <ProtocolVersionMajor type="Integer" value="1" />
            <ProtocolVersionMinor type="Integer" value="4" />
         </ProtocolVersion>
         <BatchCount type="Integer" value="1" />
      </RequestHeader>
      <BatchItem>
         // 00000012 = Activate
         <Operation type="Enumeration" value="00000012" />
         <RequestPayload>
            <UniqueIdentifier type="TextString" value="...">
         </RequestPayload>
      </BatchItem>
   */

   kmip_writer_t *writer;
   kms_kmip_request_t *req;
   const uint8_t *buf;
   size_t buflen;

   writer = kmip_writer_new ();
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestMessage);

   kmip_writer_begin_struct (writer, KMIP_TAG_RequestHeader);
   kmip_writer_begin_struct (writer, KMIP_TAG_ProtocolVersion);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMajor, 1);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMinor, 4);
   kmip_writer_close_struct (writer); /* KMIP_TAG_ProtocolVersion */
   kmip_writer_write_integer(writer, KMIP_TAG_BatchCount, 1);
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestHeader */
   
   kmip_writer_begin_struct (writer, KMIP_TAG_BatchItem);
   /* 0x0A == Get */
   kmip_writer_write_enumeration (writer, KMIP_TAG_Operation, 0x12);
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestPayload);
   kmip_writer_write_string (writer, KMIP_TAG_UniqueIdentifier, uid, strlen(uid));
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestPayload */
   kmip_writer_close_struct (writer); /* KMIP_TAG_BatchItem */
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestMessage */

   /* Copy the KMIP writer buffer to a KMIP request. */
   buf = kmip_writer_get_buffer (writer, &buflen);
   req = calloc (1, sizeof (kms_kmip_request_t));
   req->data = malloc (buflen);
   memcpy (req->data, buf, buflen);
   req->len = (uint32_t) buflen;
   kmip_writer_destroy (writer);
   return req;
}

kms_kmip_request_t *
kms_kmip_request_get_new (void *reserved, char *uid, kms_status_t *status) {
   /*
   // The following is the XML representation of the request.
   <RequestMessage>
      <RequestHeader>
         <ProtocolVersion>
            <ProtocolVersionMajor type="Integer" value="1" />
            <ProtocolVersionMinor type="Integer" value="4" />
         </ProtocolVersion>
         <BatchCount type="Integer" value="1" />
      </RequestHeader>
      <BatchItem>
         // 0000000A = Get
         <Operation type="Enumeration" value="0000000A" />
         <RequestPayload>
            <UniqueIdentifier type="TextString" value="...">
         </RequestPayload>
      </BatchItem>
   */

   kmip_writer_t *writer;
   kms_kmip_request_t *req;
   const uint8_t *buf;
   size_t buflen;

   writer = kmip_writer_new ();
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestMessage);

   kmip_writer_begin_struct (writer, KMIP_TAG_RequestHeader);
   kmip_writer_begin_struct (writer, KMIP_TAG_ProtocolVersion);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMajor, 1);
   kmip_writer_write_integer (writer, KMIP_TAG_ProtocolVersionMinor, 4);
   kmip_writer_close_struct (writer); /* KMIP_TAG_ProtocolVersion */
   kmip_writer_write_integer(writer, KMIP_TAG_BatchCount, 1);
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestHeader */
   
   kmip_writer_begin_struct (writer, KMIP_TAG_BatchItem);
   /* 0x0A == Get */
   kmip_writer_write_enumeration (writer, KMIP_TAG_Operation, 0x0A);
   kmip_writer_begin_struct (writer, KMIP_TAG_RequestPayload);
   kmip_writer_write_string (writer, KMIP_TAG_UniqueIdentifier, uid, strlen(uid));
   /* 0x01 = Raw */
   // kmip_writer_write_enumeration (writer, KMIP_TAG_KeyFormatType, 0x01);
   /* Allegedly, from PyKMIP: "Key format is not applicable to the specified object" */
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestPayload */
   kmip_writer_close_struct (writer); /* KMIP_TAG_BatchItem */
   kmip_writer_close_struct (writer); /* KMIP_TAG_RequestMessage */

   /* Copy the KMIP writer buffer to a KMIP request. */
   buf = kmip_writer_get_buffer (writer, &buflen);
   req = calloc (1, sizeof (kms_kmip_request_t));
   req->data = malloc (buflen);
   memcpy (req->data, buf, buflen);
   req->len = (uint32_t) buflen;
   kmip_writer_destroy (writer);
   return req;
}

uint8_t * kms_kmip_request_to_bytes (kms_kmip_request_t *req, uint32_t *len) {
   if (!req) {
      *len = 0;
      return NULL;
   }

   *len = req->len;
   return req->data;
}
