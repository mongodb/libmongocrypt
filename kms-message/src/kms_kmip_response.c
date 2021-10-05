#include "kms_message/kms_kmip_response.h"
#include "kms_kmip_response_private.h"
#include "kms_kmip_reader_writer_private.h"
#include "kms_status_private.h"

#include <stdlib.h>
#include <inttypes.h>

uint8_t *
kms_kmip_response_to_bytes (kms_kmip_response_t *res, uint32_t *len)
{
   *len = res->len;
   return res->data;
}

/*
Result reason strings were obtained from 9.1.3.2.29 of the KMIP 1.4
specification.
http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html
*/
static const char *
result_reason_to_string (uint32_t result_reason)
{
   switch (result_reason) {
   case 0x00000011:
      return "Key Compression Type Not Supported";

   case 0x00000012:
      return "Encoding Option Error";

   case 0x00000013:
      return "Key Value Not Present";

   case 0x00000014:
      return "Attestation Required";

   case 0x00000015:
      return "Attestation Failed";

   case 0x00000016:
      return "Sensitive";

   case 0x00000017:
      return "Not Extractable";

   case 0x00000018:
      return "Object Already Exists";

   case 0x00000100:
      return "General Failure";

   default:
      return "(Unknown Result Reason)";
   }
}

/*
Result status strings were obtained from 9.1.3.2.28 of the KMIP 1.4
specification.
http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html
*/
static const char *
result_status_to_string (uint32_t result_status)
{
   switch (result_status) {
   case 0x00000000:
      return "Success";

   case 0x00000001:
      return "Operation Failed";

   case 0x00000002:
      return "Operation Pending";

   case 0x00000003:
      return "Operation Undone";

   default:
      return "(Unknown Result Status)";
   }
}

/* Example successful Response to a Register request:
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime"
value="2021-10-05T10/05/21-0500"/> <BatchCount tag="0x42000d" type="Integer"
value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="3"/>
  <UniqueBatchItemID tag="0x420093" type="ByteString" value="41"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <UniqueIdentifier tag="0x420094" type="TextString"
value="7FJYvnV6XkaUCWuY96bCSc6AuhvkPpqI"/>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>
*/
char *
kms_kmip_response_get_unique_identifier (kms_kmip_response_t *res,
                                         kms_status_t *status)
{
   kmip_reader_t *reader = NULL;
   size_t pos;
   size_t len;
   char *uid = NULL;
   kms_request_str_t *nullterminated = NULL;

   if (!kms_kmip_response_ok (res, status)) {
      goto fail;
   }

   reader = kmip_reader_new (res->data, res->len);
   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponseMessage)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponseMessage));
      goto fail;
   }
   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_BatchItem)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponseMessage));
      goto fail;
   }
   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponsePayload)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponsePayload));
      goto fail;
   }
   if (!kmip_reader_find (reader,
                          KMIP_TAG_UniqueIdentifier,
                          KMIP_ITEM_TYPE_TextString,
                          &pos,
                          &len)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_UniqueIdentifier));
      goto fail;
   }

   if (!kmip_reader_read_string (reader, (uint8_t **) &uid, len)) {
      kms_status_errorf (status, "unable to read unique identifier");
      goto fail;
   }

   nullterminated = kms_request_str_new_from_chars (uid, len);

fail:
   kmip_reader_destroy (reader);
   return kms_request_str_detach (nullterminated);
}

/*
Example successful Response to a Get Request of a SecretData.
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime"
value="2021-10-01T10/01/21-0500"/> <BatchCount tag="0x42000d" type="Integer"
value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <ObjectType tag="0x420057" type="Enumeration" value="7"/>
   <UniqueIdentifier tag="0x420094" type="TextString"
value="VeUgqtuTi4bI8mHXH9CeocbMHLyrXnfF"/> <SecretData tag="0x420085"
type="Structure"> <SecretDataType tag="0x420086" type="Enumeration"
value="2"/> <KeyBlock tag="0x420040" type="Structure"> <KeyFormatType
tag="0x420042" type="Enumeration" value="1"/> <KeyValue tag="0x420045"
type="Structure"> <KeyMaterial tag="0x420043" type="ByteString"
value="ffa8cc79e8c3763b0121fcd06bb3488c8bf42c0774604640279b16b264194030eeb08396241defcc4d32d16ea831ad777138f08e2f985664c004c2485d6f4991eb3d9ec32802537836a9066b4e10aeb56a5ccf6aa46901e625e3400c7811d2ec"/>
     </KeyValue>
    </KeyBlock>
   </SecretData>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>
*/
uint8_t *
kms_kmip_response_get_secretdata (kms_kmip_response_t *res,
                                  uint32_t *secretdatalen,
                                  kms_status_t *status)
{
   kmip_reader_t *reader = NULL;
   size_t pos;
   size_t len;
   uint8_t *secretdata = NULL;
   uint8_t *tmp;

   if (!kms_kmip_response_ok (res, status)) {
      goto fail;
   }

   reader = kmip_reader_new (res->data, res->len);

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponseMessage)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponseMessage));
      goto fail;
   }

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_BatchItem)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponseMessage));
      goto fail;
   }

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponsePayload)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponsePayload));
      goto fail;
   }

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_SecretData)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_SecretData));
      goto fail;
   }

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_KeyBlock)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_KeyBlock));
      goto fail;
   }

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_KeyValue)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_KeyValue));
      goto fail;
   }

   if (!kmip_reader_find (reader,
                          KMIP_TAG_KeyMaterial,
                          KMIP_ITEM_TYPE_ByteString,
                          &pos,
                          &len)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_KeyMaterial));
      goto fail;
   }

   if (!kmip_reader_read_bytes (reader, &tmp, len)) {
      kms_status_errorf (status, "unable to read secretdata bytes");
      goto fail;
   }
   secretdata = malloc (len);
   memcpy (secretdata, tmp, len);
   *secretdatalen = len;

fail:
   kmip_reader_destroy (reader);
   return secretdata;
}

void
kms_kmip_response_destroy (kms_kmip_response_t *res)
{
   if (!res) {
      return;
   }
   free (res->data);
   free (res);
}

/*
Example error response to a Get request:

<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime"
value="2021-10-01T10/01/21-0500"/> <BatchCount tag="0x42000d" type="Integer"
value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="1"/>
  <ResultReason tag="0x42007e" type="Enumeration" value="1"/>
  <ResultMessage tag="0x42007d" type="TextString"
value="ResultReasonItemNotFound"/>
 </BatchItem>
</ResponseMessage>
*/
bool
kms_kmip_response_ok (kms_kmip_response_t *res, kms_status_t *status)
{
#define RESULT_STATUS_SUCCESS 0

   kmip_reader_t *reader = NULL;
   size_t pos;
   size_t len;
   uint32_t result_status;
   uint32_t result_reason = 0;
   char *result_message = "";
   uint32_t result_message_len = 0;
   bool ok = false;

   kms_status_reset (status);
   reader = kmip_reader_new (res->data, res->len);

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponseMessage)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponseMessage));
      goto fail;
   }

   if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_BatchItem)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResponseMessage));
      goto fail;
   }

   /* Look for optional Result Reason. */
   if (kmip_reader_find (reader,
                         KMIP_TAG_ResultReason,
                         KMIP_ITEM_TYPE_Enumeration,
                         &pos,
                         &len)) {
      if (!kmip_reader_read_enumeration (reader, &result_reason)) {
         kms_status_errorf (status, "unable to read result reason value");
         goto fail;
      }
   }

   /* Look for optional Result Message. */
   if (kmip_reader_find (reader,
                         KMIP_TAG_ResultMessage,
                         KMIP_ITEM_TYPE_TextString,
                         &pos,
                         &len)) {
      if (!kmip_reader_read_string (
             reader, (uint8_t **) &result_message, len)) {
         kms_status_errorf (status, "unable to read result message value");
         goto fail;
      }
      result_message_len = len;
   }

   /* Look for required Result Status. */
   if (!kmip_reader_find (reader,
                          KMIP_TAG_ResultStatus,
                          KMIP_ITEM_TYPE_Enumeration,
                          &pos,
                          &len)) {
      kms_status_errorf (status,
                         "unable to find tag: %s",
                         kmip_tag_type_to_string (KMIP_TAG_ResultStatus));
      goto fail;
   }

   if (!kmip_reader_read_enumeration (reader, &result_status)) {
      kms_status_errorf (status, "unable to read result status value");
      goto fail;
   }

   if (result_status != RESULT_STATUS_SUCCESS) {
      kms_status_errorf (status,
                         "KMIP response error. Result Status (%" PRIu32
                         "): %s. Result Reason (%" PRIu32
                         "): %s. Result Message: %.*s",
                         result_status,
                         result_status_to_string (result_status),
                         result_reason,
                         result_reason_to_string (result_reason),
                         result_message_len,
                         result_message);
      goto fail;
   }

   ok = true;
fail:
   kmip_reader_destroy (reader);
   return ok;
#undef RESULT_STATUS_SUCCESS
}