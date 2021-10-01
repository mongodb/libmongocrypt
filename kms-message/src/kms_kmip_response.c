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
 tag=ResponseMessage (42007b) type=Structure (01) length=288
  tag=ResponseHeader (42007a) type=Structure (01) length=72
   tag=ProtocolVersion (420069) type=Structure (01) length=32
    tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
    tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=4
   tag=TimeStamp (420092) type=DateTime (09) length=8 value=(TODO)
   tag=BatchCount (42000d) type=Integer (02) length=4 value=1
  tag=BatchItem (42000f) type=Structure (01) length=96
   tag=Operation (42005c) type=Enumeration (05) length=4 value=3
   tag=UniqueBatchItemID (420093) type=ByteString (08) length=1 value=A
   tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=0
   tag=ResponsePayload (42007c) type=Structure (01) length=40
    tag=UniqueIdentifier (420094) type=TextString (07) length=32 value=7FJYvnV6XkaUCWuY96bCSc6AuhvkPpqI
  tag=BatchItem (42000f) type=Structure (01) length=96 tag=Operation (42005c) type=Enumeration (05) length=4 value=18
   tag=UniqueBatchItemID (420093) type=ByteString (08) length=1 value=(TODO)
   tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=0
   tag=ResponsePayload (42007c) type=Structure (01) length=40
    tag=UniqueIdentifier (420094) type=TextString (07) length=32 value=7FJYvnV6XkaUCWuY96bCSc6AuhvkPpqI
 */

const char* kmip_tag_to_string (kmip_tag_type_t tag) {
    return "TODO";
}

const char* kmip_result_reason_to_string (uint32_t result_reason) {
    return "TODO";
}

const char* kmip_result_status_to_string (uint32_t result_status) {
    return "TODO";
}

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
        kms_status_errorf (status, "unable to find tag1: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_BatchItem)) {
        kms_status_errorf (status, "unable to find tag2: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponsePayload)) {
        kms_status_errorf (status, "unable to find tag3: %s", kmip_tag_to_string (KMIP_TAG_ResponsePayload));
        goto fail;
    }
    if (!kmip_reader_find (reader, KMIP_TAG_UniqueIdentifier, KMIP_ITEM_TYPE_TextString, &pos, &len)) {
        kms_status_errorf (status, "unable to find tag4: %s", kmip_tag_to_string (KMIP_TAG_UniqueIdentifier));
        goto fail;
    }

    if (!kmip_reader_read_string (reader, (uint8_t**) &uid, len)) {
        kms_status_errorf (status, "unable to read unique identifier");
        goto fail;
    }

    nullterminated = kms_request_str_new_from_chars (uid, len);

fail:
    kmip_reader_destroy (reader);
    return kms_request_str_detach (nullterminated);
}

/*
tag=ResponseMessage (42007b) type=Structure (01) length=320
 tag=ResponseHeader (42007a) type=Structure (01) length=72
  tag=ProtocolVersion (420069) type=Structure (01) length=32
   tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
   tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=4
  tag=TimeStamp (420092) type=DateTime (09) length=8 value=(TODO)
  tag=BatchCount (42000d) type=Integer (02) length=4 value=1
 tag=BatchItem (42000f) type=Structure (01) length=232
  tag=Operation (42005c) type=Enumeration (05) length=4 value=10
  tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=0
  tag=ResponsePayload (42007c) type=Structure (01) length=192
   tag=ObjectType (420057) type=Enumeration (05) length=4 value=7
   tag=UniqueIdentifier (420094) type=TextString (07) length=2 value=31
   tag=SecretData (420085) type=Structure (01) length=152
    tag=SecretDataType (420086) type=Enumeration (05) length=4 value=2
    tag=KeyBlock (420040) type=Structure (01) length=128
     tag=KeyFormatType (420042) type=Enumeration (05) length=4 value=2
     tag=KeyValue (420045) type=Structure (01) length=104
      tag=KeyMaterial (420043) type=ByteString (08) length=96 value=(TODO) 
*/
uint8_t*
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
        kms_status_errorf (status, "unable to find tag1: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_BatchItem)) {
        kms_status_errorf (status, "unable to find tag2: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_ResponsePayload)) {
        kms_status_errorf (status, "unable to find tag3: %s", kmip_tag_to_string (KMIP_TAG_ResponsePayload));
        goto fail;
    }
    
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_SecretData)) {
        kms_status_errorf (status, "unable to find tag4: %s", kmip_tag_to_string (KMIP_TAG_SecretData));
        goto fail;
    }
    
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_KeyBlock)) {
        kms_status_errorf (status, "unable to find tag5: %s", kmip_tag_to_string (KMIP_TAG_KeyBlock));
        goto fail;
    }
    
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_KeyValue)) {
        kms_status_errorf (status, "unable to find tag6: %s", kmip_tag_to_string (KMIP_TAG_KeyValue));
        goto fail;
    }

    if (!kmip_reader_find (reader, KMIP_TAG_KeyMaterial, KMIP_ITEM_TYPE_ByteString, &pos, &len)) {
        kms_status_errorf (status, "unable to find tag7: %s", kmip_tag_to_string (KMIP_TAG_KeyMaterial));
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
tag=ResponseMessage (42007b) type=Structure (01) length=168
 tag=ResponseHeader (42007a) type=Structure (01) length=72
  tag=ProtocolVersion (420069) type=Structure (01) length=32
   tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
   tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=4
  tag=TimeStamp (420092) type=DateTime (09) length=8 value=(TODO)
  tag=BatchCount (42000d) type=Integer (02) length=4 value=1
 tag=BatchItem (42000f) type=Structure (01) length=80
  tag=Operation (42005c) type=Enumeration (05) length=4 value=10
  tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=1
  tag=ResultReason (42007e) type=Enumeration (05) length=4 value=1
  tag=ResultMessage (42007d) type=TextString (07) length=24 value=ResultReasonItemNotFound
*/
bool
kms_kmip_response_ok (kms_kmip_response_t *res, kms_status_t *status) {
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
        kms_status_errorf (status, "unable to find tag1: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    
    if (!kmip_reader_find_and_recurse (reader, KMIP_TAG_BatchItem)) {
        kms_status_errorf (status, "unable to find tag2: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }

    /* Look for optional Result Reason. */
    if (kmip_reader_find (reader, KMIP_TAG_ResultReason, KMIP_ITEM_TYPE_Enumeration, &pos, &len)) {
        if (!kmip_reader_read_enumeration (reader, &result_reason)) {
            kms_status_errorf (status, "unable to read result reason value");
            goto fail;
        }
    }

    /* Look for optional Result Message. */
    if (kmip_reader_find (reader, KMIP_TAG_ResultMessage, KMIP_ITEM_TYPE_TextString, &pos, &len)) {
        if (!kmip_reader_read_string (reader, (uint8_t**) &result_message, len)) {
            kms_status_errorf (status, "unable to read result message value");
            goto fail;
        }
        result_message_len = len;
    }
    
    /* Look for required Result Status. */
    if (!kmip_reader_find (reader, KMIP_TAG_ResultStatus, KMIP_ITEM_TYPE_Enumeration, &pos, &len)) {
        kms_status_errorf (status, "unable to find tag3: %s", kmip_tag_to_string (KMIP_TAG_ResultStatus));
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
                          kmip_result_status_to_string (result_status),
                          result_reason,
                          kmip_result_reason_to_string (result_reason),
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