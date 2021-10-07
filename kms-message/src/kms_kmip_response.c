#include "kms_message/kms_kmip_response.h"
#include "kms_kmip_response_private.h"
#include "kms_kmip_reader_writer_private.h"
#include "kms_status_private.h"

#include <stdlib.h>

const uint8_t *
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

char *
kms_kmip_response_get_unique_identifier (kms_kmip_response_t *res,
                                        kms_status_t *status)
{
    kmip_reader_t *reader = NULL;
    kmip_reader_t *reader2 = NULL;
    kmip_reader_t *reader3 = NULL;
    kmip_reader_t *reader4 = NULL;
    size_t pos;
    size_t len;
    char *uid = NULL;
    kms_request_str_t *nullterminated = NULL;

    reader = kmip_reader_new (res->data, res->len);
    reader2 = kmip_reader_find_and_get_struct_reader (reader, KMIP_TAG_ResponseMessage);
    if (!reader2) {
        kms_status_errorf (status, "unable to find tag1: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    reader3 = kmip_reader_find_and_get_struct_reader (reader2, KMIP_TAG_BatchItem);
    if (!reader3) {
        kms_status_errorf (status, "unable to find tag2: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    reader4 = kmip_reader_find_and_get_struct_reader (reader3, KMIP_TAG_ResponsePayload);
    if (!reader4) {
        kms_status_errorf (status, "unable to find tag3: %s", kmip_tag_to_string (KMIP_TAG_ResponsePayload));
        goto fail;
    }
    if (!kmip_reader_find (reader4, KMIP_TAG_UniqueIdentifier, KMIP_ITEM_TYPE_TextString, &pos, &len)) {
        kms_status_errorf (status, "unable to find tag4: %s", kmip_tag_to_string (KMIP_TAG_UniqueIdentifier));
        goto fail;
    }

    if (!kmip_reader_read_string (reader4, (uint8_t**) &uid, len)) {
        kms_status_errorf (status, "unable to read unique identifier");
        goto fail;
    }

    nullterminated = kms_request_str_new_from_chars (uid, len);

fail:
    kmip_reader_destroy (reader4);
    kmip_reader_destroy (reader3);
    kmip_reader_destroy (reader2);
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
    kmip_reader_t *reader2 = NULL;
    kmip_reader_t *reader3 = NULL;
    kmip_reader_t *reader4 = NULL;
    kmip_reader_t *reader5 = NULL;
    kmip_reader_t *reader6 = NULL;
    kmip_reader_t *reader7 = NULL;
    size_t pos;
    size_t len;
    uint8_t *secretdata = NULL;
    uint8_t *tmp;

    reader = kmip_reader_new (res->data, res->len);
    reader2 = kmip_reader_find_and_get_struct_reader (reader, KMIP_TAG_ResponseMessage);
    if (!reader2) {
        kms_status_errorf (status, "unable to find tag1: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    reader3 = kmip_reader_find_and_get_struct_reader (reader2, KMIP_TAG_BatchItem);
    if (!reader3) {
        kms_status_errorf (status, "unable to find tag2: %s", kmip_tag_to_string (KMIP_TAG_ResponseMessage));
        goto fail;
    }
    reader4 = kmip_reader_find_and_get_struct_reader (reader3, KMIP_TAG_ResponsePayload);
    if (!reader4) {
        kms_status_errorf (status, "unable to find tag3: %s", kmip_tag_to_string (KMIP_TAG_ResponsePayload));
        goto fail;
    }
    reader5 = kmip_reader_find_and_get_struct_reader (reader4, KMIP_TAG_SecretData);
    if (!reader5) {
        kms_status_errorf (status, "unable to find tag4: %s", kmip_tag_to_string (KMIP_TAG_SecretData));
        goto fail;
    }
    reader6 = kmip_reader_find_and_get_struct_reader (reader5, KMIP_TAG_KeyBlock);
    if (!reader6) {
        kms_status_errorf (status, "unable to find tag5: %s", kmip_tag_to_string (KMIP_TAG_KeyBlock));
        goto fail;
    }
    reader7 = kmip_reader_find_and_get_struct_reader (reader6, KMIP_TAG_KeyValue);
    if (!reader7) {
        kms_status_errorf (status, "unable to find tag6: %s", kmip_tag_to_string (KMIP_TAG_KeyValue));
        goto fail;
    }

    if (!kmip_reader_find (reader7, KMIP_TAG_KeyMaterial, KMIP_ITEM_TYPE_ByteString, &pos, &len)) {
        kms_status_errorf (status, "unable to find tag7: %s", kmip_tag_to_string (KMIP_TAG_KeyMaterial));
        goto fail;
    }

    if (!kmip_reader_read_bytes (reader7, &tmp, len)) {
        kms_status_errorf (status, "unable to read secretdata bytes");
        goto fail;
    }
    secretdata = malloc (len);
    memcpy (secretdata, tmp, len);
    *secretdatalen = len;

fail:
    kmip_reader_destroy (reader7);
    kmip_reader_destroy (reader6);
    kmip_reader_destroy (reader5);
    kmip_reader_destroy (reader4);
    kmip_reader_destroy (reader3);
    kmip_reader_destroy (reader2);
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
