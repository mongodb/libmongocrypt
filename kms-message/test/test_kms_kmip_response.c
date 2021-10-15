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

#include "test_kms_assert.h"
#include "test_kms_util.h"

#include "kms_message/kms_kmip_response.h"
#include "kms_message_private.h"


/*
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="0"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2021-10-12T14:09:25-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="3"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <UniqueIdentifier tag="0x420094" type="TextString" value="39"/>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>
*/
static const uint8_t SUCCESS_REGISTER_RESPONSE[] = {
   0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x00, 0x90, 0x42, 0x00, 0x7a, 0x01, 0x00,
   0x00, 0x00, 0x48, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00,
   0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00,
   0x00, 0x00, 0x00, 0x61, 0x65, 0x97, 0x15, 0x42, 0x00, 0x0d, 0x02, 0x00, 0x00,
   0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
   0x01, 0x00, 0x00, 0x00, 0x38, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, 0x00,
   0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
   0x7c, 0x01, 0x00, 0x00, 0x00, 0x10, 0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00,
   0x02, 0x33, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const char *const SUCCESS_REGISTER_RESPONSE_UNIQUE_IDENTIFIER = "39";

void
kms_kmip_response_get_unique_identifier_test (void)
{
   kms_response_t res = {0};
   char *actual_uid;

   res.provider = KMS_REQUEST_PROVIDER_KMIP;
   res.kmip.data = (uint8_t*) SUCCESS_REGISTER_RESPONSE;
   res.kmip.len = sizeof (SUCCESS_REGISTER_RESPONSE);

   actual_uid = kms_kmip_response_get_unique_identifier (&res);
   ASSERT_RESPONSE_OK (&res);
   ASSERT_CMPSTR (SUCCESS_REGISTER_RESPONSE_UNIQUE_IDENTIFIER, actual_uid);
   free (actual_uid);
}


/*
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2021-10-12T14:09:25-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <ObjectType tag="0x420057" type="Enumeration" value="7"/>
   <UniqueIdentifier tag="0x420094" type="TextString" value="39"/>
   <SecretData tag="0x420085" type="Structure">
    <SecretDataType tag="0x420086" type="Enumeration" value="1"/>
    <KeyBlock tag="0x420040" type="Structure">
     <KeyFormatType tag="0x420042" type="Enumeration" value="2"/>
     <KeyValue tag="0x420045" type="Structure">
      <KeyMaterial tag="0x420043" type="ByteString"
value="ffa8cc79e8c3763b0121fcd06bb3488c8bf42c0774604640279b16b264194030eeb08396241defcc4d32d16ea831ad777138f08e2f985664c004c2485d6f4991eb3d9ec32802537836a9066b4e10aeb56a5ccf6aa46901e625e3400c7811d2ec"/>
     </KeyValue>
    </KeyBlock>
   </SecretData>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>
*/
static const uint8_t SUCCESS_GET_RESPONSE[] = {
   0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x01, 0x40, 0x42, 0x00, 0x7a, 0x01, 0x00,
   0x00, 0x00, 0x48, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00,
   0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00,
   0x00, 0x00, 0x00, 0x61, 0x65, 0x97, 0x15, 0x42, 0x00, 0x0d, 0x02, 0x00, 0x00,
   0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
   0x01, 0x00, 0x00, 0x00, 0xe8, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, 0x00,
   0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
   0x7c, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x42, 0x00, 0x57, 0x05, 0x00, 0x00, 0x00,
   0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x94, 0x07,
   0x00, 0x00, 0x00, 0x02, 0x33, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
   0x00, 0x85, 0x01, 0x00, 0x00, 0x00, 0x98, 0x42, 0x00, 0x86, 0x05, 0x00, 0x00,
   0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x40,
   0x01, 0x00, 0x00, 0x00, 0x80, 0x42, 0x00, 0x42, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x45, 0x01, 0x00,
   0x00, 0x00, 0x68, 0x42, 0x00, 0x43, 0x08, 0x00, 0x00, 0x00, 0x60, 0xff, 0xa8,
   0xcc, 0x79, 0xe8, 0xc3, 0x76, 0x3b, 0x01, 0x21, 0xfc, 0xd0, 0x6b, 0xb3, 0x48,
   0x8c, 0x8b, 0xf4, 0x2c, 0x07, 0x74, 0x60, 0x46, 0x40, 0x27, 0x9b, 0x16, 0xb2,
   0x64, 0x19, 0x40, 0x30, 0xee, 0xb0, 0x83, 0x96, 0x24, 0x1d, 0xef, 0xcc, 0x4d,
   0x32, 0xd1, 0x6e, 0xa8, 0x31, 0xad, 0x77, 0x71, 0x38, 0xf0, 0x8e, 0x2f, 0x98,
   0x56, 0x64, 0xc0, 0x04, 0xc2, 0x48, 0x5d, 0x6f, 0x49, 0x91, 0xeb, 0x3d, 0x9e,
   0xc3, 0x28, 0x02, 0x53, 0x78, 0x36, 0xa9, 0x06, 0x6b, 0x4e, 0x10, 0xae, 0xb5,
   0x6a, 0x5c, 0xcf, 0x6a, 0xa4, 0x69, 0x01, 0xe6, 0x25, 0xe3, 0x40, 0x0c, 0x78,
   0x11, 0xd2, 0xec};

static const uint8_t SUCCESS_GET_RESPONSE_SECRETDATA[] = {
   0xff, 0xa8, 0xcc, 0x79, 0xe8, 0xc3, 0x76, 0x3b, 0x01, 0x21, 0xfc, 0xd0,
   0x6b, 0xb3, 0x48, 0x8c, 0x8b, 0xf4, 0x2c, 0x07, 0x74, 0x60, 0x46, 0x40,
   0x27, 0x9b, 0x16, 0xb2, 0x64, 0x19, 0x40, 0x30, 0xee, 0xb0, 0x83, 0x96,
   0x24, 0x1d, 0xef, 0xcc, 0x4d, 0x32, 0xd1, 0x6e, 0xa8, 0x31, 0xad, 0x77,
   0x71, 0x38, 0xf0, 0x8e, 0x2f, 0x98, 0x56, 0x64, 0xc0, 0x04, 0xc2, 0x48,
   0x5d, 0x6f, 0x49, 0x91, 0xeb, 0x3d, 0x9e, 0xc3, 0x28, 0x02, 0x53, 0x78,
   0x36, 0xa9, 0x06, 0x6b, 0x4e, 0x10, 0xae, 0xb5, 0x6a, 0x5c, 0xcf, 0x6a,
   0xa4, 0x69, 0x01, 0xe6, 0x25, 0xe3, 0x40, 0x0c, 0x78, 0x11, 0xd2, 0xec};

void
kms_kmip_response_get_secretdata_test (void)
{
   kms_response_t res = {0};
   uint8_t *actual_secretdata;
   size_t actual_secretdata_len;

   res.provider = KMS_REQUEST_PROVIDER_KMIP;
   res.kmip.data = (uint8_t*) SUCCESS_GET_RESPONSE;
   res.kmip.len = sizeof (SUCCESS_GET_RESPONSE);

   actual_secretdata =
      kms_kmip_response_get_secretdata (&res, &actual_secretdata_len);
   ASSERT_RESPONSE_OK (&res);
   ASSERT_CMPBYTES (SUCCESS_GET_RESPONSE_SECRETDATA,
                    sizeof (SUCCESS_GET_RESPONSE_SECRETDATA),
                    actual_secretdata,
                    actual_secretdata_len);
   free (actual_secretdata);
}

/*
<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="4"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2021-10-01T14:43:13-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
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
static const uint8_t ERROR_GET_RESPOSE_NOTFOUND[] = {
   0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x00, 0xa8, 0x42, 0x00, 0x7a, 0x01, 0x00,
   0x00, 0x00, 0x48, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00,
   0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00,
   0x00, 0x00, 0x00, 0x61, 0x57, 0x1e, 0x81, 0x42, 0x00, 0x0d, 0x02, 0x00, 0x00,
   0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
   0x01, 0x00, 0x00, 0x00, 0x50, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04,
   0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, 0x00,
   0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
   0x7e, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x42, 0x00, 0x7d, 0x07, 0x00, 0x00, 0x00, 0x18, 0x52, 0x65, 0x73, 0x75,
   0x6c, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x49, 0x74, 0x65, 0x6d, 0x4e,
   0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64};

void
kms_kmip_response_get_secretdata_notfound_test (void)
{
   kms_response_t res = {0};
   uint8_t *secretdata;
   size_t secretdata_len;

   res.provider = KMS_REQUEST_PROVIDER_KMIP;
   res.kmip.data = (uint8_t*) ERROR_GET_RESPOSE_NOTFOUND;
   res.kmip.len = sizeof (ERROR_GET_RESPOSE_NOTFOUND);

   secretdata = kms_kmip_response_get_secretdata (&res, &secretdata_len);
   ASSERT_RESPONSE_ERROR (&res, "ResultReasonItemNotFound");
   ASSERT (NULL == secretdata);
}
