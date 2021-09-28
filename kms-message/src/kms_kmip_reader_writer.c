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

#include "kms_kmip_reader_writer_private.h"

#include "kms_endian_private.h"
#include "kms_request_str.h"

#include <stdint.h>

#define MAX_KMIP_WRITER_POSITIONS 10

/* KMIP encodes signed integers with two's complement.
 * Parsing functions read Integer / LongInteger as int32_t / int64_t by
 * reinterpreting byte representation.
 * Ensure that platform represents integers in two's complement.
 * See: https://stackoverflow.com/a/64843863/774658 */
#if (-1 & 3) != 3
#error Error: Twos complement integer representation is required.
#endif

struct _kmip_writer_t {
   kms_request_str_t *buffer;

   size_t positions[MAX_KMIP_WRITER_POSITIONS];
   size_t cur_pos;
};

kmip_writer_t *
kmip_writer_new (void)
{
   kmip_writer_t *writer = calloc (1, sizeof (kmip_writer_t));
   writer->buffer = kms_request_str_new ();
   return writer;
}

void
kmip_writer_destroy (kmip_writer_t *writer)
{
   kms_request_str_destroy (writer->buffer);
   free (writer);
}

void
kmip_writer_write_u8 (kmip_writer_t *writer, uint8_t value)
{
   char *c = (char *) &value;

   kms_request_str_append_chars (writer->buffer, c, 1);
}

void
kmip_writer_write_u16 (kmip_writer_t *writer, uint16_t value)
{
   uint16_t v = KMS_UINT16_TO_BE (value);
   char *c = (char *) &v;

   kms_request_str_append_chars (writer->buffer, c, 2);
}

void
kmip_writer_write_u32 (kmip_writer_t *writer, uint32_t value)
{
   uint32_t v = KMS_UINT32_TO_BE (value);
   char *c = (char *) &v;

   kms_request_str_append_chars (writer->buffer, c, 4);
}

void
kmip_writer_write_u64 (kmip_writer_t *writer, uint64_t value)
{
   uint64_t v = KMS_UINT64_TO_BE (value);
   char *c = (char *) &v;

   kms_request_str_append_chars (writer->buffer, c, 8);
}

void
kmip_writer_write_tag_enum (kmip_writer_t *writer, kmip_tag_type_t tag)
{
   /* The 0x42 prefix is for tags built into the protocol. */
   /* The 0x54 prefix is for extension tags. */
   kmip_writer_write_u8 (writer, 0x42);
   kmip_writer_write_u16 (writer, (uint16_t) tag);
}

static size_t
compute_padded_length (size_t len)
{
   if (len % 8 == 0) {
      return len;
   }

   size_t padding = 8 - (len % 8);
   return len + padding;
}

void
kmip_writer_write_string (kmip_writer_t *writer, kmip_tag_type_t tag, const char *str, size_t len)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_TextString);
   kmip_writer_write_u32 (writer, (uint32_t) len);

   size_t i;
   for (i = 0; i < len; i++) {
      kmip_writer_write_u8 (writer, str[i]);
   }

   size_t padded_length = compute_padded_length (len);
   for (i = 0; i < padded_length - len; i++) {
      kmip_writer_write_u8 (writer, 0);
   }
}

void
kmip_writer_write_bytes (kmip_writer_t *writer, kmip_tag_type_t tag, const char *str, size_t len)
{
   kmip_writer_write_tag_enum (writer, tag);

   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_ByteString);
   kmip_writer_write_u32 (writer, (uint32_t) len);

   size_t i;
   for (i = 0; i < len; i++) {
      kmip_writer_write_u8 (writer, str[i]);
   }

   size_t padded_length = compute_padded_length (len);
   for (i = 0; i < padded_length - len; i++) {
      kmip_writer_write_u8 (writer, 0);
   }
}

void
kmip_writer_write_integer (kmip_writer_t *writer, kmip_tag_type_t tag, int32_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_Integer);
   kmip_writer_write_u32 (writer, 4);
   kmip_writer_write_u32 (writer, value);
   kmip_writer_write_u32 (writer, 0);
}

void
kmip_writer_write_long_integer (kmip_writer_t *writer, kmip_tag_type_t tag, int64_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_LongInteger);
   kmip_writer_write_u32 (writer, 8);
   kmip_writer_write_u64 (writer, value);
}

void
kmip_writer_write_enumeration (kmip_writer_t *writer, kmip_tag_type_t tag, int32_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_Enumeration);
   kmip_writer_write_u32 (writer, 4);
   kmip_writer_write_u32 (writer, value);
   kmip_writer_write_u32 (writer, 0);
}

void
kmip_writer_write_datetime (kmip_writer_t *writer, kmip_tag_type_t tag, int64_t value)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_DateTime);
   kmip_writer_write_u32 (writer, 8);
   kmip_writer_write_u64 (writer, value);
}

void
kmip_writer_begin_struct (kmip_writer_t *writer, kmip_tag_type_t tag)
{
   kmip_writer_write_tag_enum (writer, tag);
   kmip_writer_write_u8 (writer, KMIP_ITEM_TYPE_Structure);

   size_t pos = writer->buffer->len;

   kmip_writer_write_u32 (writer, 0);
   KMS_ASSERT(writer->cur_pos < MAX_KMIP_WRITER_POSITIONS);
   writer->cur_pos++;
   writer->positions[writer->cur_pos] = pos;
}

void
kmip_writer_close_struct (kmip_writer_t *writer)
{
   size_t current_pos = writer->buffer->len;
   KMS_ASSERT(writer->cur_pos > 0);
   size_t start_pos = writer->positions[writer->cur_pos];
   writer->cur_pos--;
   /* offset by 4 */
   uint32_t len = (uint32_t) (current_pos - start_pos - 4);

   uint32_t v = KMS_UINT32_TO_BE (len);
   char *c = (char *) &v;
   memcpy (writer->buffer->str + start_pos, c, 4);
}

const uint8_t *
kmip_writer_get_buffer (kmip_writer_t *writer, size_t* len) {
   *len = writer->buffer->len;
   return (const uint8_t*) writer->buffer->str;
}

struct _kmip_reader_t {
   uint8_t *ptr;
   size_t pos;
   size_t len;
};

kmip_reader_t *
kmip_reader_new (uint8_t *ptr, size_t len)
{
   kmip_reader_t *reader = calloc (1, sizeof (kmip_reader_t));
   reader->ptr = ptr;
   reader->len = len;
   return reader;
}

void
kmip_reader_destroy (kmip_reader_t *reader)
{
   free (reader);
}

bool
kmip_reader_in_place (kmip_reader_t *reader,
                      size_t pos,
                      size_t len,
                      kmip_reader_t *out_reader)
{
   /* Everything should be padding to 8 byte boundaries. */
   len = compute_padded_length (len);
   if ((pos + len) > reader->len) {
      return false;
   }

   memset (out_reader, 0, sizeof (kmip_reader_t));
   out_reader->ptr = reader->ptr + reader->pos;
   out_reader->len = len;
   return true;
}

bool
kmip_reader_has_data (kmip_reader_t *reader)
{
   return reader->pos < reader->len;
}

#define CHECK_REMAINING_BUFFER_AND_RET(read_size)   \
   if ((reader->pos + (read_size)) > reader->len) { \
      return false;                                 \
   }

bool
kmip_reader_read_u8 (kmip_reader_t *reader, uint8_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint8_t));

   *value = *(reader->ptr + reader->pos);
   reader->pos += sizeof (uint8_t);

   return true;
}

bool
kmip_reader_read_u16 (kmip_reader_t *reader, uint16_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint16_t));

   uint16_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint16_t));
   *value = KMS_UINT16_FROM_BE (temp);
   reader->pos += sizeof (uint16_t);

   return true;
}

bool
kmip_reader_read_u32 (kmip_reader_t *reader, uint32_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint32_t));

   uint32_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint32_t));
   *value = KMS_UINT32_FROM_BE (temp);
   reader->pos += sizeof (uint32_t);

   return true;
}

bool
kmip_reader_read_u64 (kmip_reader_t *reader, uint64_t *value)
{
   CHECK_REMAINING_BUFFER_AND_RET (sizeof (uint64_t));

   uint64_t temp;
   memcpy (&temp, reader->ptr + reader->pos, sizeof (uint64_t));
   *value = KMS_UINT64_FROM_BE (temp);
   reader->pos += sizeof (uint64_t);

   return true;
}

bool
kmip_reader_read_bytes (kmip_reader_t *reader, uint8_t **ptr, size_t length)
{
   size_t advance_length = compute_padded_length (length);
   CHECK_REMAINING_BUFFER_AND_RET (advance_length);

   *ptr = reader->ptr + reader->pos;
   reader->pos += advance_length;

   return true;
}

#define CHECK_AND_RET(x) \
   if (!(x)) {           \
      return false;      \
   }

bool
kmip_reader_read_tag (kmip_reader_t *reader, kmip_tag_type_t *tag)
{
   uint8_t tag_first;

   CHECK_AND_RET (kmip_reader_read_u8 (reader, &tag_first));

   if (tag_first != 0x42) {
      return false;
   }

   uint16_t tag_second;
   CHECK_AND_RET (kmip_reader_read_u16 (reader, &tag_second));

   *tag = (kmip_tag_type_t) (0x420000 + tag_second);
   return true;
}

bool
kmip_reader_read_length (kmip_reader_t *reader, uint32_t *length)
{
   return kmip_reader_read_u32 (reader, length);
}

bool
kmip_reader_read_type (kmip_reader_t *reader, kmip_item_type_t *type)
{
   uint8_t u8;
   CHECK_AND_RET (kmip_reader_read_u8 (reader, &u8));
   *type = (kmip_item_type_t) u8;
   return true;
}

bool
kmip_reader_read_enumeration (kmip_reader_t *reader, uint32_t *enum_value)
{
   CHECK_AND_RET (kmip_reader_read_u32 (reader, enum_value));

   /* Skip 4 bytes because enums are padded. */
   uint32_t ignored;

   return kmip_reader_read_u32 (reader, &ignored);
}

bool
kmip_reader_read_integer (kmip_reader_t *reader, int32_t *value)
{
   CHECK_AND_RET (kmip_reader_read_u32 (reader, (uint32_t*) value));

   /* Skip 4 bytes because integers are padded. */
   uint32_t ignored;

   return kmip_reader_read_u32 (reader, &ignored);
}

bool
kmip_reader_read_long_integer (kmip_reader_t *reader, int64_t *value)
{
   return kmip_reader_read_u64 (reader, (uint64_t*) value);
}

bool
kmip_reader_read_string (kmip_reader_t *reader, uint8_t **ptr, size_t length)
{
   return kmip_reader_read_bytes (reader, ptr, length);
}

bool
kmip_reader_find (kmip_reader_t *reader,
                  kmip_tag_type_t search_tag,
                  kmip_item_type_t type,
                  size_t *pos,
                  size_t *length)
{
   reader->pos = 0;

   while (kmip_reader_has_data (reader)) {
      kmip_tag_type_t read_tag;
      CHECK_AND_RET (kmip_reader_read_tag (reader, &read_tag));

      kmip_item_type_t read_type;
      CHECK_AND_RET (kmip_reader_read_type (reader, &read_type));

      uint32_t read_length;
      CHECK_AND_RET (kmip_reader_read_length (reader, &read_length));


      if (read_tag == search_tag && read_type == type) {
         *pos = reader->pos;
         *length = read_length;
         return true;
      }

      size_t advance_length = read_length;
      advance_length = compute_padded_length (advance_length);

      CHECK_REMAINING_BUFFER_AND_RET (advance_length);

      /* Skip to the next type. */
      reader->pos += advance_length;
   }

   return false;
}

kmip_reader_t *
kmip_reader_find_and_get_struct_reader (kmip_reader_t *reader, size_t tag)
{
   size_t pos;
   size_t length;

   if (!kmip_reader_find (reader, tag, KMIP_ITEM_TYPE_Structure, &pos, &length)) {
      return NULL;
   }

   return kmip_reader_new (reader->ptr + pos, length);
}

bool
kmip_reader_find_and_read_enum (kmip_reader_t *reader,
                                size_t tag,
                                uint32_t *value)
{
   size_t pos;
   size_t length;

   if (!kmip_reader_find (reader, tag, KMIP_ITEM_TYPE_Enumeration, &pos, &length)) {
      return false;
   }

   kmip_reader_t temp_reader;
   if (!kmip_reader_in_place (reader, pos, length, &temp_reader)) {
      return false;
   }

   return kmip_reader_read_enumeration (&temp_reader, value);
}

bool
kmip_reader_find_and_read_bytes (kmip_reader_t *reader,
                                 size_t tag,
                                 uint8_t **out_ptr,
                                 size_t *out_len)
{
   size_t pos;

   if (!kmip_reader_find (reader, tag, KMIP_ITEM_TYPE_ByteString, &pos, out_len)) {
      return false;
   }

   kmip_reader_t temp_reader;
   if (!kmip_reader_in_place (reader, pos, *out_len, &temp_reader)) {
      return false;
   }

   return kmip_reader_read_bytes (&temp_reader, out_ptr, *out_len);
}

#include <inttypes.h>

static const char *
kmip_tag_type_to_string (kmip_tag_type_t tag)
{
   switch (tag) {
   case KMIP_TAG_ActivationDate:
      return "ActivationDate";
   case KMIP_TAG_ApplicationData:
      return "ApplicationData";
   case KMIP_TAG_ApplicationNamespace:
      return "ApplicationNamespace";
   case KMIP_TAG_ApplicationSpecificInformation:
      return "ApplicationSpecificInformation";
   case KMIP_TAG_ArchiveDate:
      return "ArchiveDate";
   case KMIP_TAG_AsynchronousCorrelationValue:
      return "AsynchronousCorrelationValue";
   case KMIP_TAG_AsynchronousIndicator:
      return "AsynchronousIndicator";
   case KMIP_TAG_Attribute:
      return "Attribute";
   case KMIP_TAG_AttributeIndex:
      return "AttributeIndex";
   case KMIP_TAG_AttributeName:
      return "AttributeName";
   case KMIP_TAG_AttributeValue:
      return "AttributeValue";
   case KMIP_TAG_Authentication:
      return "Authentication";
   case KMIP_TAG_BatchCount:
      return "BatchCount";
   case KMIP_TAG_BatchErrorContinuationOption:
      return "BatchErrorContinuationOption";
   case KMIP_TAG_BatchItem:
      return "BatchItem";
   case KMIP_TAG_BatchOrderOption:
      return "BatchOrderOption";
   case KMIP_TAG_BlockCipherMode:
      return "BlockCipherMode";
   case KMIP_TAG_CancellationResult:
      return "CancellationResult";
   case KMIP_TAG_Certificate:
      return "Certificate";
   case KMIP_TAG_CertificateIdentifier:
      return "CertificateIdentifier";
   case KMIP_TAG_CertificateIssuer:
      return "CertificateIssuer";
   case KMIP_TAG_CertificateIssuerAlternativeName:
      return "CertificateIssuerAlternativeName";
   case KMIP_TAG_CertificateIssuerDistinguishedName:
      return "CertificateIssuerDistinguishedName";
   case KMIP_TAG_CertificateRequest:
      return "CertificateRequest";
   case KMIP_TAG_CertificateRequestType:
      return "CertificateRequestType";
   case KMIP_TAG_CertificateSubject:
      return "CertificateSubject";
   case KMIP_TAG_CertificateSubjectAlternativeName:
      return "CertificateSubjectAlternativeName";
   case KMIP_TAG_CertificateSubjectDistinguishedName:
      return "CertificateSubjectDistinguishedName";
   case KMIP_TAG_CertificateType:
      return "CertificateType";
   case KMIP_TAG_CertificateValue:
      return "CertificateValue";
   case KMIP_TAG_CommonTemplateAttribute:
      return "CommonTemplateAttribute";
   case KMIP_TAG_CompromiseDate:
      return "CompromiseDate";
   case KMIP_TAG_CompromiseOccurrenceDate:
      return "CompromiseOccurrenceDate";
   case KMIP_TAG_ContactInformation:
      return "ContactInformation";
   case KMIP_TAG_Credential:
      return "Credential";
   case KMIP_TAG_CredentialType:
      return "CredentialType";
   case KMIP_TAG_CredentialValue:
      return "CredentialValue";
   case KMIP_TAG_CriticalityIndicator:
      return "CriticalityIndicator";
   case KMIP_TAG_CRTCoefficient:
      return "CRTCoefficient";
   case KMIP_TAG_CryptographicAlgorithm:
      return "CryptographicAlgorithm";
   case KMIP_TAG_CryptographicDomainParameters:
      return "CryptographicDomainParameters";
   case KMIP_TAG_CryptographicLength:
      return "CryptographicLength";
   case KMIP_TAG_CryptographicParameters:
      return "CryptographicParameters";
   case KMIP_TAG_CryptographicUsageMask:
      return "CryptographicUsageMask";
   case KMIP_TAG_CustomAttribute:
      return "CustomAttribute";
   case KMIP_TAG_D:
      return "D";
   case KMIP_TAG_DeactivationDate:
      return "DeactivationDate";
   case KMIP_TAG_DerivationData:
      return "DerivationData";
   case KMIP_TAG_DerivationMethod:
      return "DerivationMethod";
   case KMIP_TAG_DerivationParameters:
      return "DerivationParameters";
   case KMIP_TAG_DestroyDate:
      return "DestroyDate";
   case KMIP_TAG_Digest:
      return "Digest";
   case KMIP_TAG_DigestValue:
      return "DigestValue";
   case KMIP_TAG_EncryptionKeyInformation:
      return "EncryptionKeyInformation";
   case KMIP_TAG_G:
      return "G";
   case KMIP_TAG_HashingAlgorithm:
      return "HashingAlgorithm";
   case KMIP_TAG_InitialDate:
      return "InitialDate";
   case KMIP_TAG_InitializationVector:
      return "InitializationVector";
   case KMIP_TAG_Issuer:
      return "Issuer";
   case KMIP_TAG_IterationCount:
      return "IterationCount";
   case KMIP_TAG_IVCounterNonce:
      return "IVCounterNonce";
   case KMIP_TAG_J:
      return "J";
   case KMIP_TAG_Key:
      return "Key";
   case KMIP_TAG_KeyBlock:
      return "KeyBlock";
   case KMIP_TAG_KeyCompressionType:
      return "KeyCompressionType";
   case KMIP_TAG_KeyFormatType:
      return "KeyFormatType";
   case KMIP_TAG_KeyMaterial:
      return "KeyMaterial";
   case KMIP_TAG_KeyPartIdentifier:
      return "KeyPartIdentifier";
   case KMIP_TAG_KeyValue:
      return "KeyValue";
   case KMIP_TAG_KeyWrappingData:
      return "KeyWrappingData";
   case KMIP_TAG_KeyWrappingSpecification:
      return "KeyWrappingSpecification";
   case KMIP_TAG_LastChangeDate:
      return "LastChangeDate";
   case KMIP_TAG_LeaseTime:
      return "LeaseTime";
   case KMIP_TAG_Link:
      return "Link";
   case KMIP_TAG_LinkType:
      return "LinkType";
   case KMIP_TAG_LinkedObjectIdentifier:
      return "LinkedObjectIdentifier";
   case KMIP_TAG_MACSignature:
      return "MACSignature";
   case KMIP_TAG_MACSignatureKeyInformation:
      return "MACSignatureKeyInformation";
   case KMIP_TAG_MaximumItems:
      return "MaximumItems";
   case KMIP_TAG_MaximumResponseSize:
      return "MaximumResponseSize";
   case KMIP_TAG_MessageExtension:
      return "MessageExtension";
   case KMIP_TAG_Modulus:
      return "Modulus";
   case KMIP_TAG_Name:
      return "Name";
   case KMIP_TAG_NameType:
      return "NameType";
   case KMIP_TAG_NameValue:
      return "NameValue";
   case KMIP_TAG_ObjectGroup:
      return "ObjectGroup";
   case KMIP_TAG_ObjectType:
      return "ObjectType";
   case KMIP_TAG_Offset:
      return "Offset";
   case KMIP_TAG_OpaqueDataType:
      return "OpaqueDataType";
   case KMIP_TAG_OpaqueDataValue:
      return "OpaqueDataValue";
   case KMIP_TAG_OpaqueObject:
      return "OpaqueObject";
   case KMIP_TAG_Operation:
      return "Operation";
   case KMIP_TAG_OperationPolicyName:
      return "OperationPolicyName";
   case KMIP_TAG_P:
      return "P";
   case KMIP_TAG_PaddingMethod:
      return "PaddingMethod";
   case KMIP_TAG_PrimeExponentP:
      return "PrimeExponentP";
   case KMIP_TAG_PrimeExponentQ:
      return "PrimeExponentQ";
   case KMIP_TAG_PrimeFieldSize:
      return "PrimeFieldSize";
   case KMIP_TAG_PrivateExponent:
      return "PrivateExponent";
   case KMIP_TAG_PrivateKey:
      return "PrivateKey";
   case KMIP_TAG_PrivateKeyTemplateAttribute:
      return "PrivateKeyTemplateAttribute";
   case KMIP_TAG_PrivateKeyUniqueIdentifier:
      return "PrivateKeyUniqueIdentifier";
   case KMIP_TAG_ProcessStartDate:
      return "ProcessStartDate";
   case KMIP_TAG_ProtectStopDate:
      return "ProtectStopDate";
   case KMIP_TAG_ProtocolVersion:
      return "ProtocolVersion";
   case KMIP_TAG_ProtocolVersionMajor:
      return "ProtocolVersionMajor";
   case KMIP_TAG_ProtocolVersionMinor:
      return "ProtocolVersionMinor";
   case KMIP_TAG_PublicExponent:
      return "PublicExponent";
   case KMIP_TAG_PublicKey:
      return "PublicKey";
   case KMIP_TAG_PublicKeyTemplateAttribute:
      return "PublicKeyTemplateAttribute";
   case KMIP_TAG_PublicKeyUniqueIdentifier:
      return "PublicKeyUniqueIdentifier";
   case KMIP_TAG_PutFunction:
      return "PutFunction";
   case KMIP_TAG_Q:
      return "Q";
   case KMIP_TAG_QString:
      return "QString";
   case KMIP_TAG_Qlength:
      return "Qlength";
   case KMIP_TAG_QueryFunction:
      return "QueryFunction";
   case KMIP_TAG_RecommendedCurve:
      return "RecommendedCurve";
   case KMIP_TAG_ReplacedUniqueIdentifier:
      return "ReplacedUniqueIdentifier";
   case KMIP_TAG_RequestHeader:
      return "RequestHeader";
   case KMIP_TAG_RequestMessage:
      return "RequestMessage";
   case KMIP_TAG_RequestPayload:
      return "RequestPayload";
   case KMIP_TAG_ResponseHeader:
      return "ResponseHeader";
   case KMIP_TAG_ResponseMessage:
      return "ResponseMessage";
   case KMIP_TAG_ResponsePayload:
      return "ResponsePayload";
   case KMIP_TAG_ResultMessage:
      return "ResultMessage";
   case KMIP_TAG_ResultReason:
      return "ResultReason";
   case KMIP_TAG_ResultStatus:
      return "ResultStatus";
   case KMIP_TAG_RevocationMessage:
      return "RevocationMessage";
   case KMIP_TAG_RevocationReason:
      return "RevocationReason";
   case KMIP_TAG_RevocationReasonCode:
      return "RevocationReasonCode";
   case KMIP_TAG_KeyRoleType:
      return "KeyRoleType";
   case KMIP_TAG_Salt:
      return "Salt";
   case KMIP_TAG_SecretData:
      return "SecretData";
   case KMIP_TAG_SecretDataType:
      return "SecretDataType";
   case KMIP_TAG_SerialNumber:
      return "SerialNumber";
   case KMIP_TAG_ServerInformation:
      return "ServerInformation";
   case KMIP_TAG_SplitKey:
      return "SplitKey";
   case KMIP_TAG_SplitKeyMethod:
      return "SplitKeyMethod";
   case KMIP_TAG_SplitKeyParts:
      return "SplitKeyParts";
   case KMIP_TAG_SplitKeyThreshold:
      return "SplitKeyThreshold";
   case KMIP_TAG_State:
      return "State";
   case KMIP_TAG_StorageStatusMask:
      return "StorageStatusMask";
   case KMIP_TAG_SymmetricKey:
      return "SymmetricKey";
   case KMIP_TAG_Template:
      return "Template";
   case KMIP_TAG_TemplateAttribute:
      return "TemplateAttribute";
   case KMIP_TAG_TimeStamp:
      return "TimeStamp";
   case KMIP_TAG_UniqueBatchItemID:
      return "UniqueBatchItemID";
   case KMIP_TAG_UniqueIdentifier:
      return "UniqueIdentifier";
   case KMIP_TAG_UsageLimits:
      return "UsageLimits";
   case KMIP_TAG_UsageLimitsCount:
      return "UsageLimitsCount";
   case KMIP_TAG_UsageLimitsTotal:
      return "UsageLimitsTotal";
   case KMIP_TAG_UsageLimitsUnit:
      return "UsageLimitsUnit";
   case KMIP_TAG_Username:
      return "Username";
   case KMIP_TAG_ValidityDate:
      return "ValidityDate";
   case KMIP_TAG_ValidityIndicator:
      return "ValidityIndicator";
   case KMIP_TAG_VendorExtension:
      return "VendorExtension";
   case KMIP_TAG_VendorIdentification:
      return "VendorIdentification";
   case KMIP_TAG_WrappingMethod:
      return "WrappingMethod";
   case KMIP_TAG_X:
      return "X";
   case KMIP_TAG_Y:
      return "Y";
   case KMIP_TAG_Password:
      return "Password";
   case KMIP_TAG_DeviceIdentifier:
      return "DeviceIdentifier";
   case KMIP_TAG_EncodingOption:
      return "EncodingOption";
   case KMIP_TAG_ExtensionInformation:
      return "ExtensionInformation";
   case KMIP_TAG_ExtensionName:
      return "ExtensionName";
   case KMIP_TAG_ExtensionTag:
      return "ExtensionTag";
   case KMIP_TAG_ExtensionType:
      return "ExtensionType";
   case KMIP_TAG_Fresh:
      return "Fresh";
   case KMIP_TAG_MachineIdentifier:
      return "MachineIdentifier";
   case KMIP_TAG_MediaIdentifier:
      return "MediaIdentifier";
   case KMIP_TAG_NetworkIdentifier:
      return "NetworkIdentifier";
   case KMIP_TAG_ObjectGroupMember:
      return "ObjectGroupMember";
   case KMIP_TAG_CertificateLength:
      return "CertificateLength";
   case KMIP_TAG_DigitalSignatureAlgorithm:
      return "DigitalSignatureAlgorithm";
   case KMIP_TAG_CertificateSerialNumber:
      return "CertificateSerialNumber";
   case KMIP_TAG_DeviceSerialNumber:
      return "DeviceSerialNumber";
   case KMIP_TAG_IssuerAlternativeName:
      return "IssuerAlternativeName";
   case KMIP_TAG_IssuerDistinguishedName:
      return "IssuerDistinguishedName";
   case KMIP_TAG_SubjectAlternativeName:
      return "SubjectAlternativeName";
   case KMIP_TAG_SubjectDistinguishedName:
      return "SubjectDistinguishedName";
   case KMIP_TAG_X509CertificateIdentifier:
      return "X509CertificateIdentifier";
   case KMIP_TAG_X509CertificateIssuer:
      return "X509CertificateIssuer";
   case KMIP_TAG_X509CertificateSubject:
      return "X509CertificateSubject";
   case KMIP_TAG_KeyValueLocation:
      return "KeyValueLocation";
   case KMIP_TAG_KeyValueLocationValue:
      return "KeyValueLocationValue";
   case KMIP_TAG_KeyValueLocationType:
      return "KeyValueLocationType";
   case KMIP_TAG_KeyValuePresent:
      return "KeyValuePresent";
   case KMIP_TAG_OriginalCreationDate:
      return "OriginalCreationDate";
   case KMIP_TAG_PGPKey:
      return "PGPKey";
   case KMIP_TAG_PGPKeyVersion:
      return "PGPKeyVersion";
   case KMIP_TAG_AlternativeName:
      return "AlternativeName";
   case KMIP_TAG_AlternativeNameValue:
      return "AlternativeNameValue";
   case KMIP_TAG_AlternativeNameType:
      return "AlternativeNameType";
   case KMIP_TAG_Data:
      return "Data";
   case KMIP_TAG_SignatureData:
      return "SignatureData";
   case KMIP_TAG_DataLength:
      return "DataLength";
   case KMIP_TAG_RandomIV:
      return "RandomIV";
   case KMIP_TAG_MACData:
      return "MACData";
   case KMIP_TAG_AttestationType:
      return "AttestationType";
   case KMIP_TAG_Nonce:
      return "Nonce";
   case KMIP_TAG_NonceID:
      return "NonceID";
   case KMIP_TAG_NonceValue:
      return "NonceValue";
   case KMIP_TAG_AttestationMeasurement:
      return "AttestationMeasurement";
   case KMIP_TAG_AttestationAssertion:
      return "AttestationAssertion";
   case KMIP_TAG_IVLength:
      return "IVLength";
   case KMIP_TAG_TagLength:
      return "TagLength";
   case KMIP_TAG_FixedFieldLength:
      return "FixedFieldLength";
   case KMIP_TAG_CounterLength:
      return "CounterLength";
   case KMIP_TAG_InitialCounterValue:
      return "InitialCounterValue";
   case KMIP_TAG_InvocationFieldLength:
      return "InvocationFieldLength";
   case KMIP_TAG_AttestationCapableIndicator:
      return "AttestationCapableIndicator";
   case KMIP_TAG_OffsetItems:
      return "OffsetItems";
   case KMIP_TAG_LocatedItems:
      return "LocatedItems";
   case KMIP_TAG_CorrelationValue:
      return "CorrelationValue";
   case KMIP_TAG_InitIndicator:
      return "InitIndicator";
   case KMIP_TAG_FinalIndicator:
      return "FinalIndicator";
   case KMIP_TAG_RNGParameters:
      return "RNGParameters";
   case KMIP_TAG_RNGAlgorithm:
      return "RNGAlgorithm";
   case KMIP_TAG_DRBGAlgorithm:
      return "DRBGAlgorithm";
   case KMIP_TAG_FIPS186Variation:
      return "FIPS186Variation";
   case KMIP_TAG_PredictionResistance:
      return "PredictionResistance";
   case KMIP_TAG_RandomNumberGenerator:
      return "RandomNumberGenerator";
   case KMIP_TAG_ValidationInformation:
      return "ValidationInformation";
   case KMIP_TAG_ValidationAuthorityType:
      return "ValidationAuthorityType";
   case KMIP_TAG_ValidationAuthorityCountry:
      return "ValidationAuthorityCountry";
   case KMIP_TAG_ValidationAuthorityURI:
      return "ValidationAuthorityURI";
   case KMIP_TAG_ValidationVersionMajor:
      return "ValidationVersionMajor";
   case KMIP_TAG_ValidationVersionMinor:
      return "ValidationVersionMinor";
   case KMIP_TAG_ValidationType:
      return "ValidationType";
   case KMIP_TAG_ValidationLevel:
      return "ValidationLevel";
   case KMIP_TAG_ValidationCertificateIdentifier:
      return "ValidationCertificateIdentifier";
   case KMIP_TAG_ValidationCertificateURI:
      return "ValidationCertificateURI";
   case KMIP_TAG_ValidationVendorURI:
      return "ValidationVendorURI";
   case KMIP_TAG_ValidationProfile:
      return "ValidationProfile";
   case KMIP_TAG_ProfileInformation:
      return "ProfileInformation";
   case KMIP_TAG_ProfileName:
      return "ProfileName";
   case KMIP_TAG_ServerURI:
      return "ServerURI";
   case KMIP_TAG_ServerPort:
      return "ServerPort";
   case KMIP_TAG_StreamingCapability:
      return "StreamingCapability";
   case KMIP_TAG_AsynchronousCapability:
      return "AsynchronousCapability";
   case KMIP_TAG_AttestationCapability:
      return "AttestationCapability";
   case KMIP_TAG_UnwrapMode:
      return "UnwrapMode";
   case KMIP_TAG_DestroyAction:
      return "DestroyAction";
   case KMIP_TAG_ShreddingAlgorithm:
      return "ShreddingAlgorithm";
   case KMIP_TAG_RNGMode:
      return "RNGMode";
   case KMIP_TAG_ClientRegistrationMethod:
      return "ClientRegistrationMethod";
   case KMIP_TAG_CapabilityInformation:
      return "CapabilityInformation";
   case KMIP_TAG_KeyWrapType:
      return "KeyWrapType";
   case KMIP_TAG_BatchUndoCapability:
      return "BatchUndoCapability";
   case KMIP_TAG_BatchContinueCapability:
      return "BatchContinueCapability";
   case KMIP_TAG_PKCS12FriendlyName:
      return "PKCS12FriendlyName";
   case KMIP_TAG_Description:
      return "Description";
   case KMIP_TAG_Comment:
      return "Comment";
   case KMIP_TAG_AuthenticatedEncryptionAdditionalData:
      return "AuthenticatedEncryptionAdditionalData";
   case KMIP_TAG_AuthenticatedEncryptionTag:
      return "AuthenticatedEncryptionTag";
   case KMIP_TAG_SaltLength:
      return "SaltLength";
   case KMIP_TAG_MaskGenerator:
      return "MaskGenerator";
   case KMIP_TAG_MaskGeneratorHashingAlgorithm:
      return "MaskGeneratorHashingAlgorithm";
   case KMIP_TAG_PSource:
      return "PSource";
   case KMIP_TAG_TrailerField:
      return "TrailerField";
   case KMIP_TAG_ClientCorrelationValue:
      return "ClientCorrelationValue";
   case KMIP_TAG_ServerCorrelationValue:
      return "ServerCorrelationValue";
   case KMIP_TAG_DigestedData:
      return "DigestedData";
   case KMIP_TAG_CertificateSubjectCN:
      return "CertificateSubjectCN";
   case KMIP_TAG_CertificateSubjectO:
      return "CertificateSubjectO";
   case KMIP_TAG_CertificateSubjectOU:
      return "CertificateSubjectOU";
   case KMIP_TAG_CertificateSubjectEmail:
      return "CertificateSubjectEmail";
   case KMIP_TAG_CertificateSubjectC:
      return "CertificateSubjectC";
   case KMIP_TAG_CertificateSubjectST:
      return "CertificateSubjectST";
   case KMIP_TAG_CertificateSubjectL:
      return "CertificateSubjectL";
   case KMIP_TAG_CertificateSubjectUID:
      return "CertificateSubjectUID";
   case KMIP_TAG_CertificateSubjectSerialNumber:
      return "CertificateSubjectSerialNumber";
   case KMIP_TAG_CertificateSubjectTitle:
      return "CertificateSubjectTitle";
   case KMIP_TAG_CertificateSubjectDC:
      return "CertificateSubjectDC";
   case KMIP_TAG_CertificateSubjectDNQualifier:
      return "CertificateSubjectDNQualifier";
   case KMIP_TAG_CertificateIssuerCN:
      return "CertificateIssuerCN";
   case KMIP_TAG_CertificateIssuerO:
      return "CertificateIssuerO";
   case KMIP_TAG_CertificateIssuerOU:
      return "CertificateIssuerOU";
   case KMIP_TAG_CertificateIssuerEmail:
      return "CertificateIssuerEmail";
   case KMIP_TAG_CertificateIssuerC:
      return "CertificateIssuerC";
   case KMIP_TAG_CertificateIssuerST:
      return "CertificateIssuerST";
   case KMIP_TAG_CertificateIssuerL:
      return "CertificateIssuerL";
   case KMIP_TAG_CertificateIssuerUID:
      return "CertificateIssuerUID";
   case KMIP_TAG_CertificateIssuerSerialNumber:
      return "CertificateIssuerSerialNumber";
   case KMIP_TAG_CertificateIssuerTitle:
      return "CertificateIssuerTitle";
   case KMIP_TAG_CertificateIssuerDC:
      return "CertificateIssuerDC";
   case KMIP_TAG_CertificateIssuerDNQualifier:
      return "CertificateIssuerDNQualifier";
   case KMIP_TAG_Sensitive:
      return "Sensitive";
   case KMIP_TAG_AlwaysSensitive:
      return "AlwaysSensitive";
   case KMIP_TAG_Extractable:
      return "Extractable";
   case KMIP_TAG_NeverExtractable:
      return "NeverExtractable";
   case KMIP_TAG_ReplaceExisting:
      return "ReplaceExisting";
   default:
      return "(Unknown Tag)";
   }
}

static const char *kmip_item_type_to_string (kmip_item_type_t type) {
   switch (type) {
   case KMIP_ITEM_TYPE_Structure:
   return "Structure";
   case KMIP_ITEM_TYPE_Integer:
   return "Integer";
   case KMIP_ITEM_TYPE_LongInteger:
   return "LongInteger";
   case KMIP_ITEM_TYPE_BigInteger:
   return "BigInteger";
   case KMIP_ITEM_TYPE_Enumeration:
   return "Enumeration";
   case KMIP_ITEM_TYPE_Boolean:
   return "Boolean";
   case KMIP_ITEM_TYPE_TextString:
   return "TextString";
   case KMIP_ITEM_TYPE_ByteString:
   return "ByteString";
   case KMIP_ITEM_TYPE_DateTime:
   return "DateTime";
   case KMIP_ITEM_TYPE_Interval:
   return "Interval";
   default:
   return "(Unknown Type)";
   }
}

static bool kmip_reader_next (kmip_reader_t *reader, uint32_t read_length) {
   uint32_t advance_length = read_length;
   advance_length = compute_padded_length (advance_length);

   CHECK_REMAINING_BUFFER_AND_RET (advance_length);

   /* Skip to the next type. */
   reader->pos += advance_length;
   return true;
}

static bool
kmip_dump_recursive (kms_request_str_t *str, kmip_reader_t *reader, int level)
{
   kmip_tag_type_t tag;
   kmip_item_type_t type;
   uint32_t len;
   kmip_reader_t subreader;

   while (true) {
      int i;

      if (!kmip_reader_read_tag (reader, &tag)) {
         /* EOF */
         return false;
      }

      for (i = 0; i < level; i++) {
         kms_request_str_append_char (str, ' ');
      }

      kms_request_str_appendf (str,
                               "tag=%s (%02x%02x%02x)",
                               kmip_tag_type_to_string (tag),
                               (tag & 0xFF0000) >> 16,
                               (tag & 0xFF00) >> 8,
                               tag & 0xFF);
      if (!kmip_reader_read_type (reader, &type)) {
         goto error;
      }
      kms_request_str_appendf (
         str, " type=%s (%02x)", kmip_item_type_to_string (type), type);
      if (!kmip_reader_read_length (reader, &len)) {
         goto error;
      }
      kms_request_str_appendf (str, " length=%" PRIu32, len);

      if (type == KMIP_ITEM_TYPE_Structure) {
         kmip_reader_in_place (reader, reader->pos, (size_t) len, &subreader);
         kms_request_str_append_char (str, '\n');
         kmip_dump_recursive (str, &subreader, level + 1);
         kmip_reader_next (reader, len);
         continue;
      } else if (type == KMIP_ITEM_TYPE_Integer) {
         int32_t value;
         kmip_reader_read_integer (reader, &value);
         kms_request_str_appendf (str, " value=%" PRId32, value);
      } else if (type == KMIP_ITEM_TYPE_LongInteger) {
         int64_t value;
         kmip_reader_read_long_integer (reader, &value);
         kms_request_str_appendf (str, " value=%" PRId64, value);
      } else if (type == KMIP_ITEM_TYPE_BigInteger) {
         kms_request_str_appendf (str, " value=(TODO)");
         kmip_reader_next (reader, len);
      } else if (type == KMIP_ITEM_TYPE_Enumeration) {
         uint32_t value;
         kmip_reader_read_enumeration (reader, &value);
         kms_request_str_appendf (str, " value=%" PRIu32, value);
      } else if (type == KMIP_ITEM_TYPE_Boolean) {
         kms_request_str_appendf (str, " value=(TODO)");
         kmip_reader_next (reader, len);
      } else if (type == KMIP_ITEM_TYPE_TextString) {
         uint8_t *value;
         value = malloc (len + 1);
         value[len] = 0;
         kmip_reader_read_string (reader, &value, len);
         kms_request_str_appendf (str, " value=%s", (char *) value);
      } else if (type == KMIP_ITEM_TYPE_ByteString) {
         kms_request_str_appendf (str, " value=(TODO)");
         kmip_reader_next (reader, len);
      } else if (type == KMIP_ITEM_TYPE_DateTime) {
         kms_request_str_appendf (str, " value=(TODO)");
         kmip_reader_next (reader, len);
      } else if (type == KMIP_ITEM_TYPE_Interval) {
         kms_request_str_appendf (str, " value=(TODO)");
         kmip_reader_next (reader, len);
      } else {
         goto error;
      }

      kms_request_str_append_char (str, '\n');
   }

error:
   kms_request_str_append_chars (str, "<malformed>", -1);
   return false;
}

char *
kmip_dump (uint8_t *data, size_t len)
{
   kms_request_str_t *str = kms_request_str_new ();
   kmip_reader_t *reader;


   reader = kmip_reader_new (data, len);
   kmip_dump_recursive (str, reader, 0);
   return kms_request_str_detach (str);
}