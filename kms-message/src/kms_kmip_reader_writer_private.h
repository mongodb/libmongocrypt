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

#ifndef KMS_KMIP_READER_WRITER_PRIVATE_H
#define KMS_KMIP_READER_WRITER_PRIVATE_H

#include "kms_message/kms_b64.h"
#include "kms_message_private.h"
#include "kms_request_opt_private.h"
#include "kms_request_str.h"
#include <stdint.h>

enum ITEM_TYPE {
   ITEM_TYPE_Structure = 0x01,
   ITEM_TYPE_Integer = 0x02,
   ITEM_TYPE_LongInteger = 0x03,
   ITEM_TYPE_BigInteger = 0x04,
   ITEM_TYPE_Enumeration = 0x05,
   ITEM_TYPE_Boolean = 0x06,
   ITEM_TYPE_TextString = 0x07,
   ITEM_TYPE_ByteString = 0x08,
   ITEM_TYPE_DateTime = 0x09,
   ITEM_TYPE_Interval = 0x0A,
};

enum TAG_TYPE {
   TAG_ActivationDate = 0x420001,
   TAG_ApplicationData = 0x420002,
   TAG_ApplicationNamespace = 0x420003,
   TAG_ApplicationSpecificInformation = 0x420004,
   TAG_ArchiveDate = 0x420005,
   TAG_AsynchronousCorrelationValue = 0x420006,
   TAG_AsynchronousIndicator = 0x420007,
   TAG_Attribute = 0x420008,
   TAG_AttributeIndex = 0x420009,
   TAG_AttributeName = 0x42000A,
   TAG_AttributeValue = 0x42000B,
   TAG_Authentication = 0x42000C,
   TAG_BatchCount = 0x42000D,
   TAG_BatchErrorContinuationOption = 0x42000E,
   TAG_BatchItem = 0x42000F,
   TAG_BatchOrderOption = 0x420010,
   TAG_BlockCipherMode = 0x420011,
   TAG_CancellationResult = 0x420012,
   TAG_Certificate = 0x420013,
   TAG_CertificateIdentifier = 0x420014, //(deprecatedasofvers=ion1.1),
   TAG_CertificateIssuer = 0x420015,     //(deprecatedasofvers=ion1.1),
   TAG_CertificateIssuerAlternativeName =
      0x420016, //(deprecatedasofvers=ion1.1),
   TAG_CertificateIssuerDistinguishedName =
      0x420017, //(deprecatedasofvers=ion1.1),
   TAG_CertificateRequest = 0x420018,
   TAG_CertificateRequestType = 0x420019,
   TAG_CertificateSubject = 0x42001A, //(deprecatedasofvers=ion1.1),
   TAG_CertificateSubjectAlternativeName =
      0x42001B, //(deprecatedasofvers=ion1.1),
   TAG_CertificateSubjectDistinguishedName =
      0x42001C, //(deprecatedasofvers=ion1.1),
   TAG_CertificateType = 0x42001D,
   TAG_CertificateValue = 0x42001E,
   TAG_CommonTemplateAttribute = 0x42001F,
   TAG_CompromiseDate = 0x420020,
   TAG_CompromiseOccurrenceDate = 0x420021,
   TAG_ContactInformation = 0x420022,
   TAG_Credential = 0x420023,
   TAG_CredentialType = 0x420024,
   TAG_CredentialValue = 0x420025,
   TAG_CriticalityIndicator = 0x420026,
   TAG_CRTCoefficient = 0x420027,
   TAG_CryptographicAlgorithm = 0x420028,
   TAG_CryptographicDomainParameters = 0x420029,
   TAG_CryptographicLength = 0x42002A,
   TAG_CryptographicParameters = 0x42002B,
   TAG_CryptographicUsageMask = 0x42002C,
   TAG_CustomAttribute = 0x42002D,
   TAG_D = 0x42002E,
   TAG_DeactivationDate = 0x42002F,
   TAG_DerivationData = 0x420030,
   TAG_DerivationMethod = 0x420031,
   TAG_DerivationParameters = 0x420032,
   TAG_DestroyDate = 0x420033,
   TAG_Digest = 0x420034,
   TAG_DigestValue = 0x420035,
   TAG_EncryptionKeyInformation = 0x420036,
   TAG_G = 0x420037,
   TAG_HashingAlgorithm = 0x420038,
   TAG_InitialDate = 0x420039,
   TAG_InitializationVector = 0x42003A,
   TAG_Issuer = 0x42003B, //(deprecatedasofvers=ion1.1),
   TAG_IterationCount = 0x42003C,
   TAG_IVCounterNonce = 0x42003D,
   TAG_J = 0x42003E,
   TAG_Key = 0x42003F,
   TAG_KeyBlock = 0x420040,
   TAG_KeyCompressionType = 0x420041,
   TAG_KeyFormatType = 0x420042,
   TAG_KeyMaterial = 0x420043,
   TAG_KeyPartIdentifier = 0x420044,
   TAG_KeyValue = 0x420045,
   TAG_KeyWrappingData = 0x420046,
   TAG_KeyWrappingSpecification = 0x420047,
   TAG_LastChangeDate = 0x420048,
   TAG_LeaseTime = 0x420049,
   TAG_Link = 0x42004A,
   TAG_LinkType = 0x42004B,
   TAG_LinkedObjectIdentifier = 0x42004C,
   TAG_MACSignature = 0x42004D,
   TAG_MACSignatureKeyInformation = 0x42004E,
   TAG_MaximumItems = 0x42004F,
   TAG_MaximumResponseSize = 0x420050,
   TAG_MessageExtension = 0x420051,
   TAG_Modulus = 0x420052,
   TAG_Name = 0x420053,
   TAG_NameType = 0x420054,
   TAG_NameValue = 0x420055,
   TAG_ObjectGroup = 0x420056,
   TAG_ObjectType = 0x420057,
   TAG_Offset = 0x420058,
   TAG_OpaqueDataType = 0x420059,
   TAG_OpaqueDataValue = 0x42005A,
   TAG_OpaqueObject = 0x42005B,
   TAG_Operation = 0x42005C,
   TAG_OperationPolicyName = 0x42005D, //(deprecated),
   TAG_P = 0x42005E,
   TAG_PaddingMethod = 0x42005F,
   TAG_PrimeExponentP = 0x420060,
   TAG_PrimeExponentQ = 0x420061,
   TAG_PrimeFieldSize = 0x420062,
   TAG_PrivateExponent = 0x420063,
   TAG_PrivateKey = 0x420064,
   TAG_PrivateKeyTemplateAttribute = 0x420065,
   TAG_PrivateKeyUniqueIdentifier = 0x420066,
   TAG_ProcessStartDate = 0x420067,
   TAG_ProtectStopDate = 0x420068,
   TAG_ProtocolVersion = 0x420069,
   TAG_ProtocolVersionMajor = 0x42006A,
   TAG_ProtocolVersionMinor = 0x42006B,
   TAG_PublicExponent = 0x42006C,
   TAG_PublicKey = 0x42006D,
   TAG_PublicKeyTemplateAttribute = 0x42006E,
   TAG_PublicKeyUniqueIdentifier = 0x42006F,
   TAG_PutFunction = 0x420070,
   TAG_Q = 0x420071,
   TAG_QString = 0x420072,
   TAG_Qlength = 0x420073,
   TAG_QueryFunction = 0x420074,
   TAG_RecommendedCurve = 0x420075,
   TAG_ReplacedUniqueIdentifier = 0x420076,
   TAG_RequestHeader = 0x420077,
   TAG_RequestMessage = 0x420078,
   TAG_RequestPayload = 0x420079,
   TAG_ResponseHeader = 0x42007A,
   TAG_ResponseMessage = 0x42007B,
   TAG_ResponsePayload = 0x42007C,
   TAG_ResultMessage = 0x42007D,
   TAG_ResultReason = 0x42007E,
   TAG_ResultStatus = 0x42007F,
   TAG_RevocationMessage = 0x420080,
   TAG_RevocationReason = 0x420081,
   TAG_RevocationReasonCode = 0x420082,
   TAG_KeyRoleType = 0x420083,
   TAG_Salt = 0x420084,
   TAG_SecretData = 0x420085,
   TAG_SecretDataType = 0x420086,
   TAG_SerialNumber = 0x420087, //(deprecatedasofvers=ion1.1),
   TAG_ServerInformation = 0x420088,
   TAG_SplitKey = 0x420089,
   TAG_SplitKeyMethod = 0x42008A,
   TAG_SplitKeyParts = 0x42008B,
   TAG_SplitKeyThreshold = 0x42008C,
   TAG_State = 0x42008D,
   TAG_StorageStatusMask = 0x42008E,
   TAG_SymmetricKey = 0x42008F,
   TAG_Template = 0x420090,
   TAG_TemplateAttribute = 0x420091,
   TAG_TimeStamp = 0x420092,
   TAG_UniqueBatchItemID = 0x420093,
   TAG_UniqueIdentifier = 0x420094,
   TAG_UsageLimits = 0x420095,
   TAG_UsageLimitsCount = 0x420096,
   TAG_UsageLimitsTotal = 0x420097,
   TAG_UsageLimitsUnit = 0x420098,
   TAG_Username = 0x420099,
   TAG_ValidityDate = 0x42009A,
   TAG_ValidityIndicator = 0x42009B,
   TAG_VendorExtension = 0x42009C,
   TAG_VendorIdentification = 0x42009D,
   TAG_WrappingMethod = 0x42009E,
   TAG_X = 0x42009F,
   TAG_Y = 0x4200A0,
   TAG_Password = 0x4200A1,
   TAG_DeviceIdentifier = 0x4200A2,
   TAG_EncodingOption = 0x4200A3,
   TAG_ExtensionInformation = 0x4200A4,
   TAG_ExtensionName = 0x4200A5,
   TAG_ExtensionTag = 0x4200A6,
   TAG_ExtensionType = 0x4200A7,
   TAG_Fresh = 0x4200A8,
   TAG_MachineIdentifier = 0x4200A9,
   TAG_MediaIdentifier = 0x4200AA,
   TAG_NetworkIdentifier = 0x4200AB,
   TAG_ObjectGroupMember = 0x4200AC,
   TAG_CertificateLength = 0x4200AD,
   TAG_DigitalSignatureAlgorithm = 0x4200AE,
   TAG_CertificateSerialNumber = 0x4200AF,
   TAG_DeviceSerialNumber = 0x4200B0,
   TAG_IssuerAlternativeName = 0x4200B1,
   TAG_IssuerDistinguishedName = 0x4200B2,
   TAG_SubjectAlternativeName = 0x4200B3,
   TAG_SubjectDistinguishedName = 0x4200B4,
   TAG_X509CertificateIdentifier = 0x4200B5,
   TAG_X509CertificateIssuer = 0x4200B6,
   TAG_X509CertificateSubject = 0x4200B7,
   TAG_KeyValueLocation = 0x4200B8,
   TAG_KeyValueLocationValue = 0x4200B9,
   TAG_KeyValueLocationType = 0x4200BA,
   TAG_KeyValuePresent = 0x4200BB,
   TAG_OriginalCreationDate = 0x4200BC,
   TAG_PGPKey = 0x4200BD,
   TAG_PGPKeyVersion = 0x4200BE,
   TAG_AlternativeName = 0x4200BF,
   TAG_AlternativeNameValue = 0x4200C0,
   TAG_AlternativeNameType = 0x4200C1,
   TAG_Data = 0x4200C2,
   TAG_SignatureData = 0x4200C3,
   TAG_DataLength = 0x4200C4,
   TAG_RandomIV = 0x4200C5,
   TAG_MACData = 0x4200C6,
   TAG_AttestationType = 0x4200C7,
   TAG_Nonce = 0x4200C8,
   TAG_NonceID = 0x4200C9,
   TAG_NonceValue = 0x4200CA,
   TAG_AttestationMeasurement = 0x4200CB,
   TAG_AttestationAssertion = 0x4200CC,
   TAG_IVLength = 0x4200CD,
   TAG_TagLength = 0x4200CE,
   TAG_FixedFieldLength = 0x4200CF,
   TAG_CounterLength = 0x4200D0,
   TAG_InitialCounterValue = 0x4200D1,
   TAG_InvocationFieldLength = 0x4200D2,
   TAG_AttestationCapableIndicator = 0x4200D3,
   TAG_OffsetItems = 0x4200D4,
   TAG_LocatedItems = 0x4200D5,
   TAG_CorrelationValue = 0x4200D6,
   TAG_InitIndicator = 0x4200D7,
   TAG_FinalIndicator = 0x4200D8,
   TAG_RNGParameters = 0x4200D9,
   TAG_RNGAlgorithm = 0x4200DA,
   TAG_DRBGAlgorithm = 0x4200DB,
   TAG_FIPS186Variation = 0x4200DC,
   TAG_PredictionResistance = 0x4200DD,
   TAG_RandomNumberGenerator = 0x4200DE,
   TAG_ValidationInformation = 0x4200DF,
   TAG_ValidationAuthorityType = 0x4200E0,
   TAG_ValidationAuthorityCountry = 0x4200E1,
   TAG_ValidationAuthorityURI = 0x4200E2,
   TAG_ValidationVersionMajor = 0x4200E3,
   TAG_ValidationVersionMinor = 0x4200E4,
   TAG_ValidationType = 0x4200E5,
   TAG_ValidationLevel = 0x4200E6,
   TAG_ValidationCertificateIdentifier = 0x4200E7,
   TAG_ValidationCertificateURI = 0x4200E8,
   TAG_ValidationVendorURI = 0x4200E9,
   TAG_ValidationProfile = 0x4200EA,
   TAG_ProfileInformation = 0x4200EB,
   TAG_ProfileName = 0x4200EC,
   TAG_ServerURI = 0x4200ED,
   TAG_ServerPort = 0x4200EE,
   TAG_StreamingCapability = 0x4200EF,
   TAG_AsynchronousCapability = 0x4200F0,
   TAG_AttestationCapability = 0x4200F1,
   TAG_UnwrapMode = 0x4200F2,
   TAG_DestroyAction = 0x4200F3,
   TAG_ShreddingAlgorithm = 0x4200F4,
   TAG_RNGMode = 0x4200F5,
   TAG_ClientRegistrationMethod = 0x4200F6,
   TAG_CapabilityInformation = 0x4200F7,
   TAG_KeyWrapType = 0x4200F8,
   TAG_BatchUndoCapability = 0x4200F9,
   TAG_BatchContinueCapability = 0x4200FA,
   TAG_PKCS12FriendlyName = 0x4200FB,
   TAG_Description = 0x4200FC,
   TAG_Comment = 0x4200FD,
   TAG_AuthenticatedEncryptionAdditionalData = 0x4200FE,
   TAG_AuthenticatedEncryptionTag = 0x4200FF,
   TAG_SaltLength = 0x420100,
   TAG_MaskGenerator = 0x420101,
   TAG_MaskGeneratorHashingAlgorithm = 0x420102,
   TAG_PSource = 0x420103,
   TAG_TrailerField = 0x420104,
   TAG_ClientCorrelationValue = 0x420105,
   TAG_ServerCorrelationValue = 0x420106,
   TAG_DigestedData = 0x420107,
   TAG_CertificateSubjectCN = 0x420108,
   TAG_CertificateSubjectO = 0x420109,
   TAG_CertificateSubjectOU = 0x42010A,
   TAG_CertificateSubjectEmail = 0x42010B,
   TAG_CertificateSubjectC = 0x42010C,
   TAG_CertificateSubjectST = 0x42010D,
   TAG_CertificateSubjectL = 0x42010E,
   TAG_CertificateSubjectUID = 0x42010F,
   TAG_CertificateSubjectSerialNumber = 0x420110,
   TAG_CertificateSubjectTitle = 0x420111,
   TAG_CertificateSubjectDC = 0x420112,
   TAG_CertificateSubjectDNQualifier = 0x420113,
   TAG_CertificateIssuerCN = 0x420114,
   TAG_CertificateIssuerO = 0x420115,
   TAG_CertificateIssuerOU = 0x420116,
   TAG_CertificateIssuerEmail = 0x420117,
   TAG_CertificateIssuerC = 0x420118,
   TAG_CertificateIssuerST = 0x420119,
   TAG_CertificateIssuerL = 0x42011A,
   TAG_CertificateIssuerUID = 0x42011B,
   TAG_CertificateIssuerSerialNumber = 0x42011C,
   TAG_CertificateIssuerTitle = 0x42011D,
   TAG_CertificateIssuerDC = 0x42011E,
   TAG_CertificateIssuerDNQualifier = 0x42011F,
   TAG_Sensitive = 0x420120,
   TAG_AlwaysSensitive = 0x420121,
   TAG_Extractable = 0x420122,
   TAG_NeverExtractable = 0x420123,
   TAG_ReplaceExisting = 0x420124,
};

typedef struct _kmip_writer_t kmip_writer_t;

kmip_writer_t * kmip_writer_new ();

void kmip_writer_destroy (kmip_writer_t *writer);

void
kmip_writer_write_u8 (kmip_writer_t *writer, uint8_t value);

void
kmip_writer_write_u16 (kmip_writer_t *writer, uint16_t value);

void
kmip_writer_write_u32 (kmip_writer_t *writer, uint32_t value);

void
kmip_writer_write_u64 (kmip_writer_t *writer, uint64_t value);

void
kmip_writer_write_tag_enum (kmip_writer_t *writer, int32_t tag);

void
kmip_writer_write_string (kmip_writer_t *writer, int32_t tag, const char *str, size_t len);

void
kmip_writer_write_bytes (kmip_writer_t *writer, int32_t tag, const char *str, size_t len);

void
kmip_writer_write_integer (kmip_writer_t *writer, int32_t tag, int32_t value);

void
kmip_writer_write_long_integer (kmip_writer_t *writer, int32_t tag, int64_t value);

void
kmip_writer_write_enumeration (kmip_writer_t *writer, int32_t tag, int32_t value);

void
kmip_writer_write_datetime (kmip_writer_t *writer, int32_t tag, int64_t value);

void
kmip_writer_begin_struct (kmip_writer_t *writer, int32_t tag);

void
kmip_writer_close_struct (kmip_writer_t *writer);

const uint8_t *
kmip_writer_get_buffer (kmip_writer_t *writer, size_t* len);

typedef struct _kmip_reader_t kmip_reader_t;

kmip_reader_t *
kmip_reader_new (uint8_t *ptr, size_t len);

void
kmip_reader_destroy (kmip_reader_t *reader);

bool
kmip_reader_in_place (kmip_reader_t *reader,
                      size_t pos,
                      size_t len,
                      kmip_reader_t *out_reader);

size_t
kmip_reader_save_position (kmip_reader_t *reader);

void
kmip_reader_restore_position (kmip_reader_t *reader, size_t pos);

bool
kmip_reader_has_data (kmip_reader_t *reader);

bool
kmip_reader_read_u8 (kmip_reader_t *reader, uint8_t *value);

bool
kmip_reader_read_u16 (kmip_reader_t *reader, uint16_t *value);

bool
kmip_reader_read_u32 (kmip_reader_t *reader, uint32_t *value);

bool
kmip_reader_read_u64 (kmip_reader_t *reader, uint64_t *value);

bool
kmip_reader_read_bytes (kmip_reader_t *reader, uint8_t **ptr, size_t length);

bool
kmip_reader_read_tag (kmip_reader_t *reader, uint32_t *tag);

bool
kmip_reader_read_length (kmip_reader_t *reader, uint32_t *length);

bool
kmip_reader_read_type (kmip_reader_t *reader, uint8_t *type);

bool
kmip_reader_read_enumeration (kmip_reader_t *reader, uint32_t *enum_value);

bool
kmip_reader_read_integer (kmip_reader_t *reader, int32_t *value);

bool
kmip_reader_read_long_integer (kmip_reader_t *reader, int64_t *value);

bool
kmip_reader_read_bytes (kmip_reader_t *reader, uint8_t **ptr, size_t length);

bool
kmip_reader_read_string (kmip_reader_t *reader, uint8_t **ptr, size_t length);

/* Note: does not descend structures. */
bool
kmip_reader_find (kmip_reader_t *reader,
                  size_t search_tag,
                  uint8_t type,
                  size_t *pos,
                  size_t *length);

kmip_reader_t *
kmip_reader_find_and_get_struct_reader (kmip_reader_t *reader, size_t tag);

bool
kmip_reader_find_and_read_enum (kmip_reader_t *reader,
                                size_t tag,
                                uint32_t *value);

bool
kmip_reader_find_and_read_bytes (kmip_reader_t *reader,
                                 size_t tag,
                                 uint8_t **out_ptr,
                                 size_t *out_len);

#endif /* KMS_KMIP_READER_WRITER_PRIVATE_H */