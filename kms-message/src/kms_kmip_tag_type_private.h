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

#ifndef KMS_KMIP_TAG_TYPE_PRIVATE_H
#define KMS_KMIP_TAG_TYPE_PRIVATE_H

/* KMS_MSG_INLINE */
#include "kms_message/kms_message_defines.h"
typedef enum {
   KMIP_TAG_ActivationDate = 0x420001,
   KMIP_TAG_ApplicationData = 0x420002,
   KMIP_TAG_ApplicationNamespace = 0x420003,
   KMIP_TAG_ApplicationSpecificInformation = 0x420004,
   KMIP_TAG_ArchiveDate = 0x420005,
   KMIP_TAG_AsynchronousCorrelationValue = 0x420006,
   KMIP_TAG_AsynchronousIndicator = 0x420007,
   KMIP_TAG_Attribute = 0x420008,
   KMIP_TAG_AttributeIndex = 0x420009,
   KMIP_TAG_AttributeName = 0x42000A,
   KMIP_TAG_AttributeValue = 0x42000B,
   KMIP_TAG_Authentication = 0x42000C,
   KMIP_TAG_BatchCount = 0x42000D,
   KMIP_TAG_BatchErrorContinuationOption = 0x42000E,
   KMIP_TAG_BatchItem = 0x42000F,
   KMIP_TAG_BatchOrderOption = 0x420010,
   KMIP_TAG_BlockCipherMode = 0x420011,
   KMIP_TAG_CancellationResult = 0x420012,
   KMIP_TAG_Certificate = 0x420013,
   KMIP_TAG_CertificateIdentifier = 0x420014, /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateIssuer = 0x420015,     /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateIssuerAlternativeName =
      0x420016, /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateIssuerDistinguishedName =
      0x420017, /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateRequest = 0x420018,
   KMIP_TAG_CertificateRequestType = 0x420019,
   KMIP_TAG_CertificateSubject = 0x42001A, /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateSubjectAlternativeName =
      0x42001B, /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateSubjectDistinguishedName =
      0x42001C, /* deprecated as of version 1.1 */
   KMIP_TAG_CertificateType = 0x42001D,
   KMIP_TAG_CertificateValue = 0x42001E,
   KMIP_TAG_CommonTemplateAttribute = 0x42001F,
   KMIP_TAG_CompromiseDate = 0x420020,
   KMIP_TAG_CompromiseOccurrenceDate = 0x420021,
   KMIP_TAG_ContactInformation = 0x420022,
   KMIP_TAG_Credential = 0x420023,
   KMIP_TAG_CredentialType = 0x420024,
   KMIP_TAG_CredentialValue = 0x420025,
   KMIP_TAG_CriticalityIndicator = 0x420026,
   KMIP_TAG_CRTCoefficient = 0x420027,
   KMIP_TAG_CryptographicAlgorithm = 0x420028,
   KMIP_TAG_CryptographicDomainParameters = 0x420029,
   KMIP_TAG_CryptographicLength = 0x42002A,
   KMIP_TAG_CryptographicParameters = 0x42002B,
   KMIP_TAG_CryptographicUsageMask = 0x42002C,
   KMIP_TAG_CustomAttribute = 0x42002D,
   KMIP_TAG_D = 0x42002E,
   KMIP_TAG_DeactivationDate = 0x42002F,
   KMIP_TAG_DerivationData = 0x420030,
   KMIP_TAG_DerivationMethod = 0x420031,
   KMIP_TAG_DerivationParameters = 0x420032,
   KMIP_TAG_DestroyDate = 0x420033,
   KMIP_TAG_Digest = 0x420034,
   KMIP_TAG_DigestValue = 0x420035,
   KMIP_TAG_EncryptionKeyInformation = 0x420036,
   KMIP_TAG_G = 0x420037,
   KMIP_TAG_HashingAlgorithm = 0x420038,
   KMIP_TAG_InitialDate = 0x420039,
   KMIP_TAG_InitializationVector = 0x42003A,
   KMIP_TAG_Issuer = 0x42003B, /* deprecated as of version 1.1 */
   KMIP_TAG_IterationCount = 0x42003C,
   KMIP_TAG_IVCounterNonce = 0x42003D,
   KMIP_TAG_J = 0x42003E,
   KMIP_TAG_Key = 0x42003F,
   KMIP_TAG_KeyBlock = 0x420040,
   KMIP_TAG_KeyCompressionType = 0x420041,
   KMIP_TAG_KeyFormatType = 0x420042,
   KMIP_TAG_KeyMaterial = 0x420043,
   KMIP_TAG_KeyPartIdentifier = 0x420044,
   KMIP_TAG_KeyValue = 0x420045,
   KMIP_TAG_KeyWrappingData = 0x420046,
   KMIP_TAG_KeyWrappingSpecification = 0x420047,
   KMIP_TAG_LastChangeDate = 0x420048,
   KMIP_TAG_LeaseTime = 0x420049,
   KMIP_TAG_Link = 0x42004A,
   KMIP_TAG_LinkType = 0x42004B,
   KMIP_TAG_LinkedObjectIdentifier = 0x42004C,
   KMIP_TAG_MACSignature = 0x42004D,
   KMIP_TAG_MACSignatureKeyInformation = 0x42004E,
   KMIP_TAG_MaximumItems = 0x42004F,
   KMIP_TAG_MaximumResponseSize = 0x420050,
   KMIP_TAG_MessageExtension = 0x420051,
   KMIP_TAG_Modulus = 0x420052,
   KMIP_TAG_Name = 0x420053,
   KMIP_TAG_NameType = 0x420054,
   KMIP_TAG_NameValue = 0x420055,
   KMIP_TAG_ObjectGroup = 0x420056,
   KMIP_TAG_ObjectType = 0x420057,
   KMIP_TAG_Offset = 0x420058,
   KMIP_TAG_OpaqueDataType = 0x420059,
   KMIP_TAG_OpaqueDataValue = 0x42005A,
   KMIP_TAG_OpaqueObject = 0x42005B,
   KMIP_TAG_Operation = 0x42005C,
   KMIP_TAG_OperationPolicyName = 0x42005D, /* deprecated */
   KMIP_TAG_P = 0x42005E,
   KMIP_TAG_PaddingMethod = 0x42005F,
   KMIP_TAG_PrimeExponentP = 0x420060,
   KMIP_TAG_PrimeExponentQ = 0x420061,
   KMIP_TAG_PrimeFieldSize = 0x420062,
   KMIP_TAG_PrivateExponent = 0x420063,
   KMIP_TAG_PrivateKey = 0x420064,
   KMIP_TAG_PrivateKeyTemplateAttribute = 0x420065,
   KMIP_TAG_PrivateKeyUniqueIdentifier = 0x420066,
   KMIP_TAG_ProcessStartDate = 0x420067,
   KMIP_TAG_ProtectStopDate = 0x420068,
   KMIP_TAG_ProtocolVersion = 0x420069,
   KMIP_TAG_ProtocolVersionMajor = 0x42006A,
   KMIP_TAG_ProtocolVersionMinor = 0x42006B,
   KMIP_TAG_PublicExponent = 0x42006C,
   KMIP_TAG_PublicKey = 0x42006D,
   KMIP_TAG_PublicKeyTemplateAttribute = 0x42006E,
   KMIP_TAG_PublicKeyUniqueIdentifier = 0x42006F,
   KMIP_TAG_PutFunction = 0x420070,
   KMIP_TAG_Q = 0x420071,
   KMIP_TAG_QString = 0x420072,
   KMIP_TAG_Qlength = 0x420073,
   KMIP_TAG_QueryFunction = 0x420074,
   KMIP_TAG_RecommendedCurve = 0x420075,
   KMIP_TAG_ReplacedUniqueIdentifier = 0x420076,
   KMIP_TAG_RequestHeader = 0x420077,
   KMIP_TAG_RequestMessage = 0x420078,
   KMIP_TAG_RequestPayload = 0x420079,
   KMIP_TAG_ResponseHeader = 0x42007A,
   KMIP_TAG_ResponseMessage = 0x42007B,
   KMIP_TAG_ResponsePayload = 0x42007C,
   KMIP_TAG_ResultMessage = 0x42007D,
   KMIP_TAG_ResultReason = 0x42007E,
   KMIP_TAG_ResultStatus = 0x42007F,
   KMIP_TAG_RevocationMessage = 0x420080,
   KMIP_TAG_RevocationReason = 0x420081,
   KMIP_TAG_RevocationReasonCode = 0x420082,
   KMIP_TAG_KeyRoleType = 0x420083,
   KMIP_TAG_Salt = 0x420084,
   KMIP_TAG_SecretData = 0x420085,
   KMIP_TAG_SecretDataType = 0x420086,
   KMIP_TAG_SerialNumber = 0x420087, /* deprecated as of version 1.1 */
   KMIP_TAG_ServerInformation = 0x420088,
   KMIP_TAG_SplitKey = 0x420089,
   KMIP_TAG_SplitKeyMethod = 0x42008A,
   KMIP_TAG_SplitKeyParts = 0x42008B,
   KMIP_TAG_SplitKeyThreshold = 0x42008C,
   KMIP_TAG_State = 0x42008D,
   KMIP_TAG_StorageStatusMask = 0x42008E,
   KMIP_TAG_SymmetricKey = 0x42008F,
   KMIP_TAG_Template = 0x420090,
   KMIP_TAG_TemplateAttribute = 0x420091,
   KMIP_TAG_TimeStamp = 0x420092,
   KMIP_TAG_UniqueBatchItemID = 0x420093,
   KMIP_TAG_UniqueIdentifier = 0x420094,
   KMIP_TAG_UsageLimits = 0x420095,
   KMIP_TAG_UsageLimitsCount = 0x420096,
   KMIP_TAG_UsageLimitsTotal = 0x420097,
   KMIP_TAG_UsageLimitsUnit = 0x420098,
   KMIP_TAG_Username = 0x420099,
   KMIP_TAG_ValidityDate = 0x42009A,
   KMIP_TAG_ValidityIndicator = 0x42009B,
   KMIP_TAG_VendorExtension = 0x42009C,
   KMIP_TAG_VendorIdentification = 0x42009D,
   KMIP_TAG_WrappingMethod = 0x42009E,
   KMIP_TAG_X = 0x42009F,
   KMIP_TAG_Y = 0x4200A0,
   KMIP_TAG_Password = 0x4200A1,
   KMIP_TAG_DeviceIdentifier = 0x4200A2,
   KMIP_TAG_EncodingOption = 0x4200A3,
   KMIP_TAG_ExtensionInformation = 0x4200A4,
   KMIP_TAG_ExtensionName = 0x4200A5,
   KMIP_TAG_ExtensionTag = 0x4200A6,
   KMIP_TAG_ExtensionType = 0x4200A7,
   KMIP_TAG_Fresh = 0x4200A8,
   KMIP_TAG_MachineIdentifier = 0x4200A9,
   KMIP_TAG_MediaIdentifier = 0x4200AA,
   KMIP_TAG_NetworkIdentifier = 0x4200AB,
   KMIP_TAG_ObjectGroupMember = 0x4200AC,
   KMIP_TAG_CertificateLength = 0x4200AD,
   KMIP_TAG_DigitalSignatureAlgorithm = 0x4200AE,
   KMIP_TAG_CertificateSerialNumber = 0x4200AF,
   KMIP_TAG_DeviceSerialNumber = 0x4200B0,
   KMIP_TAG_IssuerAlternativeName = 0x4200B1,
   KMIP_TAG_IssuerDistinguishedName = 0x4200B2,
   KMIP_TAG_SubjectAlternativeName = 0x4200B3,
   KMIP_TAG_SubjectDistinguishedName = 0x4200B4,
   KMIP_TAG_X509CertificateIdentifier = 0x4200B5,
   KMIP_TAG_X509CertificateIssuer = 0x4200B6,
   KMIP_TAG_X509CertificateSubject = 0x4200B7,
   KMIP_TAG_KeyValueLocation = 0x4200B8,
   KMIP_TAG_KeyValueLocationValue = 0x4200B9,
   KMIP_TAG_KeyValueLocationType = 0x4200BA,
   KMIP_TAG_KeyValuePresent = 0x4200BB,
   KMIP_TAG_OriginalCreationDate = 0x4200BC,
   KMIP_TAG_PGPKey = 0x4200BD,
   KMIP_TAG_PGPKeyVersion = 0x4200BE,
   KMIP_TAG_AlternativeName = 0x4200BF,
   KMIP_TAG_AlternativeNameValue = 0x4200C0,
   KMIP_TAG_AlternativeNameType = 0x4200C1,
   KMIP_TAG_Data = 0x4200C2,
   KMIP_TAG_SignatureData = 0x4200C3,
   KMIP_TAG_DataLength = 0x4200C4,
   KMIP_TAG_RandomIV = 0x4200C5,
   KMIP_TAG_MACData = 0x4200C6,
   KMIP_TAG_AttestationType = 0x4200C7,
   KMIP_TAG_Nonce = 0x4200C8,
   KMIP_TAG_NonceID = 0x4200C9,
   KMIP_TAG_NonceValue = 0x4200CA,
   KMIP_TAG_AttestationMeasurement = 0x4200CB,
   KMIP_TAG_AttestationAssertion = 0x4200CC,
   KMIP_TAG_IVLength = 0x4200CD,
   KMIP_TAG_TagLength = 0x4200CE,
   KMIP_TAG_FixedFieldLength = 0x4200CF,
   KMIP_TAG_CounterLength = 0x4200D0,
   KMIP_TAG_InitialCounterValue = 0x4200D1,
   KMIP_TAG_InvocationFieldLength = 0x4200D2,
   KMIP_TAG_AttestationCapableIndicator = 0x4200D3,
   KMIP_TAG_OffsetItems = 0x4200D4,
   KMIP_TAG_LocatedItems = 0x4200D5,
   KMIP_TAG_CorrelationValue = 0x4200D6,
   KMIP_TAG_InitIndicator = 0x4200D7,
   KMIP_TAG_FinalIndicator = 0x4200D8,
   KMIP_TAG_RNGParameters = 0x4200D9,
   KMIP_TAG_RNGAlgorithm = 0x4200DA,
   KMIP_TAG_DRBGAlgorithm = 0x4200DB,
   KMIP_TAG_FIPS186Variation = 0x4200DC,
   KMIP_TAG_PredictionResistance = 0x4200DD,
   KMIP_TAG_RandomNumberGenerator = 0x4200DE,
   KMIP_TAG_ValidationInformation = 0x4200DF,
   KMIP_TAG_ValidationAuthorityType = 0x4200E0,
   KMIP_TAG_ValidationAuthorityCountry = 0x4200E1,
   KMIP_TAG_ValidationAuthorityURI = 0x4200E2,
   KMIP_TAG_ValidationVersionMajor = 0x4200E3,
   KMIP_TAG_ValidationVersionMinor = 0x4200E4,
   KMIP_TAG_ValidationType = 0x4200E5,
   KMIP_TAG_ValidationLevel = 0x4200E6,
   KMIP_TAG_ValidationCertificateIdentifier = 0x4200E7,
   KMIP_TAG_ValidationCertificateURI = 0x4200E8,
   KMIP_TAG_ValidationVendorURI = 0x4200E9,
   KMIP_TAG_ValidationProfile = 0x4200EA,
   KMIP_TAG_ProfileInformation = 0x4200EB,
   KMIP_TAG_ProfileName = 0x4200EC,
   KMIP_TAG_ServerURI = 0x4200ED,
   KMIP_TAG_ServerPort = 0x4200EE,
   KMIP_TAG_StreamingCapability = 0x4200EF,
   KMIP_TAG_AsynchronousCapability = 0x4200F0,
   KMIP_TAG_AttestationCapability = 0x4200F1,
   KMIP_TAG_UnwrapMode = 0x4200F2,
   KMIP_TAG_DestroyAction = 0x4200F3,
   KMIP_TAG_ShreddingAlgorithm = 0x4200F4,
   KMIP_TAG_RNGMode = 0x4200F5,
   KMIP_TAG_ClientRegistrationMethod = 0x4200F6,
   KMIP_TAG_CapabilityInformation = 0x4200F7,
   KMIP_TAG_KeyWrapType = 0x4200F8,
   KMIP_TAG_BatchUndoCapability = 0x4200F9,
   KMIP_TAG_BatchContinueCapability = 0x4200FA,
   KMIP_TAG_PKCS12FriendlyName = 0x4200FB,
   KMIP_TAG_Description = 0x4200FC,
   KMIP_TAG_Comment = 0x4200FD,
   KMIP_TAG_AuthenticatedEncryptionAdditionalData = 0x4200FE,
   KMIP_TAG_AuthenticatedEncryptionTag = 0x4200FF,
   KMIP_TAG_SaltLength = 0x420100,
   KMIP_TAG_MaskGenerator = 0x420101,
   KMIP_TAG_MaskGeneratorHashingAlgorithm = 0x420102,
   KMIP_TAG_PSource = 0x420103,
   KMIP_TAG_TrailerField = 0x420104,
   KMIP_TAG_ClientCorrelationValue = 0x420105,
   KMIP_TAG_ServerCorrelationValue = 0x420106,
   KMIP_TAG_DigestedData = 0x420107,
   KMIP_TAG_CertificateSubjectCN = 0x420108,
   KMIP_TAG_CertificateSubjectO = 0x420109,
   KMIP_TAG_CertificateSubjectOU = 0x42010A,
   KMIP_TAG_CertificateSubjectEmail = 0x42010B,
   KMIP_TAG_CertificateSubjectC = 0x42010C,
   KMIP_TAG_CertificateSubjectST = 0x42010D,
   KMIP_TAG_CertificateSubjectL = 0x42010E,
   KMIP_TAG_CertificateSubjectUID = 0x42010F,
   KMIP_TAG_CertificateSubjectSerialNumber = 0x420110,
   KMIP_TAG_CertificateSubjectTitle = 0x420111,
   KMIP_TAG_CertificateSubjectDC = 0x420112,
   KMIP_TAG_CertificateSubjectDNQualifier = 0x420113,
   KMIP_TAG_CertificateIssuerCN = 0x420114,
   KMIP_TAG_CertificateIssuerO = 0x420115,
   KMIP_TAG_CertificateIssuerOU = 0x420116,
   KMIP_TAG_CertificateIssuerEmail = 0x420117,
   KMIP_TAG_CertificateIssuerC = 0x420118,
   KMIP_TAG_CertificateIssuerST = 0x420119,
   KMIP_TAG_CertificateIssuerL = 0x42011A,
   KMIP_TAG_CertificateIssuerUID = 0x42011B,
   KMIP_TAG_CertificateIssuerSerialNumber = 0x42011C,
   KMIP_TAG_CertificateIssuerTitle = 0x42011D,
   KMIP_TAG_CertificateIssuerDC = 0x42011E,
   KMIP_TAG_CertificateIssuerDNQualifier = 0x42011F,
   KMIP_TAG_Sensitive = 0x420120,
   KMIP_TAG_AlwaysSensitive = 0x420121,
   KMIP_TAG_Extractable = 0x420122,
   KMIP_TAG_NeverExtractable = 0x420123,
   KMIP_TAG_ReplaceExisting = 0x420124
} kmip_tag_type_t;


static KMS_MSG_INLINE const char *
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

#endif /* KMS_KMIP_TAG_TYPE_PRIVATE_H */
