/*
 * Copyright 2023-present MongoDB, Inc.
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

#include <mongocrypt-opts-private.h>

#include <test-mongocrypt-assert-match-bson.h>
#include <test-mongocrypt.h>

#define LOCAL_KEK1_BASE64                                                                                              \
    "+ol0TFyLuVvKFSqGzOFGuaOGQnnyfAqalhOv3II/VSxQTCORCGhOmw/IxhthGx0r"                                                 \
    "2R/NpMWc91qQ8Ieho4QuE9ucToTnpJ4OquFpdZv2IcO4gey3ecZGCl9jPDig8F+a"

#define LOCAL_KEK2_BASE64                                                                                              \
    "yPSpsO8FoVkmt+qdTDnw/pJaKriwfI6NLD1yse3BZLd3ZcXb3rAVJEA+/yu/vPzE"                                                 \
    "8ju7OYTV63AwfLor8Hg9qzo8lyYC6H3RSfdJ9g9aXdCRfGZJgpbpchJUjR06JMLR"

// clang-format off
// GCP_PRIVATEKEY1 was generated with: `openssl genrsa -out private-key.pem 2048`
#define GCP_PRIVATEKEY1 "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCaqoCoH23dVS8see2DPOpHF3VHtKrXED2zcTkr+C15dDsw3hEl7123xwby/nSg08TMN9uzWkTaIP/CRNhN/VO3dmlCoRy/1Tyx8r3P7mELNPv7X6FP3MgcRMwSesvp7RYnTsImxQ6c48yTd2a4KnjFkJ9HkbOdxjoK2FENwPMdKNgU66XdzqIJBTeqSmx4FuTKdjQm3wi6vHYZgkZ1CKn90oDzpUwwIk3O4614Hxw8Gq40HgpwuTxKLFmfEgqyTHn54pw7plVivwwaUE2tXv3T4TIb0C8J9qquRtWSJuBVBM7yNucsNuWIXzW9jOT6PGcK30OIpkmf6n0Ib2pgY+WhAgMBAAECggEADypgDGwtg4YEZsPrX0KYNcGV90KevFEMPcXAvYAbpGS6X5WswIeerMQkGSxMbw8oxT4GackUhn91GJ1TyNzpyivfESCXXzOHXKsAw+xbwWOwABNdz8UGLahsyrSV/VFpKlBJjw/kOYvILd8HuE/40OV4CsZdgn9TBmh01SiJ5h5JtRP+kZycYluiUo0zLBReI8bpFPnWlCBDJJPE+UpFUCcifw/2xTkACJChtLmDDJ3NkUYACWQZ8HDf3UG3yE+OAGtP27srn1DYs6aNsr/dGfVU6Lu1mO8HswlSm4XHckdVdEmPaj/g5+TGBidnli8yMOhaPk5oDyD0DSltz4Ss2QKBgQDQ8xkFOCPQxnj6eO0s/8SXfoLQyCpHLqXNF7rw5H6VHo+5iyOt146XeLJNQeTYi/JX6bAlyPfc51ESZsjG1NucyLToJf7+Q+o/w/dNq3eNvGH1rxfYdalD4woQL+JQcgnelnMInyTCPS7drXbugl2AH2JzbwwyBHMB5KeW9paXSQKBgQC9fjo9G/ULae+w27aGSOYCnaFb0LlOJ5merjaZF3GkZPE3RhGIY19C2HRcjre4qRZbrPqyLkF8hoiLMTEd+n+vn8jUQaw/A67tVS1egnJlhut8BcFxW/jhmE80fIzRfxtRQhB/mevxTAIhhLUks3I7CZAjUabx9F+RAYLg3ZCjmQKBgBaj0Hk1TQQpDSCui5xNlkKH7aqrlZEi58oiIRpK18BWkGIdRl9mtMeKx18Bnccs2rRV2MUvUlP4KFujEWwh0i3ZvWhN/aQVPcNs+1XKF2kfGUoij6XfkdiOOB/q4E2xHYqlqI8tlzEIqhRQ4EsViwX/4I37YUnmG4P//3ym+UgpAoGAUMAx4UjArBSA6EU5CxCVtBeoY5AW549Ij6595c9vxjad9IgPgKeYOMw1ChxnfnHP7VFRpAzCK2bJWUelPrk5IIZe9tTlqhTPvqPFqbi9Nza/syJgxQYEkV5uoldRSxV3drFIhpf5S+KwJch/yRwPWclBe0uYcRNKhmi2dUz2DkECgYB4MazvGlNzdAGGt9ah+Ytq0ZZLaJlZMjlNZdsmiWn3Lhxy/l3ibTb1vALo7rQoH3Fpb55B+aiEPMtWVx0yVeIBaHmxQ+Q1Qes8vkL0ONAc4ZUPN9IVu2l8TE+cM6qzoZjpJMwK/JiFmqkE/Gss7gBgCr5JEQrXj2VecBSAcZXMwA=="
// GCP_PRIVATEKEY2 was generated with: `openssl genrsa -out private-key.pem 2048`
#define GCP_PRIVATEKEY2 "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC4OWLdpC6AKXjskPiMa/oomIlT5RqeDvcDjQBKyhBTJ8cj3brB4xTBYVNAjBuHZeD8hKGs+6m4PPBxFEt5i7dPZNQZzDJ8Gk4xEkL4Ukgzx1rYwAI1f/Ef45gqUGZJC/kSCAUoGG5FUr+o23W6OCrx302ZVPGB+MbvO6cuTv6DlpHw3w9djpy4l6aMlj+JFCKnR7ai9yoAia8IYa0edMPi2HxdQZziHdlkw3wp+jBvN/706a24TzZKa1ewz2K2lQlc8G2iLy9+AcbHwYKo07ETKmu5azOr4yJ47aC2+SnXQzSFmDOJVTAq8/PXNQVscialqOdwMVpnWE5AFw/DxJibAgMBAAECgf9IZdgVXa7+XTg7lEWWkpdCZ9Xcdu44JJOiVwtcInRCexBzRoy5qv6w3+iIzzUzZXbyihHOhKCNkzm5uX6z1er1nP7OCV5xIEdpSEll60dUDH7gc6UurX3b/MPCauwT5CCphb63gyO9BNWkfk5Qt7HGyQ3/bVo/8u7TqJsYeeKA9B5j6LrnW/gITJGOSzq9j3PpWTMGbi0T57tMBZhRmncZ4jfDruXvPsZlXFnV2sfbtgCzpaOfAQ/CKa5PHz382b7sitEoKuwtYVBrTxLKTTUhRneGaK47lhBFsbEtqhicVYOUfplgE/wLrhmFcjRkmxAzPYq89QfaQ60LGiBrMUUCgYEA5NrMJgvife4DdhtFR2yiN3ufXJtqvMUtfZZAZoPD7fVz0VSwYEfkhuNCtt0U6CD3xjpWFOL372YycNI+apyhL3kL2Jnrpsh5mjjCnLoFqKVVgTWK9GFNSzVeO9LNjGJpR1nZDorZ2FHeUW4SAfMs5b1wek7xAnPrNHYEE8TgRx8CgYEAzhNgl++WWvj/pLKwLc/Gxz03rOoXYPnAnsfyO4g9F883Ps9uVgTro9EKeD9n+nPRbSRISZExe5P8EVUXrIpviO3oHE7fvdzoBfr2Vf5c/qQ0anD47RJODjJyKwrkuWxkxotPDWU/msZdyO7hf3v5BxevrP0Bzg2+zmbVE3dvKwUCgYEAt+Gdusw91hVSLqnGxpbg2Fe6OjyeTMLZxFjfsf8ZhK99uaqkdRgO5NrhlfCZhdJHg70HwYyEzpR83u3vPNZRJMXL4OP71myqWGJW7HsDZPhDdahB2A3+fvmIl+TPR4cjNDNbFjY2x3sweJlKWsq7PnUyVPPs7p2ZVPOmXwQHeN0CgYATslZxLz03xMTqgQnF1y4wrPE9XcKOSlDW3FWSyxrLw8qL/leVcTL0nW5av/S4Q4mo3Obr4SzRmvtkzLVOkIzIkbS1v/QyuYKTz8DrxzwsOpWn9tRUFIPRZ5Dx/ECQWIPpVjdgGGVT7dHY+rwi6z6KJwFrj2M0xquOHtYO3kOJ4QKBgQDDHjZTAyzMVWJiUDI6ENSKqTUDQh/UxI1zpMxp9qoHUwO8iHF4BLastquvK/sUuRbF6mI6z9/theDEqzP5Ytd5YrD2QOBJQhX8NDmO575+N7AldsxupVqjJWrivWo/cJMOwhLZ+OHLJjkfrZQSDjg70gS7AsFeLweLO3Aa9thVYw=="
// clang-format on

#define BSON_STR(...) #__VA_ARGS__

// `kmip_get_operation_type` returns a string representation of an Operation in a KMIP request.
// Useful for tests wanting to assert the type of KMIP request contained in a `mongocrypt_kms_ctx_t`.
static const char *kmip_get_operation_type(mongocrypt_binary_t *bin) {
    // Convert to hex for easier searching with `strstr`.
    char *as_hex = data_to_hex(mongocrypt_binary_data(bin), mongocrypt_binary_len(bin));
    const char *needle = "42005c"   // Tag=Operation
                         "05"       // Type=Enum
                         "00000004" // Length
                         "000000";  // First three bytes of four byte value.
    char *found = strstr(as_hex, needle);
    if (!found) {
        bson_free(as_hex);
        return "Not found";
    }
    // Read the next two hex characters.
    found += strlen(needle);
    const char *got = "Unknown";
    // Refer to section 9.1.3.2.26 of KMIP 1.0 specification for the Operation values.
    if (0 == strncmp(found, "01", 2)) {
        got = "Create";
    } else if (0 == strncmp(found, "02", 2)) {
        got = "Create_Key_Pair";
    } else if (0 == strncmp(found, "03", 2)) {
        got = "Register";
    } else if (0 == strncmp(found, "04", 2)) {
        got = "Rekey";
    } else if (0 == strncmp(found, "05", 2)) {
        got = "Derive_Key";
    } else if (0 == strncmp(found, "06", 2)) {
        got = "Certify";
    } else if (0 == strncmp(found, "07", 2)) {
        got = "Recertify";
    } else if (0 == strncmp(found, "08", 2)) {
        got = "Locate";
    } else if (0 == strncmp(found, "09", 2)) {
        got = "Check";
    } else if (0 == strncmp(found, "0a", 2)) {
        got = "Get";
    } else if (0 == strncmp(found, "0b", 2)) {
        got = "Get_Attributes";
    } else if (0 == strncmp(found, "0c", 2)) {
        got = "Get_Attribute_List";
    } else if (0 == strncmp(found, "0d", 2)) {
        got = "Add_Attribute";
    } else if (0 == strncmp(found, "0e", 2)) {
        got = "Modify_Attribute";
    } else if (0 == strncmp(found, "0f", 2)) {
        got = "Delete_Attribute";
    } else if (0 == strncmp(found, "10", 2)) {
        got = "Obtain_Lease";
    } else if (0 == strncmp(found, "11", 2)) {
        got = "Get_Usage_Allocation";
    } else if (0 == strncmp(found, "12", 2)) {
        got = "Activate";
    } else if (0 == strncmp(found, "13", 2)) {
        got = "Revoke";
    } else if (0 == strncmp(found, "14", 2)) {
        got = "Destroy";
    } else if (0 == strncmp(found, "15", 2)) {
        got = "Archive";
    } else if (0 == strncmp(found, "16", 2)) {
        got = "Recover";
    } else if (0 == strncmp(found, "17", 2)) {
        got = "Validate";
    } else if (0 == strncmp(found, "18", 2)) {
        got = "Query";
    } else if (0 == strncmp(found, "19", 2)) {
        got = "Cancel";
    } else if (0 == strncmp(found, "1a", 2)) {
        got = "Poll";
    } else if (0 == strncmp(found, "1b", 2)) {
        got = "Notify";
    } else if (0 == strncmp(found, "1c", 2)) {
        got = "Put";
    }
    bson_free(as_hex);
    return got;
}

/*
clang-format off

`KMIP_REGISTER_RESPONSE` represents:

<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="0"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2023-12-20T13:28:43-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="3"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <UniqueIdentifier tag="0x420094" type="TextString" value="12"/>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>

clang-format on
*/
static const uint8_t KMIP_REGISTER_RESPONSE[] = {
    0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x00, 0x90, 0x42, 0x00, 0x7a, 0x01, 0x00, 0x00, 0x00, 0x48, 0x42, 0x00, 0x69,
    0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x65, 0x82, 0xec, 0x0b, 0x42, 0x00, 0x0d, 0x02,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00,
    0x38, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
    0x7f, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7c, 0x01, 0x00,
    0x00, 0x00, 0x10, 0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x02, 0x31, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
clang-format off

`KMIP_ACTIVATE_RESPONSE` represents:

<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="0"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2023-12-20T13:28:43-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="18"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <UniqueIdentifier tag="0x420094" type="TextString" value="12"/>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>

clang-format on
*/
static const uint8_t KMIP_ACTIVATE_RESPONSE[] = {
    0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x00, 0x90, 0x42, 0x00, 0x7a, 0x01, 0x00, 0x00, 0x00, 0x48, 0x42, 0x00, 0x69,
    0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x65, 0x82, 0xec, 0x0b, 0x42, 0x00, 0x0d, 0x02,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00,
    0x38, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
    0x7f, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7c, 0x01, 0x00,
    0x00, 0x00, 0x10, 0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x02, 0x31, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
clang-format off

`KMIP_GET_RESPONSE` represents:

<ResponseMessage tag="0x42007b" type="Structure">
 <ResponseHeader tag="0x42007a" type="Structure">
  <ProtocolVersion tag="0x420069" type="Structure">
   <ProtocolVersionMajor tag="0x42006a" type="Integer" value="1"/>
   <ProtocolVersionMinor tag="0x42006b" type="Integer" value="0"/>
  </ProtocolVersion>
  <TimeStamp tag="0x420092" type="DateTime" value="2023-12-20T13:28:43-0500"/>
  <BatchCount tag="0x42000d" type="Integer" value="1"/>
 </ResponseHeader>
 <BatchItem tag="0x42000f" type="Structure">
  <Operation tag="0x42005c" type="Enumeration" value="10"/>
  <ResultStatus tag="0x42007f" type="Enumeration" value="0"/>
  <ResponsePayload tag="0x42007c" type="Structure">
   <ObjectType tag="0x420057" type="Enumeration" value="7"/>
   <UniqueIdentifier tag="0x420094" type="TextString" value="12"/>
   <SecretData tag="0x420085" type="Structure">
    <SecretDataType tag="0x420086" type="Enumeration" value="2"/>
    <KeyBlock tag="0x420040" type="Structure">
     <KeyFormatType tag="0x420042" type="Enumeration" value="2"/>
     <KeyValue tag="0x420045" type="Structure">
      <KeyMaterial tag="0x420043" type="ByteString" value="e6e4b2504fc61c4e8e45691b1719d5d6618b749167100683f4f8e55df1f22ad3cbba2ab421ed9daeb73bc25c031ade820580a5c75518ab21379b3936effbcfcda146b21671f2cf9f8012b0e183d719166481075d6c3932a5aed5411f0c26e157"/>
     </KeyValue>
    </KeyBlock>
   </SecretData>
  </ResponsePayload>
 </BatchItem>
</ResponseMessage>

clang-format on
*/
static const uint8_t KMIP_GET_RESPONSE[] = {
    0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x01, 0x40, 0x42, 0x00, 0x7a, 0x01, 0x00, 0x00, 0x00, 0x48, 0x42, 0x00, 0x69,
    0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    0x00, 0x92, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x65, 0x82, 0xec, 0x0b, 0x42, 0x00, 0x0d, 0x02,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00,
    0xe8, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
    0x7f, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7c, 0x01, 0x00,
    0x00, 0x00, 0xc0, 0x42, 0x00, 0x57, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x02, 0x31, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x85,
    0x01, 0x00, 0x00, 0x00, 0x98, 0x42, 0x00, 0x86, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x42, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x80, 0x42, 0x00, 0x42, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x45, 0x01, 0x00, 0x00, 0x00, 0x68, 0x42, 0x00, 0x43, 0x08,
    0x00, 0x00, 0x00, 0x60, 0xe6, 0xe4, 0xb2, 0x50, 0x4f, 0xc6, 0x1c, 0x4e, 0x8e, 0x45, 0x69, 0x1b, 0x17, 0x19, 0xd5,
    0xd6, 0x61, 0x8b, 0x74, 0x91, 0x67, 0x10, 0x06, 0x83, 0xf4, 0xf8, 0xe5, 0x5d, 0xf1, 0xf2, 0x2a, 0xd3, 0xcb, 0xba,
    0x2a, 0xb4, 0x21, 0xed, 0x9d, 0xae, 0xb7, 0x3b, 0xc2, 0x5c, 0x03, 0x1a, 0xde, 0x82, 0x05, 0x80, 0xa5, 0xc7, 0x55,
    0x18, 0xab, 0x21, 0x37, 0x9b, 0x39, 0x36, 0xef, 0xfb, 0xcf, 0xcd, 0xa1, 0x46, 0xb2, 0x16, 0x71, 0xf2, 0xcf, 0x9f,
    0x80, 0x12, 0xb0, 0xe1, 0x83, 0xd7, 0x19, 0x16, 0x64, 0x81, 0x07, 0x5d, 0x6c, 0x39, 0x32, 0xa5, 0xae, 0xd5, 0x41,
    0x1f, 0x0c, 0x26, 0xe1, 0x57};

static void test_configuring_named_kms_providers(_mongocrypt_tester_t *tester) {
    // Test that a named KMS provider can be set.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:name1" : {"key" : "%s"}}),
                      LOCAL_KEK1_BASE64,
                      LOCAL_KEK2_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that an unrecognized named KMS provider errors.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"foo:bar" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "unrecognized type");
        mongocrypt_destroy(crypt);
    }

    // Test character validation. Only valid characters are: [a-zA-Z0-9_]
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local:name_with_invalid_character_?" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "unsupported character `?`");
        mongocrypt_destroy(crypt);
    }

    // Test configuring a named KMS provider with an empty document is prohibited.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {}}));
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "Unexpected empty document for named KMS provider");
        mongocrypt_destroy(crypt);

        // An empty document is allowed for a non-named KMS provider to configure on-demand credentials.
        crypt = mongocrypt_new();
        kms_providers = TEST_BSON(BSON_STR({"local" : {}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that duplicate named KMS providers is an error.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}, "local:name1" : {"key" : "%s"}}),
                      LOCAL_KEK1_BASE64,
                      LOCAL_KEK2_BASE64);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt, "duplicate entry");
        mongocrypt_destroy(crypt);
    }

    // Test that a named KMS provider can be set with Azure.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({
                          "local" : {"key" : "%s"},
                          "azure:name1" : {
                              "tenantId" : "placeholder1-tenantId",
                              "clientId" : "placeholder1-clientId",
                              "clientSecret" : "placeholder1-clientSecret",
                              "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
                          }
                      }),
                      LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that only configuring named KMS provider is OK.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test configuring with an empty name is an error.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt, "empty name");
        mongocrypt_destroy(crypt);
    }
}

static void test_create_datakey_with_named_kms_provider(_mongocrypt_tester_t *tester) {
    // Test creating with an unconfigured KMS provider.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested kms provider not configured: `local:not_configured`");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating with an unconfigured KMS provider, when provider of same type is configured.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:name1" : {"key" : "%s"}}),
                      LOCAL_KEK1_BASE64,
                      LOCAL_KEK2_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested kms provider not configured: `local:not_configured`");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating with an unconfigured KMS provider, when provider of same type is configured with an
    // empty document.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local" : {}, "local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64, LOCAL_KEK2_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        mongocrypt_setopt_use_need_kms_credentials_state(crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested kms provider required by datakey is not configured: `local:not_configured`");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating a local DEK with a named KMS provider.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:name1"}))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "local:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an Azure DEK with a named KMS provider
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
            "azure:name1" : {
                "tenantId" : "placeholder1-tenantId",
                "clientId" : "placeholder1-clientId",
                "clientSecret" : "placeholder1-clientSecret",
                "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
            }
        }));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:name1",
                                                               "keyName" : "placeholder1-keyName",
                                                               "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an Azure DEK when `accessToken` is passed.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"azure:name1" : {"accessToken" : "foo"}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:name1",
                                                               "keyName" : "placeholder1-keyName",
                                                               "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating two Azure keys with different named providers.
    // This is intended to test that they do not share cache entries.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
            "azure:name1" : {
                "tenantId" : "placeholder1-tenantId",
                "clientId" : "placeholder1-clientId",
                "clientSecret" : "placeholder1-clientSecret",
                "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
            },
            "azure:name2" : {
                "tenantId" : "placeholder2-tenantId",
                "clientId" : "placeholder2-clientId",
                "clientSecret" : "placeholder2-clientSecret",
                "identityPlatformEndpoint" : "placeholder2-identityPlatformEndpoint.com"
            }
        }));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with `azure:name1`.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(
                mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                             "provider" : "azure:name1",
                                                             "keyName" : "placeholder1-keyName",
                                                             "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                                         }))),
                ctx);
            ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to encrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/encrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            // Check that `out` contains name.
            bson_t out_bson;
            ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
            char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name1"}});
            _assert_match_bson(&out_bson, TMP_BSON(pattern));
            bson_destroy(&out_bson);
            mongocrypt_binary_destroy(out);
            mongocrypt_ctx_destroy(ctx);
        }

        // Create with `azure:name2`. Expect a separate oauth token is needed.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(
                mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                             "provider" : "azure:name2",
                                                             "keyName" : "placeholder2-keyName",
                                                             "keyVaultEndpoint" : "placeholder2-keyVaultEndpoint.com"
                                                         }))),
                ctx);
            ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to encrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/encrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            // Check that `out` contains name.
            bson_t out_bson;
            ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
            char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:name2"}});
            _assert_match_bson(&out_bson, TMP_BSON(pattern));
            bson_destroy(&out_bson);
            mongocrypt_binary_destroy(out);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an KMIP DEK with a named KMS provider
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"kmip:name1" : {"endpoint" : "placeholder1-endpoint.com"}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx,
                                                     TEST_BSON(BSON_STR({"provider" : "kmip:name1", "keyId" : "12"}))),
            ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS to Get KEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:5696");
            // Assert request is a Get.
            {
                mongocrypt_binary_t *request = mongocrypt_binary_new();
                ASSERT_OK(mongocrypt_kms_ctx_message(kctx, request), kctx);
                ASSERT_STREQUAL(kmip_get_operation_type(request), "Get");
                mongocrypt_binary_destroy(request);
            }
            // Feed response to Get.
            ASSERT_OK(kms_ctx_feed_all(kctx, KMIP_GET_RESPONSE, (uint32_t)(sizeof(KMIP_GET_RESPONSE))), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "kmip:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test creating a KMIP key when `keyId` is not passed.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"kmip:name1" : {"endpoint" : "placeholder1-endpoint.com"}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "kmip:name1"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS to Register KEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:5696");
            // Assert request is a Register.
            {
                mongocrypt_binary_t *request = mongocrypt_binary_new();
                ASSERT_OK(mongocrypt_kms_ctx_message(kctx, request), kctx);
                ASSERT_STREQUAL(kmip_get_operation_type(request), "Register");
                mongocrypt_binary_destroy(request);
            }
            // Feed response to Register.
            ASSERT_OK(kms_ctx_feed_all(kctx, KMIP_REGISTER_RESPONSE, (uint32_t)(sizeof(KMIP_REGISTER_RESPONSE))), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to Activate KEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:5696");
            // Assert request is a Activate.
            {
                mongocrypt_binary_t *request = mongocrypt_binary_new();
                ASSERT_OK(mongocrypt_kms_ctx_message(kctx, request), kctx);
                ASSERT_STREQUAL(kmip_get_operation_type(request), "Activate");
                mongocrypt_binary_destroy(request);
            }
            // Feed response to Activate.
            ASSERT_OK(kms_ctx_feed_all(kctx, KMIP_ACTIVATE_RESPONSE, (uint32_t)(sizeof(KMIP_ACTIVATE_RESPONSE))), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to Get KEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:5696");
            // Assert request is a Get.
            {
                mongocrypt_binary_t *request = mongocrypt_binary_new();
                ASSERT_OK(mongocrypt_kms_ctx_message(kctx, request), kctx);
                ASSERT_STREQUAL(kmip_get_operation_type(request), "Get");
                mongocrypt_binary_destroy(request);
            }
            // Feed response to Get.
            ASSERT_OK(kms_ctx_feed_all(kctx, KMIP_GET_RESPONSE, (uint32_t)(sizeof(KMIP_GET_RESPONSE))), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "kmip:name1"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

typedef struct {
    mongocrypt_binary_t *kms_providers;
    const char *key_alt_name;
    mongocrypt_binary_t *kek;
    mongocrypt_binary_t *kms_response_1;
    mongocrypt_binary_t *kms_response_2;
} create_dek_args;

// `create_dek` is a test helper to create a Data Encryption Key (DEK).
static void create_dek(_mongocrypt_tester_t *tester, create_dek_args args, _mongocrypt_buffer_t *dek) {
    BSON_ASSERT_PARAM(args.kms_providers);
    BSON_ASSERT_PARAM(args.key_alt_name);
    BSON_ASSERT_PARAM(args.kek);
    // kms_response_1 and kms_response_2 may be NULL.

    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, args.kms_providers), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, args.kek), ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "%s"}), args.key_alt_name)),
              ctx);
    ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

    if (args.kms_response_1) {
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx);
        ASSERT_OK(kms_ctx_feed_all(kctx,
                                   mongocrypt_binary_data(args.kms_response_1),
                                   mongocrypt_binary_len(args.kms_response_1)),
                  kctx);
        kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(!kctx);
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    if (args.kms_response_2) {
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx);
        ASSERT_OK(kms_ctx_feed_all(kctx,
                                   mongocrypt_binary_data(args.kms_response_2),
                                   mongocrypt_binary_len(args.kms_response_2)),
                  kctx);
        kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(!kctx);
        ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
    }

    ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
    mongocrypt_binary_t *bin = mongocrypt_binary_new();
    ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
    _mongocrypt_buffer_copy_from_binary(dek, bin);
    mongocrypt_binary_destroy(bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

static void test_explicit_with_named_kms_provider_for_azure(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
        "azure:name1" : {
            "tenantId" : "placeholder1-tenantId",
            "clientId" : "placeholder1-clientId",
            "clientSecret" : "placeholder1-clientSecret",
            "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
        },
        "azure:name2" : {
            "tenantId" : "placeholder2-tenantId",
            "clientId" : "placeholder2-clientId",
            "clientSecret" : "placeholder2-clientSecret",
            "identityPlatformEndpoint" : "placeholder2-identityPlatformEndpoint.com"
        }
    }));

    // Create `dek1` from `azure:name1`
    _mongocrypt_buffer_t dek1;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "azure1",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "azure:name1",
                                     "keyName" : "placeholder1-keyName",
                                     "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-azure/oauth-response.txt"),
                                 .kms_response_2 = TEST_FILE("./test/data/kms-azure/encrypt-response.txt")},
               &dek1);

    // Create `dek2` from `azure:name2`
    _mongocrypt_buffer_t dek2;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "azure2",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "azure:name2",
                                     "keyName" : "placeholder2-keyName",
                                     "keyVaultEndpoint" : "placeholder2-keyVaultEndpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-azure/oauth-response.txt"),
                                 .kms_response_2 = TEST_FILE("./test/data/kms-azure/encrypt-response.txt")},
               &dek2);

    // Test encrypting.
    _mongocrypt_buffer_t ciphertext;
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test encrypting without cached DEK. Store result for later decryption.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            _mongocrypt_buffer_copy_from_binary(&ciphertext, bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test encrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        mongocrypt_destroy(crypt);
    }

    // Test decrypting.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test decrypting without cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test decrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    // Test decrypting with a cached oauth token, but not a cached DEK.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Decrypt.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Recreate the `mongocrypt_ctx_t`. Expect the oauth token to be cached but the DEK not to be cached.
        mongocrypt_ctx_destroy(ctx);

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS to decrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test encrypting with two different named Azure.
    // Expect two separate oauth token requests.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Encrypt with azure:name1
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Encrypt with azure:name2
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure2"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek2)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-identityPlatformEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    // Test encrypting when access token is included in KMS providers.
    {
        mongocrypt_t *crypt = mongocrypt_new();

        mongocrypt_binary_t *kms_providers_withAccessToken =
            TEST_BSON(BSON_STR({"azure:name3_withAccessToken" : {"accessToken" : "placeholder3-accesstoken"}}));

        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers_withAccessToken), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create `dek3` from `azure:name3_withAccessToken`
        _mongocrypt_buffer_t dek3;
        create_dek(tester,
                   (create_dek_args){.kms_providers = kms_providers_withAccessToken,
                                     .key_alt_name = "azure3",
                                     .kek = TEST_BSON(BSON_STR({
                                         "provider" : "azure:name3_withAccessToken",
                                         "keyName" : "placeholder3-keyName",
                                         "keyVaultEndpoint" : "placeholder3-keyVaultEndpoint.com"
                                     })),
                                     // Does not need KMS for oauth token.
                                     .kms_response_1 = TEST_FILE("./test/data/kms-azure/encrypt-response.txt")},
                   &dek3);

        // Encrypt with `dek3`.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure3"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek3)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Does not need KMS for oauth token.

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder3-keyVaultEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        _mongocrypt_buffer_cleanup(&dek3);
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&dek2);
    _mongocrypt_buffer_cleanup(&dek1);
}

static void test_explicit_with_named_kms_provider_for_gcp(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers = TEST_BSON(
        BSON_STR({
            "gcp:name1" :
                {"email" : "placeholder1-email", "privateKey" : "%s", "endpoint" : "placeholder1-oauthEndpoint.com"},
            "gcp:name2" :
                {"email" : "placeholder2-email", "privateKey" : "%s", "endpoint" : "placeholder2-oauthEndpoint.com"}
        }),
        GCP_PRIVATEKEY1,
        GCP_PRIVATEKEY2);

    // Create `dek1` from `gcp:name1`
    _mongocrypt_buffer_t dek1;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "gcp1",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "gcp:name1",
                                     "projectId" : "placeholder1-projectId",
                                     "location" : "placeholder1-location",
                                     "keyRing" : "placeholder1-keyRing",
                                     "keyName" : "placeholder1-keyName",
                                     "endpoint" : "placeholder1-kmsEndpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-gcp/oauth-response.txt"),
                                 .kms_response_2 = TEST_FILE("./test/data/kms-gcp/encrypt-response.txt")},
               &dek1);

    // Create `dek2` from `gcp:name2`
    _mongocrypt_buffer_t dek2;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "gcp2",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "gcp:name2",
                                     "projectId" : "placeholder2-projectId",
                                     "location" : "placeholder2-location",
                                     "keyRing" : "placeholder2-keyRing",
                                     "keyName" : "placeholder2-keyName",
                                     "endpoint" : "placeholder2-kmsEndpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-gcp/oauth-response.txt"),
                                 .kms_response_2 = TEST_FILE("./test/data/kms-gcp/encrypt-response.txt")},
               &dek2);

    // Test encrypting.
    _mongocrypt_buffer_t ciphertext;
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test encrypting without cached DEK. Store result for later decryption.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-oauthEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-kmsEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            _mongocrypt_buffer_copy_from_binary(&ciphertext, bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test encrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        mongocrypt_destroy(crypt);
    }

    // Test decrypting.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test decrypting without cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-oauthEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-kmsEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test decrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    // Test decrypting with a cached oauth token, but not a cached DEK.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Decrypt.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-oauthEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Recreate the `mongocrypt_ctx_t`. Expect the oauth token to be cached but the DEK not to be cached.
        mongocrypt_ctx_destroy(ctx);

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS to decrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-kmsEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test encrypting with two different named Gcp.
    // Expect two separate oauth token requests.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Encrypt with gcp:name1
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-oauthEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-kmsEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Encrypt with gcp:name2
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp2"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek2)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS for oauth token.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-oauthEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder2-kmsEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    // Test calling `mongocrypt_ctx_kms_done` before responding to an oauth request.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp1"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
        ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_FAILS(mongocrypt_ctx_kms_done(ctx), ctx, "KMS response unfinished");
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test calling `mongocrypt_ctx_kms_done` before responding to a decrypt request.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp1"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
        ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-oauthEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to decrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-kmsEndpoint.com:443");
            ASSERT_FAILS(mongocrypt_ctx_kms_done(ctx), ctx, "KMS response unfinished");
        }

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test encrypting when access token is included in KMS providers.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers_withAccessToken =
            TEST_BSON(BSON_STR({"gcp:name3_withAccessToken" : {"accessToken" : "placeholder3-accesstoken"}}));

        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers_withAccessToken), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create `dek3` from `gcp:name3_withAccessToken`
        _mongocrypt_buffer_t dek3;
        {
            create_dek(tester,
                       (create_dek_args){.kms_providers = kms_providers_withAccessToken,
                                         .key_alt_name = "gcp3",
                                         .kek = TEST_BSON(BSON_STR({
                                             "provider" : "gcp:name3_withAccessToken",
                                             "projectId" : "placeholder3-projectId",
                                             "location" : "placeholder3-location",
                                             "keyRing" : "placeholder3-keyRing",
                                             "keyName" : "placeholder3-keyName",
                                             "endpoint" : "placeholder3-kmsEndpoint.com"
                                         })),
                                         // Does not need KMS for oauth token.

                                         .kms_response_1 = TEST_FILE("./test/data/kms-gcp/encrypt-response.txt")},
                       &dek3);
        }

        // Encrypt with `dek3`.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "gcp3"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek3)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Does not need KMS for oauth token.

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder3-kmsEndpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-gcp/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        _mongocrypt_buffer_cleanup(&dek3);
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&dek2);
    _mongocrypt_buffer_cleanup(&dek1);
}

static void test_explicit_with_named_kms_provider_for_aws(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
        "aws:name1" : {"accessKeyId" : "placeholder1-aki", "secretAccessKey" : "placeholder1-sak"},
        "aws:name2" : {"accessKeyId" : "placeholder2-aki", "secretAccessKey" : "placeholder2-sak"}
    }));

    // Create `dek1` from `aws:name1`
    _mongocrypt_buffer_t dek1;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "aws1",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "aws:name1",
                                     "region" : "placeholder1-region",
                                     "key" : "placeholder1-key",
                                     "endpoint" : "placeholder1-endpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-aws/encrypt-response.txt")},
               &dek1);

    // Create `dek2` from `aws:name2`
    _mongocrypt_buffer_t dek2;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "aws2",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "aws:name2",
                                     "region" : "placeholder2-region",
                                     "key" : "placeholder2-key",
                                     "endpoint" : "placeholder2-endpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-aws/encrypt-response.txt")},
               &dek2);

    // Test encrypting.
    _mongocrypt_buffer_t ciphertext;
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test encrypting without cached DEK. Store result for later decryption.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "aws1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-aws/decrypt-response.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            _mongocrypt_buffer_copy_from_binary(&ciphertext, bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test encrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "aws1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        mongocrypt_destroy(crypt);
    }

    // Test decrypting.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test decrypting without cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS to decrypt DEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:443");
                ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/example/kms-decrypt-reply.txt")), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test decrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&dek2);
    _mongocrypt_buffer_cleanup(&dek1);
}

static void test_explicit_with_named_kms_provider_for_kmip(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
        "kmip:name1" : {"endpoint" : "placeholder1-endpoint.com"},
        "kmip:name2" : {"endpoint" : "placeholder2-endpoint.com"}
    }));

    mongocrypt_binary_t *get_response =
        mongocrypt_binary_new_from_data((uint8_t *)KMIP_GET_RESPONSE, (uint32_t)sizeof(KMIP_GET_RESPONSE));

    // Create `dek1` from `kmip:name1`
    _mongocrypt_buffer_t dek1;

    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "kmip1",
                                 .kek = TEST_BSON(BSON_STR({"provider" : "kmip:name1", "keyId" : "12"})),
                                 .kms_response_1 = get_response},
               &dek1);

    // Create `dek2` from `kmip:name2`
    _mongocrypt_buffer_t dek2;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "kmip2",
                                 .kek = TEST_BSON(BSON_STR({"provider" : "kmip:name2", "keyId" : "12"})),
                                 .kms_response_1 = get_response},
               &dek2);

    // Test encrypting.
    _mongocrypt_buffer_t ciphertext;
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test encrypting without cached DEK. Store result for later decryption.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "kmip1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS to Get KEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:5696");
                // Assert request is a Get.
                {
                    mongocrypt_binary_t *request = mongocrypt_binary_new();
                    ASSERT_OK(mongocrypt_kms_ctx_message(kctx, request), kctx);
                    ASSERT_STREQUAL(kmip_get_operation_type(request), "Get");
                    mongocrypt_binary_destroy(request);
                }
                // Feed response to Get.
                ASSERT_OK(kms_ctx_feed_all(kctx, KMIP_GET_RESPONSE, (uint32_t)(sizeof(KMIP_GET_RESPONSE))), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            _mongocrypt_buffer_copy_from_binary(&ciphertext, bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test encrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "kmip1"}))), ctx);
            ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
            ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        mongocrypt_destroy(crypt);
    }

    // Test decrypting.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Test decrypting without cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

            // Needs KMS to Get KEK.
            {
                ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
                mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(kctx);
                const char *endpoint;
                ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
                ASSERT_STREQUAL(endpoint, "placeholder1-endpoint.com:5696");
                // Assert request is a Get.
                {
                    mongocrypt_binary_t *request = mongocrypt_binary_new();
                    ASSERT_OK(mongocrypt_kms_ctx_message(kctx, request), kctx);
                    ASSERT_STREQUAL(kmip_get_operation_type(request), "Get");
                    mongocrypt_binary_destroy(request);
                }
                // Feed response to Get.
                ASSERT_OK(kms_ctx_feed_all(kctx, KMIP_GET_RESPONSE, (uint32_t)(sizeof(KMIP_GET_RESPONSE))), kctx);
                kctx = mongocrypt_ctx_next_kms_ctx(ctx);
                ASSERT(!kctx);
                ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
            }

            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }

        // Test decrypting with cached DEK.
        {
            mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
            ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
            // DEK is already cached. State transitions directly to ready.
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
            mongocrypt_binary_t *bin = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
            mongocrypt_binary_destroy(bin);
            mongocrypt_ctx_destroy(ctx);
        }
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&dek2);
    _mongocrypt_buffer_cleanup(&dek1);
    mongocrypt_binary_destroy(get_response);
}

static void test_rewrap_with_named_kms_provider_local2local(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers =
        TEST_BSON(BSON_STR({"local:name1" : {"key" : "%s"}, "local:name2" : {"key" : "%s"}}),
                  LOCAL_KEK1_BASE64,
                  LOCAL_KEK2_BASE64);

    // Create `dek1` from `local:name1`
    _mongocrypt_buffer_t dek1;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "local1",
                                 .kek = TEST_BSON(BSON_STR({"provider" : "local:name1"}))},
               &dek1);

    // Rewrap `dek1` with `local:name2`.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:name2"}))),
                  ctx);
        mongocrypt_binary_t *filter = TEST_BSON(BSON_STR({}));
        ASSERT_OK(mongocrypt_ctx_rewrap_many_datakey_init(ctx, filter), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        // Check resulting document contains expected name.
        {
            bson_t bin_bson;
            ASSERT(_mongocrypt_binary_to_bson(bin, &bin_bson));
            char *pattern = BSON_STR({"v" : [ {"masterKey" : {"provider" : "local:name2"}} ]});
            _assert_match_bson(&bin_bson, TMP_BSON(pattern));
        }
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&dek1);
}

static void test_rewrap_with_named_kms_provider_azure2azure(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
        "azure:name1" : {
            "tenantId" : "placeholder1-tenantId",
            "clientId" : "placeholder1-clientId",
            "clientSecret" : "placeholder1-clientSecret",
            "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
        },
        "azure:name2" : {
            "tenantId" : "placeholder2-tenantId",
            "clientId" : "placeholder2-clientId",
            "clientSecret" : "placeholder2-clientSecret",
            "identityPlatformEndpoint" : "placeholder2-identityPlatformEndpoint.com"
        }
    }));

    // Create `dek1` from `azure:name1`
    _mongocrypt_buffer_t dek1;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "azure1",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "azure:name1",
                                     "keyName" : "placeholder1-keyName",
                                     "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-azure/oauth-response.txt"),
                                 .kms_response_2 = TEST_FILE("./test/data/kms-azure/encrypt-response.txt")},
               &dek1);

    // Rewrap `dek1` with `azure:name2`.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:name2",
                                                               "keyName" : "placeholder2-keyName",
                                                               "keyVaultEndpoint" : "placeholder2-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        mongocrypt_binary_t *filter = TEST_BSON(BSON_STR({}));
        ASSERT_OK(mongocrypt_ctx_rewrap_many_datakey_init(ctx, filter), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token from azure:name1.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to decrypt DEK from azure:name1.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS for oauth token from azure:name2.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder2-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder2-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        // Check resulting document contains expected name.
        {
            bson_t bin_bson;
            ASSERT(_mongocrypt_binary_to_bson(bin, &bin_bson));
            char *pattern = BSON_STR({"v" : [ {"masterKey" : {"provider" : "azure:name2"}} ]});
            _assert_match_bson(&bin_bson, TMP_BSON(pattern));
        }
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&dek1);
}

static void test_rewrap_with_named_kms_provider_azure2local(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers =
        TEST_BSON(BSON_STR({
                      "azure:name1" : {
                          "tenantId" : "placeholder1-tenantId",
                          "clientId" : "placeholder1-clientId",
                          "clientSecret" : "placeholder1-clientSecret",
                          "identityPlatformEndpoint" : "placeholder1-identityPlatformEndpoint.com"
                      },
                      "local:name1" : {"key" : "%s"}
                  }),
                  LOCAL_KEK1_BASE64);

    // Create `dek1` from `azure:name1`
    _mongocrypt_buffer_t dek1;
    create_dek(tester,
               (create_dek_args){.kms_providers = kms_providers,
                                 .key_alt_name = "azure1",
                                 .kek = TEST_BSON(BSON_STR({
                                     "provider" : "azure:name1",
                                     "keyName" : "placeholder1-keyName",
                                     "keyVaultEndpoint" : "placeholder1-keyVaultEndpoint.com"
                                 })),
                                 .kms_response_1 = TEST_FILE("./test/data/kms-azure/oauth-response.txt"),
                                 .kms_response_2 = TEST_FILE("./test/data/kms-azure/encrypt-response.txt")},
               &dek1);

    // Rewrap `dek1` with `local:name1`.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:name1"}))),
                  ctx);
        mongocrypt_binary_t *filter = TEST_BSON(BSON_STR({}));
        ASSERT_OK(mongocrypt_ctx_rewrap_many_datakey_init(ctx, filter), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek1)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token from azure:name1.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to decrypt DEK from azure:name1.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder1-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/kms-azure/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        // Check resulting document contains expected name.
        {
            bson_t bin_bson;
            ASSERT(_mongocrypt_binary_to_bson(bin, &bin_bson));
            char *pattern = BSON_STR({"v" : [ {"masterKey" : {"provider" : "local:name1"}} ]});
            _assert_match_bson(&bin_bson, TMP_BSON(pattern));
        }
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    _mongocrypt_buffer_cleanup(&dek1);
}

static void test_mongocrypt_kms_ctx_get_kms_provider(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *kms_providers =
        TEST_BSON(BSON_STR({"kmip:name1" : {"endpoint" : "placeholder1-endpoint.com"}}));

    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    ASSERT_OK(
        mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "kmip:name1", "keyId" : "12"}))),
        ctx);
    ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "kmip1"}))), ctx);
    ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

    // Needs KMS to Get KEK.
    {
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
        mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
        ASSERT(kctx);
        ASSERT_STREQUAL(mongocrypt_kms_ctx_get_kms_provider(kctx, NULL /* len */), "kmip:name1");
    }

    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_named_kms_providers(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_configuring_named_kms_providers);
    INSTALL_TEST(test_create_datakey_with_named_kms_provider);
    INSTALL_TEST(test_explicit_with_named_kms_provider_for_azure);
    INSTALL_TEST(test_explicit_with_named_kms_provider_for_gcp);
    INSTALL_TEST(test_explicit_with_named_kms_provider_for_aws);
    INSTALL_TEST(test_explicit_with_named_kms_provider_for_kmip);
    INSTALL_TEST(test_rewrap_with_named_kms_provider_local2local);
    INSTALL_TEST(test_rewrap_with_named_kms_provider_azure2azure);
    INSTALL_TEST(test_rewrap_with_named_kms_provider_azure2local);
    INSTALL_TEST(test_mongocrypt_kms_ctx_get_kms_provider);
}
