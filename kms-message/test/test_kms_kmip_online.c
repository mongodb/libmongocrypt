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

#include "kms_message/kms_kmip_request.h"
#include "kms_message/kms_kmip_response.h"
#include "kms_message/kms_kmip_response_parser.h"

#define MONGOC_LOG_DOMAIN "test_kms_kmip_online"
#include <mongoc/mongoc.h>

#include "test_kms.h"
#include "test_kms_request.h"

#include <stdio.h>

#include "src/kms_kmip_reader_writer_private.h"
#include "test_kms_online_util.h"

#include "src/hexlify.h"

/* Define TEST_TRACING_INSECURE in compiler flags to enable
 * log output with sensitive information (for debugging). */
#ifdef TEST_TRACING_INSECURE
#define TEST_TRACE(...) MONGOC_DEBUG (__VA_ARGS__)
#else
#define TEST_TRACE(...) (void) 0
#endif

#define NETWORK_TIMEOUT_MS 10000
#define BUF_SIZE 1024

typedef struct {
   const char *kmip_host;
   const char *kmip_port;
   const char *kmip_client_certificate;
   const char *kmip_ca_certificate;
} test_env_t;

static char *
test_getenv (const char *key)
{
   char *value = getenv (key);
   if (!value) {
      TEST_ERROR ("Environment variable: %s not set", key);
   }
   TEST_TRACE ("Env: %s = %s", key, value);
   return value;
}

static void
test_env_init (test_env_t *test_env)
{
   test_env->kmip_host = test_getenv ("KMIP_HOST");
   test_env->kmip_port = test_getenv ("KMIP_PORT");
   test_env->kmip_client_certificate = test_getenv ("KMIP_CLIENT_CERTIFICATE");
   test_env->kmip_ca_certificate = test_getenv ("KMIP_CA_CERTIFICATE");
}

static kms_kmip_response_t *
send_kms_kmip_request (kms_kmip_request_t *req, test_env_t *test_env)
{
   mongoc_stream_t *stream;
   mongoc_ssl_opt_t ssl_opt = {0};
   bson_error_t error;
   uint8_t *message_bytes;
   uint32_t message_len;
   ssize_t write_ret;
   kms_kmip_response_parser_t *parser;
   int32_t wants_bytes;
   int32_t bytes_read;
   uint8_t buf[BUF_SIZE];
   kms_status_t *status;
   kms_kmip_response_t *res;
   uint8_t* resbytes;
   uint32_t reslen;
   char *debugstr;

   MONGOC_DEBUG ("connecting to KMIP server");
   ssl_opt.ca_file = test_env->kmip_ca_certificate;
   ssl_opt.pem_file = test_env->kmip_client_certificate;
   stream =
      connect_with_tls (test_env->kmip_host, test_env->kmip_port, &ssl_opt);
   if (!mongoc_stream_tls_handshake_block (
          stream, test_env->kmip_host, NETWORK_TIMEOUT_MS, &error)) {
      TEST_ERROR ("failed to connect to KMIP server (%s:%s): %s",
                  test_env->kmip_host,
                  test_env->kmip_port,
                  error.message);
   }

   MONGOC_DEBUG ("writing request to KMIP server");
   message_bytes = kms_kmip_request_to_bytes (req, &message_len);
   debugstr = kmip_dump (message_bytes, message_len);
   printf ("%s\n", debugstr);
   free (debugstr);
   write_ret = mongoc_stream_write (
      stream, (void *) message_bytes, message_len, NETWORK_TIMEOUT_MS);
   TEST_ASSERT (write_ret == message_len);

   MONGOC_DEBUG ("reading response from KMIP server");
   status = kms_status_new ();

   parser = kms_kmip_response_parser_new ();
   wants_bytes = kms_kmip_response_parser_wants_bytes (parser, BUF_SIZE);
   while (wants_bytes > 0) {
      bytes_read = (int32_t) mongoc_stream_read (
         stream, buf, wants_bytes, 0, NETWORK_TIMEOUT_MS);
      ASSERT_CMPINT (bytes_read, >=, 0);
      if (!kms_kmip_response_parser_feed (
             parser, buf, (uint32_t) bytes_read, status)) {
         TEST_ERROR ("error parsing response: %s",
                     kms_status_to_string (status));
      }
      wants_bytes = kms_kmip_response_parser_wants_bytes (parser, BUF_SIZE);
   }
   ASSERT_CMPINT (wants_bytes, ==, 0);

   res = kms_kmip_response_parser_get_response (parser, status);
   if (!res) {
      TEST_ERROR ("error in kms_response_parser_get_response: %s",
                  kms_status_to_string (status));
   }

   kms_kmip_response_parser_destroy (parser);
   mongoc_stream_close (stream);
   mongoc_stream_destroy (stream);
   kms_status_destroy (status);

   resbytes = kms_kmip_response_to_bytes (res, &reslen);
   debugstr = kmip_dump (resbytes, reslen);
   char * reshex = hexlify (resbytes, reslen);
   printf ("%s\n", debugstr);
   printf ("as hex:\n%s\n", reshex);
   free (debugstr);
   return res;
}

static char *
kmip_register_and_activate_secretdata (void)
{
   test_env_t test_env;
   kms_kmip_request_t *req;
   kms_kmip_response_t *res;
   kms_status_t *status;
   char *data = "\xff\xa8\xcc\x79\xe8\xc3\x76\x3b\x01\x21\xfc\xd0\x6b\xb3\x48\x8c\x8b\xf4\x2c\x07\x74\x60\x46\x40\x27\x9b\x16\xb2\x64\x19\x40\x30\xee\xb0\x83\x96\x24\x1d\xef\xcc\x4d\x32\xd1\x6e\xa8\x31\xad\x77\x71\x38\xf0\x8e\x2f\x98\x56\x64\xc0\x04\xc2\x48\x5d\x6f\x49\x91\xeb\x3d\x9e\xc3\x28\x02\x53\x78\x36\xa9\x06\x6b\x4e\x10\xae\xb5\x6a\x5c\xcf\x6a\xa4\x69\x01\xe6\x25\xe3\x40\x0c\x78\x11\xd2\xec";
   uint8_t *reqbytes;
   uint32_t reqlen;
   char *uid;

   test_env_init (&test_env);
   status = kms_status_new ();
   req = kms_kmip_request_register_secretdata_new (NULL, (uint8_t*) data, 96, status);
   ASSERT_STATUS_OK (status);

   reqbytes = kms_kmip_request_to_bytes (req, &reqlen);
   res = send_kms_kmip_request (req, &test_env);
   kms_kmip_request_destroy (req);

   uid = kms_kmip_response_get_unique_identifier (res, status);
   ASSERT_STATUS_OK (status);
   kms_kmip_response_destroy (res);

   req = kms_kmip_request_activate_new (NULL, uid, status);
   ASSERT_STATUS_OK (status);
   res = send_kms_kmip_request (req, &test_env);
   kms_kmip_request_destroy (req);
   kms_kmip_response_ok (res, status);
   ASSERT_STATUS_OK (status);
   kms_kmip_response_destroy (res);
   return uid;
}

static void
kmip_discover_versions (void)
{
   test_env_t test_env;
   kms_kmip_request_t *req;
   kms_kmip_response_t *res;
   kms_status_t *status;

   test_env_init (&test_env);
   status = kms_status_new ();
   req = kms_kmip_request_discover_versions_new (NULL, status);
   TEST_ASSERT (req != NULL);

   res = send_kms_kmip_request (req, &test_env);
   kms_kmip_request_destroy (req);
   kms_kmip_response_destroy (res);
}

static uint8_t *
kmip_get (char *uid, uint32_t* secretdata_len) {
   test_env_t test_env;
   kms_kmip_request_t *req;
   kms_kmip_response_t *res;
   kms_status_t *status;
   uint8_t *secretdata;

   test_env_init (&test_env);
   status = kms_status_new ();
   req = kms_kmip_request_get_new (NULL, uid, status);
   ASSERT_STATUS_OK (status);

   res = send_kms_kmip_request (req, &test_env);
   kms_kmip_request_destroy (req);
   secretdata = kms_kmip_response_get_secretdata (res, secretdata_len, status);
   ASSERT_STATUS_OK (status);
   kms_kmip_response_destroy (res);
   return secretdata;
}

static void
test_kmip_register_and_activate_secretdata (void)
{
   char *uid;
   uid = kmip_register_and_activate_secretdata ();
   free (uid);
}

static void
test_kmip_discover_versions (void)
{
   kmip_discover_versions ();
}


static void
test_kmip_get (void) {
   char *uid;
   uint8_t *secretdata;
   uint32_t secretdata_len;
   char *secretdata_hex;

   uid = kmip_register_and_activate_secretdata ();
   secretdata = kmip_get (uid, &secretdata_len);
   
   secretdata_hex = hexlify (secretdata, secretdata_len);
   printf ("got hex: %s\n", secretdata_hex);
   
   free (secretdata_hex);
   free (uid);
   free (secretdata);
}

static void
dump_kmip_from_pykmip (void) {
   char *register_from_pykmip = "\x42\x00\x78\x01\x00\x00\x01\xa0\x42\x00\x77\x01\x00\x00\x00\x38\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6a\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6b\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x42\x00\x0d\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0f\x01\x00\x00\x01\x58\x42\x00\x5c\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00\x42\x00\x79\x01\x00\x00\x01\x40\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00\x42\x00\x91\x01\x00\x00\x00\x88\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0a\x07\x00\x00\x00\x18\x43\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73\x61\x67\x65\x20\x4d\x61\x73\x6b\x42\x00\x0b\x02\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x48\x42\x00\x0a\x07\x00\x00\x00\x04\x4e\x61\x6d\x65\x00\x00\x00\x00\x42\x00\x0b\x01\x00\x00\x00\x30\x42\x00\x55\x07\x00\x00\x00\x14\x75\x6e\x69\x71\x75\x65\x5f\x6e\x61\x6d\x65\x5f\x44\x57\x66\x35\x61\x44\x49\x3d\x00\x00\x00\x00\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x85\x01\x00\x00\x00\x98\x42\x00\x86\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x40\x01\x00\x00\x00\x80\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x45\x01\x00\x00\x00\x68\x42\x00\x43\x08\x00\x00\x00\x60\xc0\xc8\x68\x63\xca\xfe\x32\x13\x96\xd7\x90\xd0\x56\xc2\xe1\xac\xfe\x26\xb5\x37\xe0\xdc\x09\xe3\xc0\x90\x0a\x44\x77\x44\x4a\x69\xc0\x7d\xdf\xd7\xbb\x7c\x4a\xd0\xd5\xc2\xfd\x34\x35\x50\xd8\x42\x60\x23\x9b\x8d\x2b\x50\x2e\xa8\xe9\x63\x3a\x91\x4d\x4d\x72\xd4\x87\x10\x8c\x9d\x97\xc4\xd8\x9d\xa4\x70\x46\x70\x37\x06\xc9\x06\xf7\x90\x79\xbc\xeb\x73\x68\x48\x1c\xc7\xd9\xfa\x45\xa3\x75\xe1";
   char *str = kmip_dump ((uint8_t*) register_from_pykmip, 425);
   printf ("dump:\n%s", str);
/*
   From Python:

   random_name = "unique_name_" + base64.b64encode (os.urandom(5)).decode("utf8")
   secretdata = objects.SecretData(kek, enums.SecretDataType.SEED, [
                                    enums.CryptographicUsageMask.ENCRYPT, enums.CryptographicUsageMask.DECRYPT], random_name)
   uid = client.register(secretdata)

   To request:

tag=RequestMessage (420078) type=Structure (01) length=416
 tag=RequestHeader (420077) type=Structure (01) length=56
  tag=ProtocolVersion (420069) type=Structure (01) length=32
   tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
   tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=4
  tag=BatchCount (42000d) type=Integer (02) length=4 value=1
 tag=BatchItem (42000f) type=Structure (01) length=344
  tag=Operation (42005c) type=Enumeration (05) length=4 value=3
  tag=RequestPayload (420079) type=Structure (01) length=320
   tag=ObjectType (420057) type=Enumeration (05) length=4 value=7
   tag=TemplateAttribute (420091) type=Structure (01) length=136
    tag=Attribute (420008) type=Structure (01) length=48
     tag=AttributeName (42000a) type=TextString (07) length=24 value=Cryptographic Usage MaskB
     tag=AttributeValue (42000b) type=Integer (02) length=4 value=12
    tag=Attribute (420008) type=Structure (01) length=72
     tag=AttributeName (42000a) type=TextString (07) length=4 value=Name
     tag=AttributeValue (42000b) type=Structure (01) length=48
      tag=NameValue (420055) type=TextString (07) length=20 value=unique_name_DWf5aDI=
      tag=NameType (420054) type=Enumeration (05) length=4 value=1
   tag=SecretData (420085) type=Structure (01) length=152
    tag=SecretDataType (420086) type=Enumeration (05) length=4 value=2
    tag=KeyBlock (420040) type=Structure (01) length=128
     tag=KeyFormatType (420042) type=Enumeration (05) length=4 value=2
     tag=KeyValue (420045) type=Structure (01) length=104
      tag=KeyMaterial (420043) type=ByteString (08) length=96 value=(TODO)
*/
}

int
main (int argc, char **argv)
{
   char *test_selector = NULL;

   kms_message_init ();

   if (argc == 2) {
      test_selector = argv[1];
   }

   if (test_selector == NULL || 0 == strcmp (test_selector, "test_kmip_register_and_activate_secretdata")) {
      RUN_TEST (test_kmip_register_and_activate_secretdata);
   } else if (test_selector == NULL || 0 == strcmp (test_selector, "test_kmip_discover_versions")) {
      RUN_TEST (test_kmip_discover_versions);
   } else if (test_selector == NULL || 0 == strcmp (test_selector, "dump_kmip_from_pykmip")) {
      RUN_TEST (dump_kmip_from_pykmip);
   } else if (test_selector == NULL || 0 == strcmp (test_selector, "test_kmip_get")) {
      RUN_TEST (test_kmip_get);
   }
   return 0;
}