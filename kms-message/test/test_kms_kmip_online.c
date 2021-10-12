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

#include "kms_message/kms_request.h"
#include "kms_message/kms_kmip_response.h"
#include "kms_message/kms_kmip_response_parser.h"

#define MONGOC_LOG_DOMAIN "test_kms_kmip_online"
#include <mongoc/mongoc.h>

#include "test_kms_assert.h"
#include "test_kms_util.h"

#include <stdio.h>

#include "kms_kmip_response_private.h"
#include "kms_kmip_reader_writer_private.h"
#include "test_kms_online_util.h"
#include "kms_kmip_response_parser_private.h"

#include "test_kms_util.h"

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

/* TODO: use common send_kms_request? */
static kms_response_t *
send_kms_kmip_request (kms_request_t *req, test_env_t *test_env)
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
   kms_response_t *res;
   const uint8_t *resbytes;
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
   message_bytes = kms_request_to_bytes (req, &message_len);
   debugstr = data_to_hex (message_bytes, message_len);
   printf ("%s\n", debugstr);
   free (debugstr);
   write_ret = mongoc_stream_write (
      stream, (void *) message_bytes, message_len, NETWORK_TIMEOUT_MS);
   ASSERT (write_ret == message_len);

   MONGOC_DEBUG ("reading response from KMIP server");

   parser = kms_kmip_response_parser_new (NULL)->kmip;
   wants_bytes = kms_kmip_response_parser_wants_bytes (parser, BUF_SIZE);
   while (wants_bytes > 0) {
      bytes_read = (int32_t) mongoc_stream_read (
         stream, buf, wants_bytes, 0, NETWORK_TIMEOUT_MS);
      ASSERT_CMPINT (bytes_read, >=, 0);
      if (!kms_kmip_response_parser_feed (parser, buf, (uint32_t) bytes_read)) {
         TEST_ERROR ("error parsing response: %s", kms_kmip_response_parser_error (parser));
      }
      wants_bytes = kms_kmip_response_parser_wants_bytes (parser, BUF_SIZE);
   }
   ASSERT_CMPINT (wants_bytes, ==, 0);

   res = kms_kmip_response_parser_get_response (parser);
   if (!res) {
      TEST_ERROR ("error in kms_response_parser_get_response: %s",
                  kms_kmip_response_parser_error (parser));
   }

   kms_kmip_response_parser_destroy (parser);
   mongoc_stream_close (stream);
   mongoc_stream_destroy (stream);

   resbytes = kms_response_to_bytes (res, &reslen);
   debugstr = data_to_hex (resbytes, reslen);
   printf ("%s\n", debugstr);
   free (debugstr);
   return res;
}

static char *
kmip_register_and_activate_secretdata (void)
{
   /* TODO */
   return NULL;
}

static uint8_t *
kmip_get (char *uid, uint32_t* secretdata_len) {
   test_env_t test_env;
   kms_request_t *req;
   kms_response_t *res;
   uint8_t *secretdata;

   test_env_init (&test_env);
   req = kms_kmip_request_get_new (NULL, uid);
   ASSERT_REQUEST_OK (req);

   res = send_kms_kmip_request (req, &test_env);
   kms_request_destroy (req);
   secretdata = kms_kmip_response_get_secretdata (res, secretdata_len);
   ASSERT_RESPONSE_OK (res);
   kms_response_destroy (res);
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
test_kmip_get (void) {
   char *uid;
   uint8_t *secretdata;
   uint32_t secretdata_len;
   char *secretdata_hex;

   uid = kmip_register_and_activate_secretdata ();
   secretdata = kmip_get (uid, &secretdata_len);
   
   secretdata_hex = data_to_hex (secretdata, secretdata_len);
   printf ("got hex: %s\n", secretdata_hex);
   
   free (secretdata_hex);
   free (uid);
   free (secretdata);
}

int
main (int argc, char **argv)
{
   char *test_selector = NULL;

   kms_message_init ();

   if (argc == 2) {
      test_selector = argv[1];
   }

   if (test_selector == NULL ||
       0 == strcmp (test_selector,
                    "test_kmip_register_and_activate_secretdata")) {
      test_kmip_register_and_activate_secretdata ();
   } else if (test_selector == NULL || 0 == strcmp (test_selector, "test_kmip_get")) {
      test_kmip_get ();
   }
   return 0;
}