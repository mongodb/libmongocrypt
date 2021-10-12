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
   mongoc_ssl_opt_t ssl_opt = {0};
   kms_response_parser_t *parser;
   kms_response_t *res;

   ssl_opt.ca_file = test_env->kmip_ca_certificate;
   ssl_opt.pem_file = test_env->kmip_client_certificate;
   ssl_opt.weak_cert_validation = true;
  
   parser = kms_kmip_response_parser_new (NULL);
   res = send_kms_request (req, test_env->kmip_host, test_env->kmip_port, &ssl_opt, parser);
   kms_response_parser_destroy (parser);
   return res;
}

static char *
kmip_register_and_activate_secretdata (void)
{
   test_env_t test_env;
   kms_request_t *req;
   kms_response_t *res;
#define SECRETDATA_LEN 96
   uint8_t secretdata[SECRETDATA_LEN] = {0};
   char* uid;

   test_env_init (&test_env);
   req = kms_kmip_request_register_secretdata_new (NULL, secretdata, SECRETDATA_LEN);
   ASSERT_REQUEST_OK (req);

   res = send_kms_kmip_request (req, &test_env);
   ASSERT_RESPONSE_OK (res);
   kms_request_destroy (req);

   uid = kms_kmip_response_get_unique_identifier (res);
   ASSERT (uid);
   kms_response_destroy (res);

   req = kms_kmip_request_activate_new (NULL, uid);
   ASSERT_REQUEST_OK (req);

   res = send_kms_kmip_request (req, &test_env);
   ASSERT_RESPONSE_OK (res);
   kms_request_destroy (req);
   kms_response_destroy (res);

   return uid;
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