/*
 * Copyright 2020-present MongoDB, Inc.
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

#include <kms_message/kms_b64.h>
#include <kms_message/kms_request.h>
#include <kms_message/kms_response.h>
#include <kms_message/kms_response_parser.h>

#define MONGOC_LOG_DOMAIN "test_kms_azure_online"
#include <mongoc/mongoc.h>

#include "test_kms.h"

#include <stdio.h>

#define SCOPE "https%3A%2F%2Fvault.azure.net%2F.default"

/* Define TEST_TRACING_INSECURE in compiler flags to enable
 * log output with sensitive information (for debugging). */
#ifdef TEST_TRACING_INSECURE
#define TEST_TRACE(...) MONGOC_DEBUG (__VA_ARGS__)
#else
#define TEST_TRACE(...) (void) 0
#endif

typedef struct {
   char *tenant_id;
   char *client_id;
   char *client_secret;
   char *key_url;
   char *key_vault_url;
   char *key_path;
   char *key_host;
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
   char *azure_domain = "vault.azure.net";
   char *loc;

   test_env->tenant_id = test_getenv ("AZURE_TENANT_ID");
   test_env->client_id = test_getenv ("AZURE_CLIENT_ID");
   test_env->client_secret = test_getenv ("AZURE_CLIENT_SECRET");
   test_env->key_url = test_getenv ("AZURE_KEY_URL");

   loc = strstr (test_env->key_url, azure_domain);
   TEST_ASSERT (loc);
   test_env->key_vault_url = bson_strndup (
      test_env->key_url, strlen (azure_domain) + loc - test_env->key_url);
   test_env->key_path = bson_strdup (loc + strlen (azure_domain));
   loc = strstr (test_env->key_vault_url, "//");
   test_env->key_host = bson_strdup (loc + 2);
}

static void
test_env_cleanup (test_env_t *test_env)
{
   bson_free (test_env->key_vault_url);
   bson_free (test_env->key_path);
   bson_free (test_env->key_host);
}

/* Create a TLS stream to a host. */
static mongoc_stream_t *
connect_with_tls (const char *host)
{
   mongoc_stream_t *stream;
   mongoc_socket_t *sock = NULL;
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   int64_t expire_at;
   int s;
   const int connecttimeoutms = 5000;

   memset (&hints, 0, sizeof hints);
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0;

   s = getaddrinfo (host, "443", &hints, &result);
   TEST_ASSERT (s == 0);

   for (rp = result; rp; rp = rp->ai_next) {
      if (!(sock = mongoc_socket_new (
               rp->ai_family, rp->ai_socktype, rp->ai_protocol))) {
         continue;
      }

      expire_at = bson_get_monotonic_time () + (connecttimeoutms * 1000L);
      if (0 !=
          mongoc_socket_connect (
             sock, rp->ai_addr, (mongoc_socklen_t) rp->ai_addrlen, expire_at)) {
         mongoc_socket_destroy (sock);
         sock = NULL;
         continue;
      }

      break;
   }

   if (!sock) {
      TEST_ERROR ("Failed to connect: %s", host);
   }

   freeaddrinfo (result);

   stream = mongoc_stream_socket_new (sock);
   TEST_ASSERT (stream);
   return mongoc_stream_tls_new_with_hostname (
      stream, host, (mongoc_ssl_opt_t *) mongoc_ssl_opt_get_default (), 1);
}

/* Helper to send an HTTP request and receive a response. */
static kms_response_t *
send_kms_request (kms_request_t *req, const char *host)
{
   mongoc_stream_t *tls_stream;
   char *req_str;
   int32_t socket_timeout_ms = 5000;
   ssize_t write_ret;
   kms_response_parser_t *response_parser;
   int bytes_to_read;
   int bytes_read;
   uint8_t buf[1024];
   kms_response_t *response;

   tls_stream = connect_with_tls (host);
   req_str = kms_request_to_string (req);

   write_ret = mongoc_stream_write (
      tls_stream, req_str, strlen (req_str), socket_timeout_ms);
   TEST_ASSERT (write_ret == (ssize_t) strlen (req_str));

   response_parser = kms_response_parser_new ();
   while ((bytes_to_read =
              kms_response_parser_wants_bytes (response_parser, 1024)) > 0) {
      bytes_read =
         mongoc_stream_read (tls_stream, buf, 1024, 0, socket_timeout_ms);
      if (!kms_response_parser_feed (response_parser, buf, bytes_read)) {
         TEST_ERROR ("read failed: %s",
                     kms_response_parser_error (response_parser));
      }
   }

   response = kms_response_parser_get_response (response_parser);
   TEST_ASSERT (response);

   kms_request_free_string (req_str);
   kms_response_parser_destroy (response_parser);
   mongoc_stream_destroy (tls_stream);
   return response;
}

/*
Authenticate to Azure by sending an oauth request with client_id and
client_secret (set in environment variables).
Returns the base64url encoded bearer token that must be freed with bson_free.

Subsequent requests to Azure can use the returned token by setting the header
Authorization: Bearer <token>.

References:
[1]
https://docs.microsoft.com/en-us/azure/key-vault/general/authentication-requests-and-responses
*/
static char *
azure_authenticate (void)
{
   kms_request_t *req;
   kms_request_opt_t *opt;
   char *path;
   char *payload;
   char *req_str;
   const char *res_str;
   bson_t *res_bson;
   bson_iter_t iter;
   char *bearer_token;

   kms_response_t *res;
   test_env_t test_env;
   test_env_init (&test_env);

   opt = kms_request_opt_new ();
   kms_request_opt_set_connection_close (opt, true);
   kms_request_opt_set_provider (opt, KMS_REQUEST_PROVIDER_AZURE);

   path = bson_strdup_printf ("/%s/oauth2/v2.0/token", test_env.tenant_id);
   payload = bson_strdup_printf (
      "client_id=%s&scope=%s&client_secret=%s&grant_type=client_credentials",
      test_env.client_id,
      SCOPE,
      test_env.client_secret);

   req = kms_request_new ("POST", path, opt);
   TEST_ASSERT (kms_request_add_header_field (
      req, "Content-Type", "application/x-www-form-urlencoded"));
   TEST_ASSERT (
      kms_request_add_header_field (req, "Host", "login.microsoftonline.com"));
   TEST_ASSERT (
      kms_request_add_header_field (req, "Accept", "application/json"));
   TEST_ASSERT (kms_request_append_payload (req, payload, strlen (payload)));
   req_str = kms_request_to_string (req);
   TEST_TRACE ("--> HTTP request:\n%s\n", req_str);

   res = send_kms_request (req, "login.microsoftonline.com");
   res_str = kms_response_get_body (res, NULL);
   TEST_TRACE ("<-- HTTP response:\n%s\n", res_str);
   TEST_ASSERT (kms_response_get_status (res) == 200);

   res_bson =
      bson_new_from_json ((const uint8_t *) res_str, strlen (res_str), NULL);
   TEST_ASSERT (res_bson);
   if (!bson_iter_init_find (&iter, res_bson, "access_token")) {
      TEST_ERROR ("could not find 'access_token' in HTTP response");
   }

   bearer_token = bson_strdup (bson_iter_utf8 (&iter, NULL));

   kms_request_free_string (req_str);
   kms_response_destroy (res);
   kms_request_destroy (req);
   bson_free (path);
   bson_free (payload);
   bson_destroy (res_bson);
   test_env_cleanup (&test_env);
   kms_request_opt_destroy (opt);
   return bearer_token;
}

/* Test wrapping a 96 byte payload (the size of a data key) and unwrapping it
 * back. */
static void
test_azure_wrapkey (void)
{
   test_env_t test_env;
   kms_request_opt_t *opt;
   kms_request_t *req;
   char *req_str;
   char *bearer_token;
   kms_response_t *res;
   char *path_and_query;
   char *bearer_token_value;
   char *payload;
   const char *res_str;
   char *encrypted;
   char *decrypted;
   bson_t *res_bson;
   bson_iter_t iter;

/* value is 96 bytes, generated with openssl rand -base64 96. Then converted
 * to the base64url encoding, which Azure uses (slightly different from base64).
 */
#define KEY_DATA_BASE64URL                                      \
   "IyyjC2eyMNcYOgZaIXl1H0qTYZhdVbyyn-0kiSK0n9O-"               \
   "5OPNLi9xdDnCO3VBSsI9cUWMtVfTwvL7HY8S1VCCUQDnTyx8ZPVNTSRZk_" \
   "liS7BDsQjPEfC4LZv8Un3bSHs"

   test_env_init (&test_env);
   path_and_query =
      bson_strdup_printf ("%s/wrapkey?api-version=7.0", test_env.key_path);
   bearer_token = azure_authenticate ();
   bearer_token_value = bson_strdup_printf ("Bearer %s", bearer_token);
   payload = bson_strdup_printf (
      "{\"alg\": \"RSA-OAEP-256\", \"value\": \"%s\"}", KEY_DATA_BASE64URL);

   opt = kms_request_opt_new ();
   kms_request_opt_set_connection_close (opt, true);
   kms_request_opt_set_provider (opt, KMS_REQUEST_PROVIDER_AZURE);
   req = kms_request_new ("POST", path_and_query, opt);
   kms_request_add_header_field (req, "Authorization", bearer_token_value);
   kms_request_add_header_field (req, "Host", test_env.key_host);
   kms_request_add_header_field (req, "Content-Type", "application/json");
   kms_request_append_payload (req, payload, strlen (payload));
   req_str = kms_request_to_string (req);
   TEST_TRACE ("--> HTTP request:\n%s\n", req_str);
   res = send_kms_request (req, test_env.key_host);

   res_str = kms_response_get_body (res, NULL);
   TEST_TRACE ("<-- HTTP response:\n%s", res_str);
   res_bson =
      bson_new_from_json ((const uint8_t *) res_str, strlen (res_str), NULL);
   TEST_ASSERT (res_bson);
   TEST_ASSERT (bson_iter_init_find (&iter, res_bson, "value"));
   encrypted = bson_strdup (bson_iter_utf8 (&iter, NULL));

   bson_destroy (res_bson);
   bson_free (payload);
   bson_free (req_str);
   kms_request_destroy (req);
   kms_response_destroy (res);
   bson_free (path_and_query);

   /* Send a request to unwrap the encrypted key. */
   path_and_query =
      bson_strdup_printf ("%s/unwrapkey?api-version=7.0", test_env.key_path);
   payload = bson_strdup_printf (
      "{\"alg\": \"RSA-OAEP-256\", \"value\": \"%s\"}", encrypted);
   req = kms_request_new ("POST", path_and_query, opt);
   kms_request_add_header_field (req, "Authorization", bearer_token_value);
   kms_request_add_header_field (req, "Host", test_env.key_host);
   kms_request_add_header_field (req, "Content-Type", "application/json");
   kms_request_append_payload (req, payload, strlen (payload));
   req_str = kms_request_to_string (req);
   TEST_TRACE ("--> HTTP request:\n%s\n", req_str);
   res = send_kms_request (req, test_env.key_host);
   res_str = kms_response_get_body (res, NULL);
   TEST_TRACE ("<-- HTTP response:\n%s", res_str);
   res_bson =
      bson_new_from_json ((const uint8_t *) res_str, strlen (res_str), NULL);
   TEST_ASSERT (res_bson);
   TEST_ASSERT (bson_iter_init_find (&iter, res_bson, "value"));
   decrypted = bson_strdup (bson_iter_utf8 (&iter, NULL));
   TEST_ASSERT_STREQUAL (decrypted, KEY_DATA_BASE64URL);

   bson_destroy (res_bson);
   kms_response_destroy (res);
   bson_free (req_str);
   bson_free (payload);
   bson_free (path_and_query);
   bson_free (bearer_token);
   bson_free (bearer_token_value);
   test_env_cleanup (&test_env);
   kms_request_destroy (req);
   bson_free (encrypted);
   bson_free (decrypted);
   kms_request_opt_destroy (opt);
}

int
main (int argc, char **argv)
{
   RUN_TEST (test_azure_wrapkey);
}