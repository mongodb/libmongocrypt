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

#include <mongocrypt-endpoint-private.h>

#include "test-mongocrypt.h"

void
_test_mongocrypt_endpoint (_mongocrypt_tester_t *tester)
{
   _mongocrypt_endpoint_t *endpoint;
   mongocrypt_status_t *status;
   _mongocrypt_endpoint_parse_opts_t opts;

   status = mongocrypt_status_new ();

   endpoint = _mongocrypt_endpoint_new (
      "https://kevin.keyvault.azure.net:443/some/path/?query=value",
      -1,
      NULL /* opts */,
      status);
   ASSERT_STREQUAL (endpoint->host, "kevin.keyvault.azure.net");
   ASSERT_STREQUAL (endpoint->domain, "keyvault.azure.net");
   ASSERT_STREQUAL (endpoint->subdomain, "kevin");
   ASSERT_STREQUAL (endpoint->protocol, "https");
   ASSERT_STREQUAL (endpoint->port, "443");
   ASSERT_STREQUAL (endpoint->path, "some/path");
   ASSERT_STREQUAL (endpoint->query, "query=value");
   BSON_ASSERT (mongocrypt_status_ok (status));
   _mongocrypt_endpoint_destroy (endpoint);

   endpoint =
      _mongocrypt_endpoint_new ("kevin.keyvault.azure.net:443", -1, NULL /* opts */, status);
   ASSERT_STREQUAL (endpoint->host, "kevin.keyvault.azure.net");
   ASSERT_STREQUAL (endpoint->domain, "keyvault.azure.net");
   ASSERT_STREQUAL (endpoint->subdomain, "kevin");
   BSON_ASSERT (!endpoint->protocol);
   ASSERT_STREQUAL (endpoint->port, "443");
   BSON_ASSERT (!endpoint->path);
   BSON_ASSERT (!endpoint->query);
   BSON_ASSERT (mongocrypt_status_ok (status));
   _mongocrypt_endpoint_destroy (endpoint);

   endpoint = _mongocrypt_endpoint_new ("kevin.keyvault.azure.net", -1, NULL /* opts */, status);
   ASSERT_STREQUAL (endpoint->host, "kevin.keyvault.azure.net");
   ASSERT_STREQUAL (endpoint->domain, "keyvault.azure.net");
   ASSERT_STREQUAL (endpoint->subdomain, "kevin");
   BSON_ASSERT (!endpoint->protocol);
   BSON_ASSERT (!endpoint->port);
   BSON_ASSERT (!endpoint->path);
   BSON_ASSERT (!endpoint->query);
   BSON_ASSERT (mongocrypt_status_ok (status));
   _mongocrypt_endpoint_destroy (endpoint);

   endpoint = _mongocrypt_endpoint_new ("malformed", -1, NULL /* opts */, status);
   BSON_ASSERT (!endpoint);
   ASSERT_STATUS_CONTAINS (
      status,
      "Invalid endpoint, expected dot separator in host, but got: malformed");
   _mongocrypt_endpoint_destroy (endpoint);

   /* A host without a dot separator is valid if the "allow_empty_subdomain" option is true. */
   memset (&opts, 0, sizeof (opts));
   opts.allow_empty_subdomain = true;
   endpoint = _mongocrypt_endpoint_new ("localhost", -1, &opts, status);
   ASSERT_STREQUAL (endpoint->host, "localhost");
   ASSERT_STREQUAL (endpoint->domain, "localhost");
   BSON_ASSERT (!endpoint->subdomain);
   BSON_ASSERT (!endpoint->protocol);
   BSON_ASSERT (!endpoint->port);
   BSON_ASSERT (!endpoint->path);
   BSON_ASSERT (!endpoint->query);
   BSON_ASSERT (mongocrypt_status_ok (status));
   _mongocrypt_endpoint_destroy (endpoint);

   memset (&opts, 0, sizeof (opts));
   opts.allow_empty_subdomain = true;
   endpoint = _mongocrypt_endpoint_new ("localhost:1234", -1, &opts, status);
   ASSERT_STREQUAL (endpoint->host, "localhost");
   ASSERT_STREQUAL (endpoint->domain, "localhost");
   BSON_ASSERT (!endpoint->subdomain);
   BSON_ASSERT (!endpoint->protocol);
   ASSERT_STREQUAL (endpoint->port, "1234");
   BSON_ASSERT (!endpoint->path);
   BSON_ASSERT (!endpoint->query);
   BSON_ASSERT (mongocrypt_status_ok (status));
   _mongocrypt_endpoint_destroy (endpoint);

   /* A host without a dot separator is invalid if the "allow_empty_subdomain" option is false. */
   memset (&opts, 0, sizeof (opts));
   opts.allow_empty_subdomain = false;
   endpoint = _mongocrypt_endpoint_new ("localhost", -1, &opts, status);
   ASSERT_STATUS_CONTAINS (
      status,
      "Invalid endpoint, expected dot separator in host, but got: localhost");
   BSON_ASSERT (!endpoint);

   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_endpoint (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_mongocrypt_endpoint);
}
