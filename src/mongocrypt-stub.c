/*
 * Copyright 2018-present MongoDB, Inc.
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

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "mongocrypt.h"
#include "mongocrypt-binary.h"
#include "mongocrypt-key-query.h"

#if defined(_WIN32)
#define BSON_FUNC __FUNCTION__
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ < 199901L
#define BSON_FUNC __FUNCTION__
#else
#define BSON_FUNC __func__
#endif

#define CRYPT_ENTRY                                             \
   do {                                                         \
      if (getenv ("MONGOCRYPT_TRACE")) {                        \
         printf ("[CRYPT entry] %s:%d\n", BSON_FUNC, __LINE__); \
      }                                                         \
   } while (0)

static void
_simulate_latency (void)
{
   int ms = 1000;
   struct timespec to_sleep = {0};

   if (getenv ("MONGOCRYPT_LATENCY_MS")) {
      if (0 == sscanf (getenv ("MONGOCRYPT_LATENCY_MS"), "%d", &ms)) {
         printf ("Invalid MONGOCRYPT_LATENCY_MS\n");
      }
   }

   to_sleep.tv_sec = ms / 1000;
   to_sleep.tv_nsec = (ms % 1000) * 1000;
   nanosleep (&to_sleep, NULL);
}

#define MONGOCRYPT_STATUS_PLACEHOLDER 1
struct _mongocrypt_status_t {
   uint32_t code;
   char *message;
   int placeholder;
};

#define MONGOCRYPT_PLACEHOLDER 2
struct _mongocrypt_t {
   int placeholder;
};

#define MONGOCRYPT_REQUEST_PLACEHOLDER 3
struct _mongocrypt_request_t {
   int placeholder;
};

#define MONGOCRYPT_OPTS_PLACEHOLDER 4
struct _mongocrypt_opts_t {
   int placeholder;
};

#define MONGOCRYPT_KEY_QUERY_PLACEHOLDER 5
struct _mongocrypt_key_query_t {
   int placeholder;
};


const char *
mongocrypt_version (void)
{
   return MONGOCRYPT_VERSION;
}


void
mongocrypt_init (void)
{
   CRYPT_ENTRY;
}


void
mongocrypt_cleanup (void)
{
   CRYPT_ENTRY;
}


mongocrypt_opts_t *
mongocrypt_opts_new (void)
{
   mongocrypt_opts_t *opts;
   CRYPT_ENTRY;
   opts = calloc (1, sizeof (mongocrypt_opts_t));
   opts->placeholder = MONGOCRYPT_OPTS_PLACEHOLDER;
   return opts;
}


void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts)
{
   CRYPT_ENTRY;
   if (!opts) {
      return;
   }
   assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
   free (opts);
}


void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value)
{
   CRYPT_ENTRY;

   assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
}


mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status)
{
   mongocrypt_t *crypt;

   CRYPT_ENTRY;
   crypt = calloc (1, sizeof (mongocrypt_t));
   crypt->placeholder = MONGOCRYPT_PLACEHOLDER;
   return crypt;
}


void
mongocrypt_destroy (mongocrypt_t *crypt)
{
   CRYPT_ENTRY;
   if (!crypt) {
      return;
   }
   assert (crypt->placeholder == MONGOCRYPT_PLACEHOLDER);
   free (crypt);
}


mongocrypt_status_t *
mongocrypt_status_new (void)
{
   mongocrypt_status_t *status;

   CRYPT_ENTRY;
   status = calloc (1, sizeof (mongocrypt_status_t));
   status->placeholder = MONGOCRYPT_STATUS_PLACEHOLDER;
   return status;
}


void
mongocrypt_status_destroy (mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   if (!status) {
      return;
   }
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   free (status);
}


mongocrypt_error_type_t
mongocrypt_status_error_type (mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   return MONGOCRYPT_ERROR_TYPE_NONE;
}


uint32_t
mongocrypt_status_code (mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   return 0;
}


const char *
mongocrypt_status_message (mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   return "everything is fine";
}


const mongocrypt_binary_t *
mongocrypt_key_query_filter (const mongocrypt_key_query_t *key_query)
{
   static mongocrypt_binary_t bin = {0};

   CRYPT_ENTRY;
   assert (key_query->placeholder == MONGOCRYPT_KEY_QUERY_PLACEHOLDER);
   return &bin;
}


const char *
mongocrypt_key_query_keyvault_name (const mongocrypt_key_query_t *key_query)
{
   static char *name = "default";

   CRYPT_ENTRY;
   assert (key_query->placeholder == MONGOCRYPT_KEY_QUERY_PLACEHOLDER);
   return name;
}


void
mongocrypt_key_query_destroy (mongocrypt_key_query_t *key_query)
{
   CRYPT_ENTRY;
   if (!key_query) {
      return;
   }
   assert (key_query->placeholder == MONGOCRYPT_KEY_QUERY_PLACEHOLDER);
   free (key_query);
}


bool
mongocrypt_request_needs_keys (mongocrypt_request_t *request)
{
   CRYPT_ENTRY;
   assert (request->placeholder == MONGOCRYPT_REQUEST_PLACEHOLDER);
   return false;
}


const mongocrypt_key_query_t *
mongocrypt_request_next_key_query (mongocrypt_request_t *request,
                                   const mongocrypt_opts_t *opts)
{
   static mongocrypt_key_query_t key_query = {0};

   CRYPT_ENTRY;
   key_query.placeholder = MONGOCRYPT_REQUEST_PLACEHOLDER;
   return &key_query;
}


bool
mongocrypt_request_add_keys (mongocrypt_request_t *request,
                             const mongocrypt_opts_t *opts,
                             const mongocrypt_binary_t *responses,
                             uint32_t num_responses,
                             mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   assert (request->placeholder == MONGOCRYPT_REQUEST_PLACEHOLDER);
   if (opts) {
      assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
   }
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);

   _simulate_latency ();
   return false;
}


void
mongocrypt_request_destroy (mongocrypt_request_t *request)
{
   CRYPT_ENTRY;
   if (!request) {
      return;
   }
   assert (request->placeholder == MONGOCRYPT_REQUEST_PLACEHOLDER);
   free (request);
}


mongocrypt_request_t *
mongocrypt_encrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *schema,
                          const mongocrypt_binary_t *cmd,
                          mongocrypt_status_t *status)
{
   mongocrypt_request_t *request;

   CRYPT_ENTRY;
   assert (crypt->placeholder == MONGOCRYPT_PLACEHOLDER);
   if (opts) {
      assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
   }
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   _simulate_latency ();
   request = calloc (1, sizeof (mongocrypt_request_t));
   request->placeholder = MONGOCRYPT_REQUEST_PLACEHOLDER;
   return request;
}


bool
mongocrypt_encrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t *encrypted_cmd,
                           mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   assert (request->placeholder == MONGOCRYPT_REQUEST_PLACEHOLDER);
   if (opts) {
      assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
   }
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   return false;
}


mongocrypt_request_t *
mongocrypt_decrypt_start (mongocrypt_t *crypt,
                          const mongocrypt_opts_t *opts,
                          const mongocrypt_binary_t *encrypted_docs,
                          uint32_t num_docs,
                          mongocrypt_status_t *status)
{
   mongocrypt_request_t *request;

   CRYPT_ENTRY;
   assert (crypt->placeholder == MONGOCRYPT_PLACEHOLDER);
   if (opts) {
      assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
   }
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   request = calloc (1, sizeof (mongocrypt_request_t));
   request->placeholder = MONGOCRYPT_REQUEST_PLACEHOLDER;
   return request;
}


bool
mongocrypt_decrypt_finish (mongocrypt_request_t *request,
                           const mongocrypt_opts_t *opts,
                           mongocrypt_binary_t **docs,
                           mongocrypt_status_t *status)
{
   CRYPT_ENTRY;
   assert (request->placeholder == MONGOCRYPT_REQUEST_PLACEHOLDER);
   if (opts) {
      assert (opts->placeholder == MONGOCRYPT_OPTS_PLACEHOLDER);
   }
   assert (status->placeholder == MONGOCRYPT_STATUS_PLACEHOLDER);
   return false;
}
