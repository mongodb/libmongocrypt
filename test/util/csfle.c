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

#define MONGOC_LOG_DOMAIN "csfle"

#include <mongocrypt.h>
#include <mongoc/mongoc.h>
#include <kms_message/kms_b64.h>
#include <fcntl.h>

#include "util.h"

const char *help_text = ""
#include "HELP.autogen"
   ;

static void
_exit_help (void)
{
   printf ("Usage: csfle <function> [options...]\n");
   printf ("%s", help_text);
   exit (0);
}

static void
set_kms_providers (mongocrypt_t *crypt, bson_t *args)
{
   bson_t *kms_providers;
   bson_iter_t iter;
   mongocrypt_binary_t *bin;

   kms_providers = bson_get_json (args, "kms_providers_file");
   if (!kms_providers) {
      kms_providers = util_read_json_file (".csfle/kms_providers.json");
   }

   if (bson_iter_init_find (&iter, kms_providers, "aws")) {
      const char *secret_access_key =
         bson_req_utf8 (kms_providers, "aws.secretAccessKey");
      const char *access_key_id =
         bson_req_utf8 (kms_providers, "aws.accessKeyId");

      if (!mongocrypt_setopt_kms_provider_aws (
             crypt, access_key_id, -1, secret_access_key, -1)) {
         ERREXIT_MONGOCRYPT (crypt);
      }
   }

   if (bson_iter_init_find (&iter, kms_providers, "local")) {
      const uint8_t *key;
      uint32_t key_len;

      key = bson_req_bin (kms_providers, "local.key", &key_len);
      if (key_len != 96) {
         ERREXIT ("Expected local.key to be 96 bytes, got: %d", (int) key_len);
      }
      bin = mongocrypt_binary_new_from_data ((uint8_t *) key, key_len);
      if (!mongocrypt_setopt_kms_provider_local (crypt, bin)) {
         ERREXIT_MONGOCRYPT (crypt);
      }
      mongocrypt_binary_destroy (bin);
   }

   if (bson_iter_init_find (&iter, kms_providers, "azure") ||
       bson_iter_init_find (&iter, kms_providers, "gcp")) {
      bson_t tmp;

      bson_init (&tmp);
      bson_copy_to_excluding_noinit (kms_providers, &tmp, "local", "aws", NULL);
      /* Use the cool new way to set KMS providers, by a document. */
      bin = util_bson_to_bin (&tmp);
      if (!mongocrypt_setopt_kms_providers (crypt, bin)) {
         ERREXIT_MONGOCRYPT (crypt);
      }
      mongocrypt_binary_destroy (bin);
      bson_destroy (&tmp);
   }

   bson_destroy (kms_providers);
}

static mongocrypt_t *
crypt_new (bson_t *args)
{
   mongocrypt_t *crypt;
   bson_t *schema_map;
   mongocrypt_binary_t *bin;

   crypt = mongocrypt_new ();
   if (!mongocrypt_setopt_log_handler (crypt, _log_to_stdout, NULL)) {
      ERREXIT_MONGOCRYPT (crypt);
   }

   set_kms_providers (crypt, args);

   schema_map = bson_get_json (args, "schema_map_file");
   if (schema_map) {
      bin = util_bson_to_bin (schema_map);
      if (!mongocrypt_setopt_schema_map (crypt, bin)) {
         ERREXIT_MONGOCRYPT (crypt);
      }
      mongocrypt_binary_destroy (bin);
   }
   bson_destroy (schema_map);

   if (!mongocrypt_init (crypt)) {
      ERREXIT_MONGOCRYPT (crypt);
   }

   return crypt;
}

typedef struct {
   mongoc_client_t *keyvault_client;
   mongoc_client_t *mongocryptd_client;
   mongoc_client_t *mongodb_client;

   char *keyvault_db;
   char *keyvault_coll;

   _state_machine_t machine;
} state_t;

static void
state_init (state_t *state, bson_t *args, mongocrypt_ctx_t *ctx)
{
   const char *keyvault_ns;
   char *pos;

   state->keyvault_client = mongoc_client_new (
      bson_get_utf8 (args, "mongodb_uri", "mongodb://localhost:27017"));
   state->mongocryptd_client = mongoc_client_new (
      bson_get_utf8 (args, "mongocryptd_uri", "mongodb://localhost:27020"));
   state->mongodb_client = mongoc_client_new (
      bson_get_utf8 (args, "mongodb_uri", "mongodb://localhost:27017"));

   keyvault_ns = bson_get_utf8 (args, "keyvault_ns", "keyvault.datakeys");
   pos = strstr (keyvault_ns, ".");
   if (!pos) {
      ERREXIT ("Key vault collection namespace invalid: %s", keyvault_ns);
   }
   state->keyvault_db = bson_strndup (keyvault_ns, pos - keyvault_ns);
   state->keyvault_coll = bson_strdup (pos + 1);

   state->machine.ctx = ctx;
   state->machine.keyvault_coll = mongoc_client_get_collection (
      state->keyvault_client, state->keyvault_db, state->keyvault_coll);
   state->machine.mongocryptd_client = state->mongocryptd_client;
   state->machine.collinfo_client = state->mongodb_client;
   state->machine.db_name = bson_get_utf8 (args, "db", NULL);
   state->machine.trace = bson_get_bool (args, "trace", false);
}

static void
state_cleanup (state_t *state)
{
   mongoc_collection_destroy (state->machine.keyvault_coll);
   mongoc_client_destroy (state->keyvault_client);
   mongoc_client_destroy (state->mongocryptd_client);
   mongoc_client_destroy (state->mongodb_client);
   bson_free (state->keyvault_db);
   bson_free (state->keyvault_coll);
}

static void
fn_createdatakey (bson_t *args)
{
   state_t state;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   const char *kms_provider;
   bson_t result;
   bson_error_t error;
   char *result_utf8;
   mongocrypt_binary_t *bin;

   crypt = crypt_new (args);
   ctx = mongocrypt_ctx_new (crypt);

   kms_provider = bson_req_utf8 (args, "kms_provider");

   /* Set the key encryption key (KEK). */
   if (0 == strcmp ("aws", kms_provider)) {
      const char *region;
      const char *cmk;
      const char *endpoint;

      region = bson_req_utf8 (args, "aws_kek_region");
      cmk = bson_req_utf8 (args, "aws_kek_key");
      if (!mongocrypt_ctx_setopt_masterkey_aws (ctx, region, -1, cmk, -1)) {
         ERREXIT_CTX (ctx);
      }

      endpoint = bson_get_utf8 (args, "aws_kek_endpoint", NULL);
      if (endpoint) {
         if (!mongocrypt_ctx_setopt_masterkey_aws_endpoint (
                ctx, endpoint, -1)) {
            ERREXIT_CTX (ctx);
         }
      }
   } else if (0 == strcmp ("local", kms_provider)) {
      if (!mongocrypt_ctx_setopt_masterkey_local (ctx)) {
         ERREXIT_CTX (ctx);
      }
   } else if (0 == strcmp ("azure", kms_provider)) {
      bson_t azure_kek = BSON_INITIALIZER;

      BSON_APPEND_UTF8 (&azure_kek, "provider", "azure");
      BSON_APPEND_UTF8 (&azure_kek,
                        "keyVaultEndpoint",
                        bson_req_utf8 (args, "azure_kek_keyvaultendpoint"));
      BSON_APPEND_UTF8 (
         &azure_kek, "keyName", bson_req_utf8 (args, "azure_kek_keyname"));
      if (bson_has_field (args, "azure_kek_keyversion")) {
         BSON_APPEND_UTF8 (&azure_kek,
                           "keyVersion",
                           bson_req_utf8 (args, "azure_kek_keyversion"));
      }

      bin = util_bson_to_bin (&azure_kek);
      if (!mongocrypt_ctx_setopt_key_encryption_key (ctx, bin)) {
         ERREXIT_CTX (ctx);
      }
      mongocrypt_binary_destroy (bin);
      bson_destroy (&azure_kek);
   } else if (0 == strcmp ("gcp", kms_provider)) {
      bson_t gcp_kek = BSON_INITIALIZER;

      BSON_APPEND_UTF8 (&gcp_kek, "provider", "gcp");
      if (bson_has_field (args, "gcp_kek_endpoint")) {
         BSON_APPEND_UTF8 (
            &gcp_kek, "endpoint", bson_req_utf8 (args, "gcp_kek_endpoint"));
      }

      BSON_APPEND_UTF8 (
         &gcp_kek, "projectId", bson_req_utf8 (args, "gcp_kek_projectid"));
      BSON_APPEND_UTF8 (
         &gcp_kek, "location", bson_req_utf8 (args, "gcp_kek_location"));
      BSON_APPEND_UTF8 (
         &gcp_kek, "keyRing", bson_req_utf8 (args, "gcp_kek_keyring"));
      BSON_APPEND_UTF8 (
         &gcp_kek, "keyName", bson_req_utf8 (args, "gcp_kek_keyname"));

      if (bson_has_field (args, "gcp_kek_keyversion")) {
         BSON_APPEND_UTF8 (
            &gcp_kek, "keyVersion", bson_req_utf8 (args, "gcp_kek_keyversion"));
      }

      bin = util_bson_to_bin (&gcp_kek);
      if (!mongocrypt_ctx_setopt_key_encryption_key (ctx, bin)) {
         ERREXIT_CTX (ctx);
      }
      mongocrypt_binary_destroy (bin);
      bson_destroy (&gcp_kek);
   } else {
      ERREXIT ("Unknown KMS provider: %s", kms_provider);
   }

   if (!mongocrypt_ctx_datakey_init (ctx)) {
      ERREXIT_CTX (ctx);
   }

   state_init (&state, args, ctx);

   if (state.machine.trace) {
      MONGOC_DEBUG ("Running state machine");
   }

   if (!_state_machine_run (&state.machine, &result, &error)) {
      ERREXIT_BSON (&error);
   }

   if (state.machine.trace) {
      MONGOC_DEBUG ("Finished running state machine");
   }

   if (!mongoc_collection_insert_one (
          state.machine.keyvault_coll, &result, NULL, NULL, &error)) {
      ERREXIT_BSON (&error);
   }

   result_utf8 = bson_as_canonical_extended_json (&result, NULL);
   printf ("%s\n", result_utf8);
   bson_free (result_utf8);

   bson_destroy (&result);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   state_cleanup (&state);
}

static void
fn_autoencrypt (bson_t *args)
{
   state_t state;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   const char *db;
   mongocrypt_binary_t *bin;
   bson_t *cmd;
   bson_t result;
   bson_error_t error;
   char *result_utf8;

   crypt = crypt_new (args);
   ctx = mongocrypt_ctx_new (crypt);

   cmd = bson_get_json (args, "command_file");
   if (!cmd) {
      const char *cmd_utf8 = bson_req_utf8 (args, "command");
      cmd = bson_new_from_json (
         (const uint8_t *) cmd_utf8, strlen (cmd_utf8), &error);
      if (!cmd) {
         ERREXIT_BSON (&error);
      }
   }

   db = bson_req_utf8 (args, "db");
   bin = util_bson_to_bin (cmd);
   if (!mongocrypt_ctx_encrypt_init (ctx, db, -1, bin)) {
      ERREXIT_CTX (ctx);
   }

   state_init (&state, args, ctx);

   if (state.machine.trace) {
      MONGOC_INFO ("Running state machine");
   }

   if (!_state_machine_run (&state.machine, &result, &error)) {
      ERREXIT_BSON (&error);
   }

   if (state.machine.trace) {
      MONGOC_INFO ("Finished running state machine");
   }

   result_utf8 = bson_as_canonical_extended_json (&result, NULL);
   printf ("%s\n", result_utf8);
   bson_free (result_utf8);

   bson_destroy (cmd);
   mongocrypt_binary_destroy (bin);
   bson_destroy (&result);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   state_cleanup (&state);
}

static void
fn_autodecrypt (bson_t *args)
{
   state_t state;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   bson_t *doc;
   bson_t result;
   bson_error_t error;
   char *result_utf8;

   crypt = crypt_new (args);
   ctx = mongocrypt_ctx_new (crypt);

   doc = bson_get_json (args, "document_file");
   if (!doc) {
      const char *doc_utf8 = bson_req_utf8 (args, "document");
      doc = bson_new_from_json (
         (const uint8_t *) doc_utf8, strlen (doc_utf8), &error);
      if (!doc) {
         ERREXIT_BSON (&error);
      }
   }

   bin = util_bson_to_bin (doc);
   if (!mongocrypt_ctx_decrypt_init (ctx, bin)) {
      ERREXIT_CTX (ctx);
   }

   state_init (&state, args, ctx);

   if (state.machine.trace) {
      MONGOC_INFO ("Running state machine");
   }

   if (!_state_machine_run (&state.machine, &result, &error)) {
      ERREXIT_BSON (&error);
   }

   if (state.machine.trace) {
      MONGOC_INFO ("Finished running state machine");
   }

   result_utf8 = bson_as_canonical_extended_json (&result, NULL);
   printf ("%s\n", result_utf8);
   bson_free (result_utf8);

   bson_destroy (doc);
   mongocrypt_binary_destroy (bin);
   bson_destroy (&result);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   state_cleanup (&state);
}

static void
fn_explicitencrypt (bson_t *args)
{
   state_t state;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   const char *value;
   bson_t *value_doc;
   const char *key_id_base64;
   const char *key_alt_name;
   const char *algorithm;
   mongocrypt_binary_t *bin;
   bson_t result;
   bson_error_t error;
   char *result_utf8;
   uint8_t key_id[97];

   crypt = crypt_new (args);
   ctx = mongocrypt_ctx_new (crypt);
   value = bson_req_utf8 (args, "value");
   value_doc =
      bson_new_from_json ((const uint8_t *) value, strlen (value), &error);
   if (!value_doc) {
      ERREXIT_BSON (&error);
   }
   key_id_base64 = bson_get_utf8 (args, "key_id", NULL);
   if (key_id_base64) {
      int len = kms_message_b64_pton (key_id_base64, key_id, sizeof (key_id));
      if (len < 0) {
         ERREXIT ("Could not base64 decode: %s", key_id_base64);
      }
      bin = mongocrypt_binary_new_from_data (key_id, len);
      if (!mongocrypt_ctx_setopt_key_id (ctx, bin)) {
         ERREXIT_CTX (ctx);
      }
      mongocrypt_binary_destroy (bin);
   }

   key_alt_name = bson_get_utf8 (args, "key_alt_name", NULL);
   if (key_alt_name) {
      bson_t *wrapper;

      wrapper = BCON_NEW ("keyAltName", key_alt_name);
      bin = util_bson_to_bin (wrapper);
      if (!mongocrypt_ctx_setopt_key_alt_name (ctx, bin)) {
         ERREXIT_CTX (ctx);
      }
      mongocrypt_binary_destroy (bin);
   }


   algorithm = bson_req_utf8 (args, "algorithm");
   if (!mongocrypt_ctx_setopt_algorithm (ctx, algorithm, -1)) {
      ERREXIT_CTX (ctx);
   }

   bin = util_bson_to_bin (value_doc);
   if (!mongocrypt_ctx_explicit_encrypt_init (ctx, bin)) {
      ERREXIT_CTX (ctx);
   }

   state_init (&state, args, ctx);

   if (state.machine.trace) {
      MONGOC_INFO ("Running state machine");
   }

   if (!_state_machine_run (&state.machine, &result, &error)) {
      ERREXIT_BSON (&error);
   }

   if (state.machine.trace) {
      MONGOC_INFO ("Finished running state machine");
   }

   result_utf8 = bson_as_canonical_extended_json (&result, NULL);
   printf ("%s\n", result_utf8);
   bson_free (result_utf8);

   bson_destroy (value_doc);
   mongocrypt_binary_destroy (bin);
   bson_destroy (&result);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   state_cleanup (&state);
}

static void
fn_explicitdecrypt (bson_t *args)
{
   state_t state;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   const char *value;
   bson_t *value_doc;
   mongocrypt_binary_t *bin;
   bson_t result;
   bson_error_t error;
   char *result_utf8;

   crypt = crypt_new (args);
   ctx = mongocrypt_ctx_new (crypt);
   value = bson_req_utf8 (args, "value");
   value_doc =
      bson_new_from_json ((const uint8_t *) value, strlen (value), &error);
   if (!value_doc) {
      ERREXIT_BSON (&error);
   }

   bin = util_bson_to_bin (value_doc);
   if (!mongocrypt_ctx_explicit_decrypt_init (ctx, bin)) {
      ERREXIT_CTX (ctx);
   }

   state_init (&state, args, ctx);

   if (state.machine.trace) {
      MONGOC_INFO ("Running state machine");
   }

   if (!_state_machine_run (&state.machine, &result, &error)) {
      ERREXIT_BSON (&error);
   }

   if (state.machine.trace) {
      MONGOC_INFO ("Finished running state machine");
   }

   result_utf8 = bson_as_canonical_extended_json (&result, NULL);
   printf ("%s\n", result_utf8);
   bson_free (result_utf8);

   bson_destroy (value_doc);
   mongocrypt_binary_destroy (bin);
   bson_destroy (&result);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   state_cleanup (&state);
}

int
main (int argc, char **argv)
{
   bson_t args;
   bson_t *options_file_bson;
   char *fn;

   mongoc_init ();

   if (argc < 2) {
      _exit_help ();
   }

   fn = argv[1];
   bson_init (&args);
   args_parse (&args, argc - 2, argv + 2);
   options_file_bson = bson_get_json (&args, "options_file");
   if (options_file_bson) {
      bson_concat (&args, options_file_bson);
   }

   if (0 == strcmp (fn, "create_datakey")) {
      fn_createdatakey (&args);
   } else if (0 == strcmp (fn, "auto_encrypt")) {
      fn_autoencrypt (&args);
   } else if (0 == strcmp (fn, "auto_decrypt")) {
      fn_autodecrypt (&args);
   } else if (0 == strcmp (fn, "explicit_encrypt")) {
      fn_explicitencrypt (&args);
   } else if (0 == strcmp (fn, "explicit_decrypt")) {
      fn_explicitdecrypt (&args);
   } else {
      ERREXIT ("Unknown function: %s", fn);
   }

   bson_destroy (&args);
   bson_destroy (options_file_bson);

   mongoc_cleanup ();
}