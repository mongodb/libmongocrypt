/*
 * Copyright 2019-present MongoDB, Inc.
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


#include "mongocrypt-private.h"
#include "mongocrypt-binary-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-kms-ctx-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-status-private.h"
#include <kms_message/kms_b64.h>
#include "mongocrypt.h"

/* Before we've read the Content-Length header in an HTTP response,
 * we don't know how many bytes we'll need. So return this value
 * in kms_ctx_bytes_needed until we are fed the Content-Length.
 */
#define DEFAULT_MAX_KMS_BYTE_REQUEST 1024
#define SHA256_LEN 32

static bool
_sha256 (void *ctx, const char *input, size_t len, unsigned char *hash_out)
{
   bool ret;
   mongocrypt_status_t *status;
   _mongocrypt_crypto_t *crypto = (_mongocrypt_crypto_t *) ctx;
   mongocrypt_binary_t *plaintext, *out;

   status = mongocrypt_status_new ();
   plaintext =
      mongocrypt_binary_new_from_data ((uint8_t *) input, (uint32_t) len);
   out = mongocrypt_binary_new ();

   out->data = hash_out;
   out->len = SHA256_LEN;

   ret = crypto->sha_256 (crypto->ctx, plaintext, out, status);

   mongocrypt_status_destroy (status);
   mongocrypt_binary_destroy (plaintext);
   mongocrypt_binary_destroy (out);
   return ret;
}

static bool
_sha256_hmac (void *ctx,
              const char *key_input,
              size_t key_len,
              const char *input,
              size_t len,
              unsigned char *hash_out)
{
   mongocrypt_status_t *status;
   _mongocrypt_crypto_t *crypto = (_mongocrypt_crypto_t *) ctx;
   mongocrypt_binary_t *key, *plaintext, *out;
   bool ret;

   (void) crypto;

   status = mongocrypt_status_new ();
   key = mongocrypt_binary_new_from_data ((uint8_t *) key_input,
                                          (uint32_t) key_len);
   plaintext =
      mongocrypt_binary_new_from_data ((uint8_t *) input, (uint32_t) len);
   out = mongocrypt_binary_new ();

   out->data = hash_out;
   out->len = SHA256_LEN;

   ret = crypto->hmac_sha_256 (crypto->ctx, key, plaintext, out, status);

   mongocrypt_status_destroy (status);
   mongocrypt_binary_destroy (key);
   mongocrypt_binary_destroy (plaintext);
   mongocrypt_binary_destroy (out);
   return ret;
}

static void
_set_kms_crypto_hooks (_mongocrypt_crypto_t *crypto, kms_request_opt_t *opts)
{
   if (crypto->hooks_enabled) {
      kms_request_opt_set_crypto_hooks (opts, _sha256, _sha256_hmac, crypto);
   }
}


bool
_mongocrypt_kms_ctx_init_aws_decrypt (mongocrypt_kms_ctx_t *kms,
                                      _mongocrypt_opts_t *crypt_opts,
                                      _mongocrypt_key_doc_t *key,
                                      _mongocrypt_log_t *log,
                                      _mongocrypt_crypto_t *crypto)
{
   kms_request_opt_t *opt;
   mongocrypt_status_t *status;

   kms->parser = kms_response_parser_new ();
   kms->log = log;
   kms->status = mongocrypt_status_new ();
   status = kms->status;
   kms->req_type = MONGOCRYPT_KMS_DECRYPT;
   _mongocrypt_buffer_init (&kms->result);

   if (!key->masterkey_provider) {
      CLIENT_ERR ("no kms provider specified on key");
      return false;
   }

   if (MONGOCRYPT_KMS_PROVIDER_AWS != key->masterkey_provider) {
      CLIENT_ERR ("expected aws kms provider");
      return false;
   }

   if (!key->masterkey_region) {
      CLIENT_ERR ("no key region provided");
      return false;
   }

   if (0 == (crypt_opts->kms_providers & MONGOCRYPT_KMS_PROVIDER_AWS)) {
      CLIENT_ERR ("aws kms not configured");
      return false;
   }

   if (!crypt_opts->kms_aws_access_key_id) {
      CLIENT_ERR ("aws access key id not provided");
      return false;
   }

   if (!crypt_opts->kms_aws_secret_access_key) {
      CLIENT_ERR ("aws secret access key not provided");
      return false;
   }

   /* create the KMS request. */
   opt = kms_request_opt_new ();
   BSON_ASSERT (opt);

   _set_kms_crypto_hooks (crypto, opt);
   /* TODO: we might want to let drivers control whether or not we send
    * Connection: close header. Unsure right now. */
   kms_request_opt_set_connection_close (opt, true);

   kms->req = kms_decrypt_request_new (
      key->key_material.data, key->key_material.len, opt);

   kms_request_opt_destroy (opt);
   kms_request_set_service (kms->req, "kms");

   if (kms_request_get_error (kms->req)) {
      CLIENT_ERR ("error constructing KMS message: %s",
                  kms_request_get_error (kms->req));
      return false;
   }

   /* If an endpoint was set, override the default Host header. */
   if (key->endpoint) {
      if (!kms_request_add_header_field (kms->req, "Host", key->endpoint)) {
         CLIENT_ERR ("error constructing KMS message: %s",
                     kms_request_get_error (kms->req));
         return false;
      }
   }

   if (!kms_request_set_region (kms->req, key->masterkey_region)) {
      CLIENT_ERR ("failed to set region");
      return false;
   }

   if (!kms_request_set_access_key_id (kms->req,
                                       crypt_opts->kms_aws_access_key_id)) {
      CLIENT_ERR ("failed to set aws access key id");
      return false;
   }
   if (!kms_request_set_secret_key (kms->req,
                                    crypt_opts->kms_aws_secret_access_key)) {
      CLIENT_ERR ("failed to set aws secret access key");
   }

   _mongocrypt_buffer_init (&kms->msg);
   kms->msg.data = (uint8_t *) kms_request_get_signed (kms->req);
   if (!kms->msg.data) {
      CLIENT_ERR ("failed to create KMS message");
      return false;
   }
   kms->msg.len = (uint32_t) strlen ((char *) kms->msg.data);
   kms->msg.owned = true;

   if (key->endpoint) {
      kms->endpoint = bson_strdup (key->endpoint);
   } else {
      /* construct the endpoint from AWS region. */
      kms->endpoint =
         bson_strdup_printf ("kms.%s.amazonaws.com", key->masterkey_region);
   }
   return true;
}


bool
_mongocrypt_kms_ctx_init_aws_encrypt (
   mongocrypt_kms_ctx_t *kms,
   _mongocrypt_opts_t *crypt_opts,
   _mongocrypt_ctx_opts_t *ctx_opts,
   _mongocrypt_buffer_t *plaintext_key_material,
   _mongocrypt_log_t *log,
   _mongocrypt_crypto_t *crypto)
{
   kms_request_opt_t *opt;
   mongocrypt_status_t *status;

   kms->parser = kms_response_parser_new ();
   kms->status = mongocrypt_status_new ();
   status = kms->status;
   kms->req_type = MONGOCRYPT_KMS_ENCRYPT;
   _mongocrypt_buffer_init (&kms->result);
   kms->log = log;

   if (MONGOCRYPT_KMS_PROVIDER_AWS != ctx_opts->masterkey_kms_provider) {
      CLIENT_ERR ("expected aws kms provider");
      return false;
   }

   if (!ctx_opts->masterkey_aws_region) {
      CLIENT_ERR ("no key region provided");
      return false;
   }

   if (!ctx_opts->masterkey_aws_cmk) {
      CLIENT_ERR ("no aws cmk provided");
      return false;
   }

   if (0 == (crypt_opts->kms_providers & MONGOCRYPT_KMS_PROVIDER_AWS)) {
      CLIENT_ERR ("aws kms not configured");
      return false;
   }

   if (!crypt_opts->kms_aws_access_key_id) {
      CLIENT_ERR ("aws access key id not provided");
      return false;
   }

   if (!crypt_opts->kms_aws_secret_access_key) {
      CLIENT_ERR ("aws secret access key not provided");
      return false;
   }

   /* create the KMS request. */
   opt = kms_request_opt_new ();
   BSON_ASSERT (opt);

   _set_kms_crypto_hooks (crypto, opt);
   /* TODO: we might want to let drivers control whether or not we send
    * Connection: close header. Unsure right now. */
   kms_request_opt_set_connection_close (opt, true);

   kms->req = kms_encrypt_request_new (plaintext_key_material->data,
                                       plaintext_key_material->len,
                                       ctx_opts->masterkey_aws_cmk,
                                       opt);

   kms_request_opt_destroy (opt);
   kms_request_set_service (kms->req, "kms");

   if (kms_request_get_error (kms->req)) {
      CLIENT_ERR ("error constructing KMS message: %s",
                  kms_request_get_error (kms->req));
      return false;
   }

   /* If an endpoint was set, override the default Host header. */
   if (ctx_opts->masterkey_aws_endpoint) {
      if (!kms_request_add_header_field (
             kms->req, "Host", ctx_opts->masterkey_aws_endpoint)) {
         CLIENT_ERR ("error constructing KMS message: %s",
                     kms_request_get_error (kms->req));
      }
   }

   if (!kms_request_set_region (kms->req, ctx_opts->masterkey_aws_region)) {
      CLIENT_ERR ("failed to set region");
      return false;
   }

   if (!kms_request_set_access_key_id (kms->req,
                                       crypt_opts->kms_aws_access_key_id)) {
      CLIENT_ERR ("failed to set aws access key id");
      return false;
   }
   if (!kms_request_set_secret_key (kms->req,
                                    crypt_opts->kms_aws_secret_access_key)) {
      CLIENT_ERR ("failed to set aws secret access key");
   }

   _mongocrypt_buffer_init (&kms->msg);
   kms->msg.data = (uint8_t *) kms_request_get_signed (kms->req);
   if (!kms->msg.data) {
      CLIENT_ERR ("failed to create KMS message");
      return false;
   }
   kms->msg.len = (uint32_t) strlen ((char *) kms->msg.data);
   kms->msg.owned = true;

   /* construct the endpoint */
   if (ctx_opts->masterkey_aws_endpoint) {
      kms->endpoint = bson_strdup (ctx_opts->masterkey_aws_endpoint);
   } else {
      kms->endpoint = bson_strdup_printf ("kms.%s.amazonaws.com",
                                          ctx_opts->masterkey_aws_region);
   }
   return true;
}


uint32_t
mongocrypt_kms_ctx_bytes_needed (mongocrypt_kms_ctx_t *kms)
{
   if (!kms) {
      return 0;
   }
   /* TODO: an oddity of kms-message. After retrieving the JSON result, it
    * resets the parser. */
   if (!mongocrypt_status_ok (kms->status) ||
       !_mongocrypt_buffer_empty (&kms->result)) {
      return 0;
   }
   return kms_response_parser_wants_bytes (kms->parser,
                                           DEFAULT_MAX_KMS_BYTE_REQUEST);
}


bool
mongocrypt_kms_ctx_feed (mongocrypt_kms_ctx_t *kms, mongocrypt_binary_t *bytes)
{
   mongocrypt_status_t *status;

   if (!kms) {
      return false;
   }

   status = kms->status;
   if (!mongocrypt_status_ok (status)) {
      return false;
   }

   if (!bytes) {
      CLIENT_ERR ("argument 'bytes' is required");
      return false;
   }

   if (bytes->len > mongocrypt_kms_ctx_bytes_needed (kms)) {
      CLIENT_ERR ("KMS response fed too much data");
      return false;
   }

   if (kms->log->trace_enabled) {
      _mongocrypt_log (kms->log,
                       MONGOCRYPT_LOG_LEVEL_TRACE,
                       "%s (%s=\"%.*s\")",
                       BSON_FUNC,
                       "bytes",
                       mongocrypt_binary_len (bytes),
                       mongocrypt_binary_data (bytes));
   }

   if (!kms_response_parser_feed (kms->parser, bytes->data, bytes->len)) {
      CLIENT_ERR ("KMS response parser error with status %d, error: '%s'",
                  kms_response_parser_status (kms->parser),
                  kms_response_parser_error (kms->parser));
      return false;
   }

   if (0 == mongocrypt_kms_ctx_bytes_needed (kms)) {
      kms_response_t *response = NULL;
      const char *body;
      bson_t body_bson = BSON_INITIALIZER;
      bool ret;
      const char *key;
      bson_error_t bson_error;
      bson_iter_t iter;
      uint32_t b64_strlen;
      char *b64_str;
      int http_status;
      size_t body_len;

      ret = false;
      /* Parse out the {en|de}crypted result. */
      http_status = kms_response_parser_status (kms->parser);
      response = kms_response_parser_get_response (kms->parser);
      body = kms_response_get_body (response, &body_len);

      if (http_status != 200) {
         /* 1xx, 2xx, and 3xx HTTP status codes are not errors, but we only
          * support handling 200 response. */
         if (http_status < 400) {
            CLIENT_ERR ("Unsupported HTTP code in KMS response. HTTP status=%d",
                        http_status);
            goto fail;
         }

         /* Either empty body or body containing JSON with error message. */
         if (body_len == 0) {
            CLIENT_ERR ("Error in KMS response. HTTP status=%d", http_status);
            goto fail;
         }
         /* AWS error responses include a JSON message, like { "message":
          * "error" } */
         bson_destroy (&body_bson);
         if (!bson_init_from_json (&body_bson, body, body_len, &bson_error)) {
            bson_init (&body_bson);
         } else if (bson_iter_init_find (&iter, &body_bson, "message") &&
                    BSON_ITER_HOLDS_UTF8 (&iter)) {
            CLIENT_ERR ("Error in KMS response '%s'. "
                        "HTTP status=%d",
                        bson_iter_utf8 (&iter, NULL),
                        http_status);
            goto fail;
         }

         /* If we couldn't parse JSON, return the body unchanged as an error. */
         CLIENT_ERR ("Error parsing JSON in KMS response '%s'. HTTP status=%d",
                     body,
                     http_status);
         goto fail;
      }

      /* If HTTP response succeeded (status 200) then body should contain JSON.
       */
      bson_destroy (&body_bson);
      if (!bson_init_from_json (&body_bson, body, body_len, &bson_error)) {
         CLIENT_ERR ("Error parsing JSON in KMS response '%s'. "
                     "HTTP status=%d",
                     bson_error.message,
                     http_status);
         bson_init (&body_bson);
         goto fail;
      }

      key = (kms->req_type == MONGOCRYPT_KMS_DECRYPT) ? "Plaintext"
                                                      : "CiphertextBlob";

      if (!bson_iter_init_find (&iter, &body_bson, key) ||
          !BSON_ITER_HOLDS_UTF8 (&iter)) {
         CLIENT_ERR (
            "KMS JSON response does not include string '%s'. HTTP status=%d",
            key,
            http_status);
         goto fail;
      }

      b64_str = (char *) bson_iter_utf8 (&iter, &b64_strlen);
      BSON_ASSERT (b64_str);
      kms->result.data = bson_malloc (b64_strlen + 1);
      BSON_ASSERT (kms->result.data);

      kms->result.len =
         kms_message_b64_pton (b64_str, kms->result.data, b64_strlen);
      kms->result.owned = true;
      ret = true;
   fail:
      bson_destroy (&body_bson);
      kms_response_destroy (response);
      return ret;
   }
   return true;
}


bool
_mongocrypt_kms_ctx_result (mongocrypt_kms_ctx_t *kms,
                            _mongocrypt_buffer_t *out)
{
   mongocrypt_status_t *status;

   status = kms->status;

   /* If we have no status, we were never initialized */
   if (!status) {
      return false;
   }

   if (!mongocrypt_status_ok (status)) {
      return false;
   }

   if (mongocrypt_kms_ctx_bytes_needed (kms) > 0) {
      CLIENT_ERR ("KMS response unfinished");
      return false;
   }

   _mongocrypt_buffer_init (out);
   out->data = kms->result.data;
   out->len = kms->result.len;
   return true;
}


bool
mongocrypt_kms_ctx_status (mongocrypt_kms_ctx_t *kms,
                           mongocrypt_status_t *status_out)
{
   if (!kms) {
      return false;
   }

   if (!status_out) {
      mongocrypt_status_t *status = kms->status;
      CLIENT_ERR ("argument 'status' is required");
      return false;
   }
   _mongocrypt_status_copy_to (kms->status, status_out);
   return mongocrypt_status_ok (status_out);
}


void
_mongocrypt_kms_ctx_cleanup (mongocrypt_kms_ctx_t *kms)
{
   if (!kms) {
      return;
   }
   if (kms->req) {
      kms_request_destroy (kms->req);
   }
   if (kms->parser) {
      kms_response_parser_destroy (kms->parser);
   }
   mongocrypt_status_destroy (kms->status);
   _mongocrypt_buffer_cleanup (&kms->msg);
   _mongocrypt_buffer_cleanup (&kms->result);
   bson_free (kms->endpoint);
}


bool
mongocrypt_kms_ctx_message (mongocrypt_kms_ctx_t *kms, mongocrypt_binary_t *msg)
{
   if (!kms) {
      return false;
   }

   if (!msg) {
      mongocrypt_status_t *status = kms->status;
      CLIENT_ERR ("argument 'msg' is required");
      return false;
   }
   msg->data = kms->msg.data;
   msg->len = kms->msg.len;
   return true;
}


bool
mongocrypt_kms_ctx_endpoint (mongocrypt_kms_ctx_t *kms, const char **endpoint)
{
   if (!kms) {
      return false;
   }
   if (!endpoint) {
      mongocrypt_status_t *status = kms->status;
      CLIENT_ERR ("argument 'endpoint' is required");
      return false;
   }
   *endpoint = kms->endpoint;
   return true;
}
