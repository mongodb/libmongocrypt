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

#include "mongoc/mongoc.h"
#include "mongocrypt-private.h"
#include "kms_message/kms_b64.h"
#include "kms_message/kms_message.h"

#define ERRNO_IS_AGAIN(errno)                                          \
   ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK) || \
    (errno == EINPROGRESS))


static mongoc_stream_t *
_get_aws_stream (bson_error_t *error)
{
   int errcode;
   int r;
   struct sockaddr_in server_addr = {0};
   mongoc_socket_t *conn_sock = NULL;
   mongoc_stream_t *stream = NULL;
   mongoc_stream_t *tls_stream = NULL;
   mongoc_ssl_opt_t ssl_opts = {0};

   memcpy (&ssl_opts, mongoc_ssl_opt_get_default (), sizeof ssl_opts);
   conn_sock = mongoc_socket_new (AF_INET, SOCK_STREAM, 0);
   if (!conn_sock) {
      SET_CRYPT_ERR ("could not create socket to AWS");
      return NULL;
   }

   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons (443);
   /* TODO: actually do a DNS lookup. */
   /* 54.239.18.135, kms.us-east-1.amazonaws.com */
   server_addr.sin_addr.s_addr = htonl (0x36EF1287);
   r = mongoc_socket_connect (
      conn_sock, (struct sockaddr *) &server_addr, sizeof (server_addr), -1);

   errcode = mongoc_socket_errno (conn_sock);
   if (!(r == 0 || ERRNO_IS_AGAIN (errcode))) {
      mongoc_socket_destroy (conn_sock);
      SET_CRYPT_ERR (
         "mongoc_socket_connect unexpected return: %d (errno: %d)\n",
         r,
         errcode);
      return NULL;
   }

   stream = mongoc_stream_socket_new (conn_sock);
   tls_stream = mongoc_stream_tls_new_with_hostname (
      stream, "kms.us-east-1.amazonaws.com", &ssl_opts, 1 /* client */);

   if (!tls_stream) {
      SET_CRYPT_ERR ("could not create TLS stream on AWS");
      mongoc_stream_destroy (stream);
      return NULL;
   }

   if (!mongoc_stream_tls_handshake_block (
          tls_stream, "kms.us-east-1.amazonaws.com", 1000, error)) {
      mongoc_stream_destroy (tls_stream);
      return NULL;
   }

   return tls_stream;
}

static void
print_without_carriage_return (uint8_t *buf, ssize_t n)
{
   ssize_t i;

   for (i = 0; i < n; i++) {
      if (buf[i] != '\r') {
         putchar (buf[i]);
      }
   }
}

static bool
_api_call (mongoc_crypt_t *crypt,
   kms_request_t *request,
           kms_response_t **response,
           bson_error_t *error)
{
   bool ret = false;
   mongoc_stream_t *stream;
   char *sreq = NULL;
   size_t sreq_len;
   ssize_t n;
   uint8_t read_buf[64];
   kms_response_parser_t *parser = kms_response_parser_new ();
   int64_t start;
   const int32_t timeout_msec = 1000;

   stream = _get_aws_stream (error);
   if (!stream) {
      goto cleanup;
   }

   /* TODO: CRLF endings? */
   sreq = kms_request_get_signed (request);
   sreq_len = strlen (sreq);
   printf ("%s\n", sreq);

   n = mongoc_stream_write (stream, sreq, sreq_len, timeout_msec);
   /* TODO: don't error, just keep writing. */
   if (n != (ssize_t) sreq_len) {
      SET_CRYPT_ERR (
               "Only wrote %zd of %zu bytes (errno: %d)\n",
               n,
               sreq_len,
               errno);
      goto cleanup;
   }

   start = bson_get_monotonic_time ();
   while (kms_response_parser_wants_bytes (parser, sizeof (read_buf))) {
      if (bson_get_monotonic_time () - start > timeout_msec * 1000) {
         SET_CRYPT_ERR ("Timed out reading response\n");
         goto cleanup;
      }

      n = mongoc_stream_read (
         stream, read_buf, sizeof (read_buf), 1, timeout_msec);
      if (n < 0) {
         SET_CRYPT_ERR ("Read returned %zd (errno: %d)\n", n, errno);
         goto cleanup;
      }

      if (n == 0) {
         break;
      }

      print_without_carriage_return (read_buf, n);
      kms_response_parser_feed (parser, read_buf, (uint32_t) n);
   }

   *response = kms_response_parser_get_response (parser);
   if (!*response) {
      SET_CRYPT_ERR ("Could not get kms response");
      goto cleanup;
   }

   ret = true;
cleanup:
   kms_response_parser_destroy (parser);
   bson_free (sreq);
   mongoc_stream_destroy (stream);
   return ret;
}

static bool
_get_data_key_from_response (kms_response_t* response, mongoc_crypt_key_t* key, bson_error_t* error) {
   bson_json_reader_t* reader = NULL;
   const char* raw_response_body;
   bson_t response_body = BSON_INITIALIZER;
   bson_iter_t iter;
   reader = bson_json_data_reader_new (false, 1024);
   bool ret = false;
   char* b64_str;
   uint32_t b64_strlen;
   uint8_t* decoded_data;
   int decoded_len;

   raw_response_body = kms_response_get_body (response);
   bson_json_data_reader_ingest (reader, (const uint8_t*) raw_response_body, strlen(raw_response_body));
   switch (bson_json_reader_read(reader, &response_body, error)) {
   case 1:
      break;
   case -1:
      /* error already set. */
      goto cleanup;
   default:
      SET_CRYPT_ERR ("Could not read JSON document from response");
      goto cleanup;
   }

   CRYPT_TRACE ("kms response: %s", tmp_json(&response_body));

   if (!bson_iter_init_find (&iter, &response_body, "Plaintext")) {
      SET_CRYPT_ERR ("JSON response does not include Plaintext");
      goto cleanup;
   }

   b64_str = (char*)bson_iter_utf8 (&iter, &b64_strlen);
   /* We need to doubly base64 decode. */
   decoded_data = bson_malloc(b64_strlen + 1);
   decoded_len = kms_message_b64_pton (b64_str, decoded_data, b64_strlen);

   b64_str = (char*) decoded_data;
   b64_str[decoded_len + 1] = '\0';
   CRYPT_TRACE("decryption #1: %s\n", b64_str);
   decoded_data = bson_malloc((size_t)decoded_len + 1);

   decoded_len = kms_message_b64_pton(b64_str, decoded_data, (size_t)decoded_len);
   decoded_data[decoded_len] = '\0';
   CRYPT_TRACE ("decryption #2: %s\n", (char*)decoded_data);

   bson_free (b64_str);

   key->data_key.data = decoded_data;
   key->data_key.len = (uint32_t)decoded_len;
   key->data_key.owned = true;
   ret = true;
cleanup:
   bson_destroy (&response_body);
   bson_json_reader_destroy (reader);
   return ret;
}


bool
_mongoc_crypt_kms_decrypt (mongoc_crypt_t *crypt,
                           mongoc_crypt_key_t *key,
                           bson_error_t *error)
{
   kms_request_t* request = NULL;
   kms_response_t* response = NULL;
   kms_request_opt_t* request_opt = NULL;
   bool ret = false;

   request_opt = kms_request_opt_new ();
   kms_request_opt_set_connection_close (request_opt, true);

   request = kms_decrypt_request_new (
      key->key_material.data, key->key_material.len /* - 1 ? */, request_opt);
   kms_request_set_region (request, crypt->opts.aws_region);
   kms_request_set_service (request, "kms"); /* That seems odd. */
   kms_request_set_access_key_id (request, crypt->opts.aws_access_key_id);
   kms_request_set_secret_key (request, crypt->opts.aws_secret_access_key);

   if (!_api_call(crypt, request, &response, error)) {
      goto cleanup;
   }

   if (!_get_data_key_from_response(response, key, error)) {
      goto cleanup;
   }

   ret = true;
cleanup:
   kms_request_opt_destroy (request_opt);
   kms_request_destroy (request);
   kms_response_destroy (response);
   return ret;
}
