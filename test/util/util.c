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

#include "util.h"

/* Utilities for integration tests and example runners. */

#include <mongoc/mongoc.h>
#include "mongocrypt.h"

static void
_errexit_status (mongocrypt_status_t *status, int line)
{
   int code;
   const char *msg;

   code = mongocrypt_status_code (status);
   msg = mongocrypt_status_message (status, NULL);
   MONGOC_ERROR ("Error at line %d with code %d and msg: %s", line, code, msg);
   exit (1);
}

void
_errexit_mongocrypt (mongocrypt_t *crypt, int line)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   mongocrypt_status (crypt, status);
   _errexit_status (status, line);
   mongocrypt_status_destroy (status);
}

void
_errexit_ctx (mongocrypt_ctx_t *ctx, int line)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   mongocrypt_ctx_status (ctx, status);
   _errexit_status (status, line);
   mongocrypt_status_destroy (status);
}

void
_errexit_bson (bson_error_t *error, int line)
{
   MONGOC_ERROR ("Error at line %d with code %d and msg: %s",
                 line,
                 error->code,
                 error->message);
   exit (1);
}

void
_log_to_stdout (mongocrypt_log_level_t level,
                const char *message,
                uint32_t message_len,
                void *ctx)
{
   switch (level) {
   case MONGOCRYPT_LOG_LEVEL_FATAL:
      printf ("FATAL");
      break;
   case MONGOCRYPT_LOG_LEVEL_ERROR:
      printf ("ERROR");
      break;
   case MONGOCRYPT_LOG_LEVEL_WARNING:
      printf ("WARNING");
      break;
   case MONGOCRYPT_LOG_LEVEL_INFO:
      printf ("INFO");
      break;
   case MONGOCRYPT_LOG_LEVEL_TRACE:
      printf ("TRACE");
      break;
   }
   printf (" %s\n", message);
}

char *
util_getenv (const char *key)
{
   char *value = getenv (key);
   if (!value) {
      MONGOC_ERROR ("Environment variable: %s not set", key);
   }
   return value;
}

mongocrypt_binary_t *
util_bson_to_bin (bson_t *bson)
{
   return mongocrypt_binary_new_from_data ((uint8_t *) bson_get_data (bson),
                                           bson->len);
}

bson_t *
util_bin_to_bson (mongocrypt_binary_t *bin)
{
   return bson_new_from_data (mongocrypt_binary_data (bin),
                              mongocrypt_binary_len (bin));
}

static void
_prefix_mongocryptd_error (bson_error_t *error)
{
   char buf[sizeof (error->message)];

   bson_snprintf (buf, sizeof (buf), "mongocryptd error: %s:", error->message);
   memcpy (error->message, buf, sizeof (buf));
}

static void
_prefix_keyvault_error (bson_error_t *error)
{
   char buf[sizeof (error->message)];

   bson_snprintf (buf, sizeof (buf), "key vault error: %s:", error->message);
   memcpy (error->message, buf, sizeof (buf));
}

static void
_status_to_error (mongocrypt_status_t *status, bson_error_t *error)
{
   bson_set_error (error,
                   MONGOC_ERROR_CLIENT_SIDE_ENCRYPTION,
                   mongocrypt_status_code (status),
                   "%s",
                   mongocrypt_status_message (status, NULL));
}

/* Checks for an error on mongocrypt context.
 * If error_expected, then we expect mongocrypt_ctx_status to report a failure
 * status (due to a previous failed function call). If it did not, return a
 * generic error.
 * Returns true if ok, and does not modify @error.
 * Returns false if error, and sets @error.
 */
bool
_ctx_check_error (mongocrypt_ctx_t *ctx,
                  bson_error_t *error,
                  bool error_expected)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   if (!mongocrypt_ctx_status (ctx, status)) {
      _status_to_error (status, error);
      mongocrypt_status_destroy (status);
      return false;
   } else if (error_expected) {
      bson_set_error (error,
                      MONGOC_ERROR_CLIENT,
                      MONGOC_ERROR_CLIENT_INVALID_ENCRYPTION_STATE,
                      "generic error from libmongocrypt operation");
      mongocrypt_status_destroy (status);
      return false;
   }
   mongocrypt_status_destroy (status);
   return true;
}

bool
_kms_ctx_check_error (mongocrypt_kms_ctx_t *kms_ctx,
                      bson_error_t *error,
                      bool error_expected)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   if (!mongocrypt_kms_ctx_status (kms_ctx, status)) {
      _status_to_error (status, error);
      mongocrypt_status_destroy (status);
      return false;
   } else if (error_expected) {
      bson_set_error (error,
                      MONGOC_ERROR_CLIENT,
                      MONGOC_ERROR_CLIENT_INVALID_ENCRYPTION_STATE,
                      "generic error from libmongocrypt KMS operation");
      mongocrypt_status_destroy (status);
      return false;
   }
   mongocrypt_status_destroy (status);
   return true;
}

bool
_crypt_check_error (mongocrypt_t *crypt,
                    bson_error_t *error,
                    bool error_expected)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   if (!mongocrypt_status (crypt, status)) {
      _status_to_error (status, error);
      mongocrypt_status_destroy (status);
      return false;
   } else if (error_expected) {
      bson_set_error (error,
                      MONGOC_ERROR_CLIENT,
                      MONGOC_ERROR_CLIENT_INVALID_ENCRYPTION_STATE,
                      "generic error from libmongocrypt handle");
      mongocrypt_status_destroy (status);
      return false;
   }
   mongocrypt_status_destroy (status);
   return true;
}

/* Convert a mongocrypt_binary_t to a static bson_t */
static bool
_bin_to_static_bson (mongocrypt_binary_t *bin, bson_t *out, bson_error_t *error)
{
   /* Copy bin into bson_t result. */
   if (!bson_init_static (
          out, mongocrypt_binary_data (bin), mongocrypt_binary_len (bin))) {
      bson_set_error (error,
                      MONGOC_ERROR_BSON,
                      MONGOC_ERROR_BSON_INVALID,
                      "invalid returned bson");
      return false;
   }
   return true;
}

/* State handler MONGOCRYPT_CTX_NEED_MONGO_COLLINFO */
static bool
_state_need_mongo_collinfo (_state_machine_t *state_machine,
                            bson_error_t *error)
{
   mongoc_database_t *db = NULL;
   mongoc_cursor_t *cursor = NULL;
   bson_t filter_bson;
   const bson_t *collinfo_bson = NULL;
   bson_t opts = BSON_INITIALIZER;
   mongocrypt_binary_t *filter_bin = NULL;
   mongocrypt_binary_t *collinfo_bin = NULL;
   bool ret = false;

   /* 1. Run listCollections on the encrypted MongoClient with the filter
    * provided by mongocrypt_ctx_mongo_op */
   filter_bin = mongocrypt_binary_new ();
   if (!mongocrypt_ctx_mongo_op (state_machine->ctx, filter_bin)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   if (!_bin_to_static_bson (filter_bin, &filter_bson, error)) {
      goto fail;
   }

   bson_append_document (&opts, "filter", -1, &filter_bson);
   db = mongoc_client_get_database (state_machine->collinfo_client,
                                    state_machine->db_name);

   if (state_machine->trace) {
      char *opts_str;

      opts_str = bson_as_canonical_extended_json (&filter_bson, NULL);
      MONGOC_DEBUG (
         "--> sending listCollections cmd on db %s mongod with opts: %s",
         state_machine->db_name,
         opts_str);
      bson_free (opts_str);
   }
   cursor = mongoc_database_find_collections_with_opts (db, &opts);
   if (mongoc_cursor_error (cursor, error)) {
      goto fail;
   }

   /* 2. Return the first result (if any) with mongocrypt_ctx_mongo_feed or
    * proceed to the next step if nothing was returned. */
   if (mongoc_cursor_next (cursor, &collinfo_bson)) {
      if (state_machine->trace) {
         char *result_str;

         result_str = bson_as_canonical_extended_json (collinfo_bson, NULL);
         MONGOC_DEBUG ("<-- got result: %s", result_str);
         bson_free (result_str);
      }
      collinfo_bin = mongocrypt_binary_new_from_data (
         (uint8_t *) bson_get_data (collinfo_bson), collinfo_bson->len);
      if (!mongocrypt_ctx_mongo_feed (state_machine->ctx, collinfo_bin)) {
         _ctx_check_error (state_machine->ctx, error, true);
         goto fail;
      }
   } else if (mongoc_cursor_error (cursor, error)) {
      goto fail;
   }

   /* 3. Call mongocrypt_ctx_mongo_done */
   if (!mongocrypt_ctx_mongo_done (state_machine->ctx)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   ret = true;

fail:

   bson_destroy (&opts);
   mongocrypt_binary_destroy (filter_bin);
   mongocrypt_binary_destroy (collinfo_bin);
   mongoc_cursor_destroy (cursor);
   mongoc_database_destroy (db);
   return ret;
}

static bool
_state_need_mongo_markings (_state_machine_t *state_machine,
                            bson_error_t *error)
{
   bool ret = false;
   mongocrypt_binary_t *mongocryptd_cmd_bin = NULL;
   mongocrypt_binary_t *mongocryptd_reply_bin = NULL;
   bson_t mongocryptd_cmd_bson;
   bson_t reply = BSON_INITIALIZER;

   mongocryptd_cmd_bin = mongocrypt_binary_new ();

   if (!mongocrypt_ctx_mongo_op (state_machine->ctx, mongocryptd_cmd_bin)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   if (!_bin_to_static_bson (
          mongocryptd_cmd_bin, &mongocryptd_cmd_bson, error)) {
      goto fail;
   }

   if (state_machine->trace) {
      char *cmd_str;
      bson_iter_t iter;

      bson_iter_init (&iter, &mongocryptd_cmd_bson);
      bson_iter_next (&iter);
      cmd_str = bson_as_canonical_extended_json (&mongocryptd_cmd_bson, NULL);
      MONGOC_DEBUG ("--> sending %s cmd to mongocryptd: %s",
                    bson_iter_key (&iter),
                    cmd_str);
      bson_free (cmd_str);
   }

   /* 1. Use db.runCommand to run the command provided by
    * mongocrypt_ctx_mongo_op on the MongoClient connected to mongocryptd. */
   bson_destroy (&reply);
   if (!mongoc_client_command_simple (state_machine->mongocryptd_client,
                                      "admin",
                                      &mongocryptd_cmd_bson,
                                      NULL /* read_prefs */,
                                      &reply,
                                      error)) {
      _prefix_mongocryptd_error (error);
      goto fail;
   }

   if (state_machine->trace) {
      char *reply_str;

      reply_str = bson_as_canonical_extended_json (&reply, NULL);
      MONGOC_DEBUG ("<-- got reply: %s", reply_str);
      bson_free (reply_str);
   }

   /* 2. Feed the reply back with mongocrypt_ctx_mongo_feed. */
   mongocryptd_reply_bin = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (&reply), reply.len);
   if (!mongocrypt_ctx_mongo_feed (state_machine->ctx, mongocryptd_reply_bin)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   /* 3. Call mongocrypt_ctx_mongo_done. */
   if (!mongocrypt_ctx_mongo_done (state_machine->ctx)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   ret = true;
fail:
   bson_destroy (&reply);
   mongocrypt_binary_destroy (mongocryptd_cmd_bin);
   mongocrypt_binary_destroy (mongocryptd_reply_bin);
   return ret;
}

static bool
_state_need_mongo_keys (_state_machine_t *state_machine, bson_error_t *error)
{
   bool ret = false;
   mongocrypt_binary_t *filter_bin = NULL;
   bson_t filter_bson;
   bson_t opts = BSON_INITIALIZER;
   mongocrypt_binary_t *key_bin = NULL;
   const bson_t *key_bson;
   mongoc_cursor_t *cursor = NULL;
   mongoc_read_concern_t *rc = NULL;

   /* 1. Use MongoCollection.find on the MongoClient connected to the key vault
    * client (which may be the same as the encrypted client). Use the filter
    * provided by mongocrypt_ctx_mongo_op. */
   filter_bin = mongocrypt_binary_new ();
   if (!mongocrypt_ctx_mongo_op (state_machine->ctx, filter_bin)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   if (!_bin_to_static_bson (filter_bin, &filter_bson, error)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   rc = mongoc_read_concern_new ();
   mongoc_read_concern_set_level (rc, MONGOC_READ_CONCERN_LEVEL_MAJORITY);
   if (!mongoc_read_concern_append (rc, &opts)) {
      bson_set_error (error,
                      MONGOC_ERROR_BSON,
                      MONGOC_ERROR_BSON_INVALID,
                      "%s",
                      "could not set read concern");
      goto fail;
   }

   if (state_machine->trace) {
      char *filter_str;
      char *opts_str;

      filter_str = bson_as_canonical_extended_json (&filter_bson, NULL);
      opts_str = bson_as_canonical_extended_json (&opts, NULL);
      MONGOC_DEBUG ("--> sending find to mongod with filter: %s and opts: %s",
                    filter_str,
                    opts_str);
      bson_free (filter_str);
      bson_free (opts_str);
   }

   cursor = mongoc_collection_find_with_opts (
      state_machine->keyvault_coll, &filter_bson, &opts, NULL /* read prefs */);
   /* 2. Feed all resulting documents back (if any) with repeated calls to
    * mongocrypt_ctx_mongo_feed. */
   while (mongoc_cursor_next (cursor, &key_bson)) {
      if (state_machine->trace) {
         char *key_str;

         key_str = bson_as_canonical_extended_json (key_bson, NULL);
         MONGOC_DEBUG ("<-- got result key document: %s", key_str);
         bson_free (key_str);
      }
      mongocrypt_binary_destroy (key_bin);
      key_bin = mongocrypt_binary_new_from_data (
         (uint8_t *) bson_get_data (key_bson), key_bson->len);
      if (!mongocrypt_ctx_mongo_feed (state_machine->ctx, key_bin)) {
         _ctx_check_error (state_machine->ctx, error, true);
         goto fail;
      }
   }
   if (mongoc_cursor_error (cursor, error)) {
      _prefix_keyvault_error (error);
      goto fail;
   }

   /* 3. Call mongocrypt_ctx_mongo_done. */
   if (!mongocrypt_ctx_mongo_done (state_machine->ctx)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   ret = true;
fail:
   mongocrypt_binary_destroy (filter_bin);
   mongoc_cursor_destroy (cursor);
   mongoc_read_concern_destroy (rc);
   bson_destroy (&opts);
   mongocrypt_binary_destroy (key_bin);
   return ret;
}

/* Create a TLS stream to a host. */
static mongoc_stream_t *
connect_stream_with_tls (mongoc_ssl_opt_t *ssl_opt,
                         const char *endpoint,
                         int32_t connecttimeoutms,
                         bson_error_t *error)
{
   mongoc_stream_t *stream = NULL;
   mongoc_socket_t *sock = NULL;
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   int64_t expire_at;
   int s;
   char *colon = NULL;
   char *host = NULL;
   char *port = NULL;
   bool success = false;

   colon = strstr (endpoint, ":");
   if (colon == NULL) {
      host = bson_strdup (endpoint);
      port = bson_strdup ("443");
   } else {
      host = bson_strndup (endpoint, colon - endpoint);
      port = bson_strdup (colon + 1);
   }

   memset (&hints, 0, sizeof hints);
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0;

   s = getaddrinfo (host, port, &hints, &result);
   if (s != 0) {
      MONGOC_ERROR ("DNS lookup failed: %s", host);
      goto done;
   }

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
      MONGOC_ERROR ("Failed to connect: %s", host);
      goto done;
   }

   stream = mongoc_stream_socket_new (sock);
   if (!stream) {
      MONGOC_ERROR ("Failed to create stream: %s", host);
      goto done;
   }

   success = true;
done:
   if (result) {
      freeaddrinfo (result);
   }
   if (success) {
      stream = mongoc_stream_tls_new_with_hostname (stream, host, ssl_opt, 1);
   } else {
      mongoc_stream_destroy (stream);
      stream = NULL;
   }

   if (!mongoc_stream_tls_handshake_block (
          stream, host, connecttimeoutms, error)) {
      mongoc_stream_destroy (stream);
      stream = NULL;
   }

   bson_free (host);
   bson_free (port);
   return stream;
}

/* Copied from mongoc-stream.c */
bool
_mongoc_stream_writev_full (mongoc_stream_t *stream,
                            mongoc_iovec_t *iov,
                            size_t iovcnt,
                            int32_t timeout_msec,
                            bson_error_t *error)
{
   size_t total_bytes = 0;
   size_t i;
   ssize_t r;

   for (i = 0; i < iovcnt; i++) {
      total_bytes += iov[i].iov_len;
   }

   r = mongoc_stream_writev (stream, iov, iovcnt, timeout_msec);

   if (r < 0) {
      if (error) {
         char buf[128];
         char *errstr;

         errstr = bson_strerror_r (errno, buf, sizeof (buf));

         bson_set_error (error,
                         MONGOC_ERROR_STREAM,
                         MONGOC_ERROR_STREAM_SOCKET,
                         "Failure during socket delivery: %s (%d)",
                         errstr,
                         errno);
      }

      return false;
   }

   if (r != (ssize_t) total_bytes) {
      bson_set_error (error,
                      MONGOC_ERROR_STREAM,
                      MONGOC_ERROR_STREAM_SOCKET,
                      "Failure to send all requested bytes (only sent: %" PRIu64
                      "/%" PRId64 " in %dms) during socket delivery",
                      (uint64_t) r,
                      (int64_t) total_bytes,
                      timeout_msec);

      return false;
   }

   return true;
}

static bool
_state_need_kms (_state_machine_t *state_machine, bson_error_t *error)
{
   mongocrypt_kms_ctx_t *kms_ctx = NULL;
   mongoc_stream_t *tls_stream = NULL;
   bool ret = false;
   mongocrypt_binary_t *http_req = NULL;
   mongocrypt_binary_t *http_reply = NULL;
   const char *endpoint;
   uint32_t sockettimeout;
   mongoc_ssl_opt_t ssl_opt;

   sockettimeout = MONGOC_DEFAULT_SOCKETTIMEOUTMS;
   kms_ctx = mongocrypt_ctx_next_kms_ctx (state_machine->ctx);
   while (kms_ctx) {
      mongoc_iovec_t iov;

      mongocrypt_binary_destroy (http_req);
      http_req = mongocrypt_binary_new ();
      if (!mongocrypt_kms_ctx_message (kms_ctx, http_req)) {
         _kms_ctx_check_error (kms_ctx, error, true);
         goto fail;
      }

      if (!mongocrypt_kms_ctx_endpoint (kms_ctx, &endpoint)) {
         _kms_ctx_check_error (kms_ctx, error, true);
         goto fail;
      }

      ssl_opt = *mongoc_ssl_opt_get_default ();
      ssl_opt.ca_file = state_machine->tls_ca_file;
      ssl_opt.pem_file = state_machine->tls_certificate_key_file;
      tls_stream =
         connect_stream_with_tls (&ssl_opt, endpoint, sockettimeout, error);
#ifdef MONGOC_ENABLE_SSL_SECURE_CHANNEL
      /* Retry once with schannel as a workaround for CDRIVER-3566. */
      if (!tls_stream) {
         tls_stream =
            connect_stream_with_tls (&ssl_opt, endpoint, sockettimeout, error);
      }
#endif
      if (!tls_stream) {
         goto fail;
      }

      iov.iov_base = (char *) mongocrypt_binary_data (http_req);
      iov.iov_len = mongocrypt_binary_len (http_req);

      if (state_machine->trace) {
         MONGOC_DEBUG ("--> sending KMS message: \n%.*s",
                       (int) iov.iov_len,
                       (char *) iov.iov_base);
      }

      if (!_mongoc_stream_writev_full (
             tls_stream, &iov, 1, sockettimeout, error)) {
         goto fail;
      }

      /* Read and feed reply. */
      while (mongocrypt_kms_ctx_bytes_needed (kms_ctx) > 0) {
#define BUFFER_SIZE 1024
         uint8_t buf[BUFFER_SIZE];
         uint32_t bytes_needed = mongocrypt_kms_ctx_bytes_needed (kms_ctx);
         ssize_t read_ret;

         /* Cap the bytes requested at the buffer size. */
         if (bytes_needed > BUFFER_SIZE) {
            bytes_needed = BUFFER_SIZE;
         }

         read_ret = mongoc_stream_read (
            tls_stream, buf, bytes_needed, 1 /* min_bytes. */, sockettimeout);
         if (read_ret == -1) {
            bson_set_error (error,
                            MONGOC_ERROR_STREAM,
                            MONGOC_ERROR_STREAM_SOCKET,
                            "failed to read from KMS stream: %d",
                            errno);
            goto fail;
         }

         if (read_ret == 0) {
            bson_set_error (error,
                            MONGOC_ERROR_STREAM,
                            MONGOC_ERROR_STREAM_SOCKET,
                            "unexpected EOF from KMS stream");
            goto fail;
         }

         if (state_machine->trace) {
            MONGOC_DEBUG (
               "<-- read KMS reply: %.*s", (int) read_ret, (char *) buf);
         }

         mongocrypt_binary_destroy (http_reply);
         http_reply = mongocrypt_binary_new_from_data (buf, read_ret);
         if (!mongocrypt_kms_ctx_feed (kms_ctx, http_reply)) {
            _kms_ctx_check_error (kms_ctx, error, true);
            goto fail;
         }
      }
      kms_ctx = mongocrypt_ctx_next_kms_ctx (state_machine->ctx);
   }
   /* When NULL is returned by mongocrypt_ctx_next_kms_ctx, this can either be
    * an error or end-of-list. */
   if (!_ctx_check_error (state_machine->ctx, error, false)) {
      goto fail;
   }

   if (!mongocrypt_ctx_kms_done (state_machine->ctx)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   ret = true;
fail:
   mongoc_stream_destroy (tls_stream);
   mongocrypt_binary_destroy (http_req);
   mongocrypt_binary_destroy (http_reply);
   return ret;
#undef BUFFER_SIZE
}

static bool
_state_ready (_state_machine_t *state_machine,
              bson_t *result,
              bson_error_t *error)
{
   mongocrypt_binary_t *result_bin = NULL;
   bson_t tmp;
   bool ret = false;

   bson_init (result);
   result_bin = mongocrypt_binary_new ();
   if (!mongocrypt_ctx_finalize (state_machine->ctx, result_bin)) {
      _ctx_check_error (state_machine->ctx, error, true);
      goto fail;
   }

   if (!_bin_to_static_bson (result_bin, &tmp, error)) {
      goto fail;
   }

   bson_destroy (result);
   bson_copy_to (&tmp, result);

   ret = true;
fail:
   mongocrypt_binary_destroy (result_bin);
   return ret;
}

const char *
_state_string (mongocrypt_ctx_state_t state)
{
   switch (state) {
   case MONGOCRYPT_CTX_ERROR:
      return "MONGOCRYPT_CTX_ERROR";
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      return "MONGOCRYPT_CTX_NEED_MONGO_COLLINFO";
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      return "MONGOCRYPT_CTX_NEED_MONGO_MARKINGS";
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      return "MONGOCRYPT_CTX_NEED_MONGO_KEYS";
   case MONGOCRYPT_CTX_NEED_KMS:
      return "MONGOCRYPT_CTX_NEED_KMS";
   case MONGOCRYPT_CTX_READY:
      return "MONGOCRYPT_CTX_READY";
   case MONGOCRYPT_CTX_DONE:
      return "MONGOCRYPT_CTX_DONE";
   default:
      return "UNKNOWN";
   }
}

/*--------------------------------------------------------------------------
 *
 * _mongoc_cse_run_state_machine --
 *    Run the mongocrypt_ctx state machine.
 *
 * Post-conditions:
 *    *result may be set to a new bson_t, or NULL otherwise. Caller should
 *    not assume return value of true means *result is set. If false returned,
 *    @error is set.
 *
 * --------------------------------------------------------------------------
 */
bool
_state_machine_run (_state_machine_t *state_machine,
                    bson_t *result,
                    bson_error_t *error)
{
   bool ret = false;
   mongocrypt_binary_t *bin = NULL;

   bson_init (result);
   while (true) {
      if (state_machine->trace) {
         MONGOC_DEBUG (
            "Current state = %s",
            _state_string (mongocrypt_ctx_state (state_machine->ctx)));
      }
      switch (mongocrypt_ctx_state (state_machine->ctx)) {
      default:
      case MONGOCRYPT_CTX_ERROR:
         _ctx_check_error (state_machine->ctx, error, true);
         goto fail;
      case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
         if (!_state_need_mongo_collinfo (state_machine, error)) {
            goto fail;
         }
         break;
      case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
         if (!_state_need_mongo_markings (state_machine, error)) {
            goto fail;
         }
         break;
      case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
         if (!_state_need_mongo_keys (state_machine, error)) {
            goto fail;
         }
         break;
      case MONGOCRYPT_CTX_NEED_KMS:
         if (!_state_need_kms (state_machine, error)) {
            goto fail;
         }
         break;
      case MONGOCRYPT_CTX_READY:
         bson_destroy (result);
         if (!_state_ready (state_machine, result, error)) {
            goto fail;
         }
         break;
      case MONGOCRYPT_CTX_DONE:
         goto success;
         break;
      }
   }

success:
   ret = true;
fail:
   if (!ret && state_machine->trace) {
      MONGOC_DEBUG ("Error: %s", error->message);
   }
   mongocrypt_binary_destroy (bin);
   return ret;
}

bson_t *
util_read_json_file (const char *path)
{
   bson_json_reader_t *reader;
   bson_error_t error;
   bson_t *doc;

   reader = bson_json_reader_new_from_file (path, &error);
   if (!reader) {
      ERREXIT ("Error opening %s: %s", path, error.message);
   }

   doc = bson_new ();
   if (1 != bson_json_reader_read (reader, doc, &error)) {
      ERREXIT ("Could not read BSON from %s: %s", path, error.message);
   }
   bson_json_reader_destroy (reader);
   return doc;
}

void
args_parse (bson_t *args, int argc, char **argv)
{
   int i;

   if (argc % 2 != 0) {
      ERREXIT ("Invalid arguments, expected list of key-value pairs.");
   }

   for (i = 0; i < argc; i++) {
      for (i = 0; i < argc; i += 2) {
         if (0 != strncmp (argv[i], "--", 2)) {
            ERREXIT ("Malformed option: %s", argv[i]);
         }
         bson_append_utf8 (args, argv[i] + 2, -1, argv[i + 1], -1);
      }
   }
}

const char *
bson_get_utf8 (bson_t *bson, const char *dotkey, const char *default_value)
{
   bson_iter_t iter;

   bson_iter_init (&iter, bson);
   if (bson_iter_find_descendant (&iter, dotkey, &iter) &&
       BSON_ITER_HOLDS_UTF8 (&iter)) {
      return bson_iter_utf8 (&iter, NULL);
   }
   return default_value;
}

const char *
bson_req_utf8 (bson_t *bson, const char *dotkey)
{
   const char *ret;

   ret = bson_get_utf8 (bson, dotkey, NULL);
   if (!ret) {
      ERREXIT ("Required field missing: '%s'", dotkey);
   }
   return ret;
}

const uint8_t *
bson_get_bin (bson_t *bson, const char *dotkey, uint32_t *len)
{
   bson_iter_t iter;
   bson_iter_t subiter;
   bson_subtype_t subtype;
   const uint8_t *data = NULL;

   bson_iter_init (&iter, bson);
   if (bson_iter_find_descendant (&iter, dotkey, &subiter) &&
       BSON_ITER_HOLDS_BINARY (&subiter)) {
      bson_iter_binary (&subiter, &subtype, len, &data);
   }
   return data;
}

const uint8_t *
bson_req_bin (bson_t *bson, const char *dotkey, uint32_t *len)
{
   const uint8_t *ret;

   ret = bson_get_bin (bson, dotkey, len);
   if (!ret) {
      ERREXIT ("Required field missing: '%s'", dotkey);
   }
   return ret;
}

bson_t *
bson_get_json (bson_t *bson, const char *dotkey)
{
   const char *path;

   path = bson_get_utf8 (bson, dotkey, NULL);
   if (!path) {
      return NULL;
   }
   return util_read_json_file (path);
}

bson_t *
bson_req_json (bson_t *bson, const char *dotkey)
{
   bson_t *ret;

   ret = bson_get_json (bson, dotkey);
   if (!ret) {
      ERREXIT ("Required field missing: '%s'", dotkey);
   }
   return ret;
}

bool
bson_get_bool (bson_t *bson, const char *dotkey, bool default_value)
{
   const char *as_str;

   as_str = bson_get_utf8 (bson, dotkey, NULL);
   if (!as_str) {
      return default_value;
   }
   if (0 == bson_strcasecmp (as_str, "true") || 0 == strcmp (as_str, "1")) {
      return true;
   }
   return default_value;
}