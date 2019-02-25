#include <stdio.h>
#include <stdlib.h>

#include <mongoc/mongoc.h>
#include <mongocrypt.h>
#include <mongocrypt-crypto-private.h>
#include <mongocrypt-key-cache-private.h>
#include <mongocrypt-private.h>


#define ASSERT_OR_PRINT_MSG(_statement, msg)          \
   do {                                               \
      if (!(_statement)) {                            \
         fprintf (stderr,                             \
                  "FAIL:%s:%d  %s()\n  %s\n  %s\n\n", \
                  __FILE__,                           \
                  __LINE__,                           \
                  BSON_FUNC,                          \
                  #_statement,                        \
                  (msg));                             \
         fflush (stderr);                             \
         abort ();                                    \
      }                                               \
   } while (0)

#define ASSERT_OR_PRINT(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, mongocrypt_status_message (_err))

#define ASSERT_OR_PRINT_BSON(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, _err.message)

/* read the schema file, create mongocrypt_t handle with options. */
static void
_setup (mongocrypt_opts_t *opts, bson_t *one_schema)
{
   bson_json_reader_t *reader;
   bson_error_t error;
   int status;
   bson_iter_t iter;
   bson_t schemas;
   const uint8_t *data;
   uint32_t len;
   bson_t temp;

   reader = bson_json_reader_new_from_file ("./test/schema.json", &error);
   ASSERT_OR_PRINT_BSON (reader, error);

   bson_init (&schemas);
   status = bson_json_reader_read (reader, &schemas, &error);
   ASSERT_OR_PRINT_BSON (status == 1, error);

   printf ("schema: %s\n", tmp_json (&schemas));

   BSON_ASSERT (bson_iter_init_find (&iter, &schemas, "test.crypt"));
   BSON_ASSERT (BSON_ITER_HOLDS_DOCUMENT (&iter));
   bson_iter_recurse (&iter, &iter);
   BSON_ASSERT (bson_iter_find (&iter, "schema"));
   bson_iter_document (&iter, &len, &data);
   bson_init_static (&temp, data, len);
   bson_copy_to (&temp, one_schema);
   bson_destroy (&schemas);
   printf ("schema: %s\n", tmp_json (one_schema));

   mongocrypt_opts_set_opt (
      opts, MONGOCRYPT_AWS_ACCESS_KEY_ID, getenv ("AWS_ACCESS_KEY_ID"));
   mongocrypt_opts_set_opt (
      opts, MONGOCRYPT_AWS_SECRET_ACCESS_KEY, getenv ("AWS_SECRET_ACCESS_KEY"));
   mongocrypt_opts_set_opt (opts, MONGOCRYPT_AWS_REGION, getenv ("AWS_REGION"));

   bson_json_reader_destroy (reader);
}

static void
_satisfy_key_queries (mongoc_client_t *keyvault_client,
                      mongocrypt_request_t *request)
{
   mongoc_collection_t *keyvault_coll;

   keyvault_coll =
      mongoc_client_get_collection (keyvault_client, "admin", "datakeys");
   while (mongocrypt_request_needs_keys (request)) {
      const mongocrypt_key_query_t *key_query;
      const mongocrypt_binary_t *filter_bin;
      bson_t filter;
      const bson_t *result;
      mongoc_cursor_t *cursor;
      int ret;
      mongocrypt_status_t *status = mongocrypt_status_new ();

      key_query = mongocrypt_request_next_key_query (request, NULL);
      filter_bin = mongocrypt_key_query_filter (key_query);
      bson_init_static (&filter, filter_bin->data, filter_bin->len);
      printf ("using filter: %s\n", bson_as_json (&filter, NULL));

      cursor = mongoc_collection_find_with_opts (
         keyvault_coll, &filter, NULL /* opts */, NULL /* read prefs */);
      if (!cursor) {
         bson_error_t bson_error;
         mongoc_cursor_error (cursor, &bson_error);
         ASSERT_OR_PRINT_BSON (cursor, bson_error);
      }

      while (mongoc_cursor_next (cursor, &result)) {
         mongocrypt_binary_t key_bin;

         key_bin.data = (uint8_t *) bson_get_data (result);
         key_bin.len = result->len;
         ret = mongocrypt_request_add_keys (request, NULL, &key_bin, 1, status);
         ASSERT_OR_PRINT (ret, status);
      }
      mongocrypt_status_destroy (status);
   }

   /* TODO: leaks, leaks everywhere. */
}

static void
test_roundtrip (void)
{
   mongocrypt_opts_t *opts;
   mongocrypt_t *crypt;
   mongocrypt_status_t *status = mongocrypt_status_new ();
   bson_t schema, out;
   bson_t *cmd;
   mongocrypt_binary_t schema_bin = {0}, cmd_bin = {0}, encrypted_bin = {0},
                       *decrypted_bin;
   mongocrypt_request_t *request;
   mongoc_client_t *keyvault_client;
   int ret;

   opts = mongocrypt_opts_new ();
   _setup (opts, &schema);

   keyvault_client = mongoc_client_new ("mongodb://localhost:27017");

   crypt = mongocrypt_new (opts, status);
   ASSERT_OR_PRINT (crypt, status);

   cmd = BCON_NEW ("find",
                   "collection",
                   "filter",
                   "{",
                   "name",
                   "Todd Davis",
                   "ssn",
                   "457-55-5642",
                   "}");

   schema_bin.data = (uint8_t *) bson_get_data (&schema);
   schema_bin.len = schema.len;

   cmd_bin.data = (uint8_t *) bson_get_data (cmd);
   cmd_bin.len = cmd->len;

   request =
      mongocrypt_encrypt_start (crypt, NULL, &schema_bin, &cmd_bin, status);
   ASSERT_OR_PRINT (request, status);

   BSON_ASSERT (mongocrypt_request_needs_keys (request));
   _satisfy_key_queries (keyvault_client, request);
   _mongocrypt_key_cache_dump (crypt->cache);

   ret = mongocrypt_encrypt_finish (request, NULL, &encrypted_bin, status);
   ASSERT_OR_PRINT (ret, status);
   bson_init_static (&out, encrypted_bin.data, encrypted_bin.len);
   printf ("Encrypted document: %s\n", tmp_json (&out));

   request = mongocrypt_decrypt_start (crypt, NULL, &encrypted_bin, 1, status);
   ASSERT_OR_PRINT (request, status);

   /* Because no caching, we actually need to fetch keys again. */
   BSON_ASSERT (mongocrypt_request_needs_keys (request));
   _satisfy_key_queries (keyvault_client, request);
   _mongocrypt_key_cache_dump (crypt->cache);

   ret = mongocrypt_decrypt_finish (request, NULL, &decrypted_bin, status);
   ASSERT_OR_PRINT (ret, status);
   bson_init_static (&out, decrypted_bin->data, decrypted_bin->len);
   printf ("Decrypted document: %s\n", tmp_json (&out));

   mongocrypt_status_destroy (status);
}


/* Return a repeated character with no null terminator. */
static char *
_repeat_char (char c, uint32_t times)
{
   char *result;
   uint32_t i;

   result = bson_malloc (times);
   for (i = 0; i < times; i++) {
      result[i] = c;
   }

   return result;
}

void
_mongocrypt_test_roundtrip (void)
{
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key = {0}, iv = {0}, associated_data = {0},
                        plaintext = {0}, ciphertext = {0}, decrypted = {0};
   uint32_t bytes_written;
   bool ret;

   plaintext.data = (uint8_t *) "test";
   plaintext.len = 5; /* include NULL. */

   ciphertext.len = _mongocrypt_calculate_ciphertext_len (5);
   ciphertext.data = bson_malloc (ciphertext.len);
   ciphertext.owned = true;

   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   decrypted.owned = true;

   key.data = (uint8_t *) _repeat_char ('k', 64);
   key.len = 64;
   key.owned = true;

   iv.data = (uint8_t *) _repeat_char ('i', 16);
   iv.len = 16;
   iv.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (&iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);

   BSON_ASSERT (bytes_written == ciphertext.len);

   ret = _mongocrypt_do_decryption (
      &associated_data, &key, &ciphertext, &decrypted, &bytes_written, status);
   BSON_ASSERT (ret);


   BSON_ASSERT (bytes_written == plaintext.len);
   decrypted.len = bytes_written;
   BSON_ASSERT (0 == strcmp ((char *) decrypted.data, (char *) plaintext.data));

   /* Modify a bit in the ciphertext hash to ensure HMAC integrity check. */
   ciphertext.data[ciphertext.len - 1] &= 1;

   _mongocrypt_buffer_cleanup (&decrypted);
   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   decrypted.owned = true;

   ret = _mongocrypt_do_decryption (
      &associated_data, &key, &ciphertext, &decrypted, &bytes_written, status);
   BSON_ASSERT (!ret);
   BSON_ASSERT (0 == strcmp (status->message, "HMAC validation failure"));

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&decrypted);
   _mongocrypt_buffer_cleanup (&ciphertext);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
}


/* Helper to print binary. */
static void
_print_buf (const char *prefix, const _mongocrypt_buffer_t *buf)
{
   uint32_t i;

   printf ("%s has length: %d\n", prefix, buf->len);

   for (i = 0; i < buf->len; i++) {
      printf ("%02x", buf->data[i]);
   }
   printf ("\n");
}


static void
_init_buffer (_mongocrypt_buffer_t *out, const char *hex_string)
{
   int i;

   out->len = strlen (hex_string) / 2;
   out->data = bson_malloc (out->len);
   out->owned = true;
   for (i = 0; i < out->len; i++) {
      int tmp;
      BSON_ASSERT (sscanf (hex_string + (2 * i), "%02x", &tmp));
      *(out->data + i) = (uint8_t) tmp;
   }
}


/* From [MCGREW], see comment at the top of this file. */
void
_mongocrypt_test_mcgrew (void)
{
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key, iv, associated_data, plaintext,
      ciphertext_expected, ciphertext_actual;
   uint32_t bytes_written;
   bool ret;

   _init_buffer (&key,
                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1"
                 "b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
                 "3738393a3b3c3d3e3f");
   _init_buffer (&iv, "1af38c2dc2b96ffdd86694092341bc04");
   _init_buffer (&plaintext,
                 "41206369706865722073797374656d206d757374206e6f742"
                 "0626520726571756972656420746f20626520736563726574"
                 "2c20616e64206974206d7573742062652061626c6520746f2"
                 "066616c6c20696e746f207468652068616e6473206f662074"
                 "686520656e656d7920776974686f757420696e636f6e76656"
                 "e69656e6365");
   _init_buffer (&associated_data,
                 "546865207365636f6e64207072696e6369706c65206"
                 "f662041756775737465204b6572636b686f666673");
   _init_buffer (&ciphertext_expected,
                 "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10f"
                 "fbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e"
                 "9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75"
                 "c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae4"
                 "96b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930"
                 "930806d0703b1f64dd3b4c088a7f45c216839645b2012bf2e6269a8c56a81"
                 "6dbc1b267761955bc5");

   ciphertext_actual.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext_actual.data = bson_malloc (ciphertext_actual.len);
   ciphertext_actual.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (&iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext_actual,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);
   BSON_ASSERT (ciphertext_actual.len == ciphertext_expected.len);
   BSON_ASSERT (0 == memcmp (ciphertext_actual.data,
                             ciphertext_expected.data,
                             ciphertext_actual.len));

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&ciphertext_expected);
   _mongocrypt_buffer_cleanup (&ciphertext_actual);
   mongocrypt_status_destroy (status);
}


#define RUN_TEST(fn)                          \
   do {                                       \
      bool found = true;                      \
      if (argc > 1) {                         \
         int i;                               \
         found = false;                       \
         for (i = 1; i < argc; i++) {         \
            if (0 == strcmp (argv[i], #fn)) { \
               found = true;                  \
            }                                 \
         }                                    \
      }                                       \
      if (!found) {                           \
         break;                               \
      }                                       \
      printf ("running test: %s\n", #fn);     \
      fn ();                                  \
   } while (0);


int
main (int argc, char **argv)
{
   mongocrypt_init ();
   printf ("Test runner.\n");
   printf ("Pass a list of test names to run only specific tests. E.g.:\n");
   printf ("test-mongocrypt _mongocrypt_test_mcgrew\n\n");
   RUN_TEST (_mongocrypt_test_roundtrip);
   RUN_TEST (_mongocrypt_test_mcgrew);

   mongocrypt_cleanup ();
}
