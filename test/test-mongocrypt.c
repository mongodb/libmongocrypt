#include <stdio.h>
#include <stdlib.h>

#include <mongoc/mongoc.h>
#include <mongocrypt.h>
#include <mongocrypt-private.h>
#include <mongocrypt-key-cache-private.h>

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


extern void
_mongocrypt_test_roundtrip ();

int
main (int argc, char **argv)
{
   mongocrypt_init ();
   printf ("Test runner\n");
   _mongocrypt_test_roundtrip ();
   mongocrypt_cleanup ();
}
