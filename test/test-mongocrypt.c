#include <stdio.h>
#include <stdlib.h>

#include <mongoc/mongoc.h>
#include <mongocrypt.h>
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
   ASSERT_OR_PRINT_MSG (_statement, mongocrypt_error_message (_err))

#define ASSERT_OR_PRINT_BSON(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, _err.message)

static void
_setup (mongocrypt_opts_t *opts, bson_t *schema)
{
   bson_json_reader_t *reader;
   bson_error_t error;
   int status;

   reader = bson_json_reader_new_from_file ("./test/schema.json", &error);
   ASSERT_OR_PRINT_BSON (reader, error);

   bson_init (schema);
   status = bson_json_reader_read (reader, schema, &error);
   ASSERT_OR_PRINT_BSON (status == 1, error);

   mongocrypt_opts_set_opt (
      opts, MONGOCRYPT_AWS_ACCESS_KEY_ID, getenv ("AWS_ACCESS_KEY_ID"));
   mongocrypt_opts_set_opt (
      opts, MONGOCRYPT_AWS_SECRET_ACCESS_KEY, getenv ("AWS_SECRET_ACCESS_KEY"));
   mongocrypt_opts_set_opt (opts, MONGOCRYPT_AWS_REGION, getenv ("AWS_REGION"));
   mongocrypt_opts_set_opt (opts,
                            MONGOCRYPT_DEFAULT_KEYVAULT_CLIENT_URI,
                            "mongodb://localhost:27017");

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
      mongocrypt_key_query_t *key_query;
      const mongocrypt_binary_t *filter_bin;
      bson_t filter;
      const bson_t *result;
      mongoc_cursor_t *cursor;
      int ret;
      mongocrypt_error_t *error;

      key_query = mongocrypt_request_next_key_query (request, NULL);
      filter_bin = mongocrypt_key_query_filter (key_query);
      bson_init_static (&filter, filter_bin->data, filter_bin->len);

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
         ret = mongocrypt_request_add_keys (request, NULL, &key_bin, 1, &error);
         ASSERT_OR_PRINT (ret, error);
      }
   }

   /* TODO: leaks, leaks everywhere. */
}


/* TODO: clean up this test. */
static void
roundtrip_test (void)
{
   mongocrypt_opts_t *opts;
   mongocrypt_t *crypt;
   mongocrypt_error_t *error = NULL;
   bson_t schema, out;
   bson_t *doc;
   mongocrypt_binary_t schema_bin = {0}, doc_bin = {0}, bson_out = {0},
                       decrypted_out = {0};
   int ret;

   opts = mongocrypt_opts_new ();
   _setup (opts, &schema);

   crypt = mongocrypt_new (opts, &error);
   ASSERT_OR_PRINT (crypt, error);
   mongocrypt_error_destroy (error);

   doc = BCON_NEW ("name", "Todd Davis", "ssn", "457-55-5642");

   schema_bin.data = (uint8_t *) bson_get_data (&schema);
   schema_bin.len = schema.len;

   doc_bin.data = (uint8_t *) bson_get_data (doc);
   doc_bin.len = doc->len;

   ret = mongocrypt_encrypt (crypt, &schema_bin, &doc_bin, &bson_out, &error);
   ASSERT_OR_PRINT (ret, error);
   mongocrypt_error_destroy (error);

   bson_init_static (&out, bson_out.data, bson_out.len);
   printf ("encrypted: %s\n", bson_as_json (&out, NULL));

   ret = mongocrypt_decrypt (crypt, &bson_out, &decrypted_out, &error);
   ASSERT_OR_PRINT (ret, error);
   mongocrypt_error_destroy (error);

   bson_destroy (&out);
   bson_init_static (&out, decrypted_out.data, decrypted_out.len);
   printf ("decrypted: %s\n", bson_as_json (&out, NULL));

   bson_destroy (doc);
   bson_destroy (&schema);
   mongocrypt_destroy (crypt);
   mongocrypt_opts_destroy (opts);
}

static void
test_new_api (void)
{
   mongocrypt_opts_t *opts;
   mongocrypt_t *crypt;
   mongocrypt_error_t *error = NULL;
   bson_t schema, out;
   bson_t *cmd;
   mongocrypt_binary_t schema_bin = {0}, cmd_bin = {0}, encrypted_bin = {0}, decrypted_bin = {0};
   mongocrypt_request_t *request;
   mongoc_client_t *keyvault_client;
   int ret;

   opts = mongocrypt_opts_new ();
   _setup (opts, &schema);

   keyvault_client = mongoc_client_new ("mongodb://localhost:27017");

   crypt = mongocrypt_new (opts, &error);
   ASSERT_OR_PRINT (crypt, error);
   mongocrypt_error_destroy (error);

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
      mongocrypt_encrypt_start (crypt, NULL, &schema_bin, &cmd_bin, &error);
   ASSERT_OR_PRINT (request, error);
   mongocrypt_error_destroy (error);

   BSON_ASSERT (mongocrypt_request_needs_keys (request));
   _satisfy_key_queries (keyvault_client, request);
   _mongocrypt_keycache_dump (crypt);

   ret = mongocrypt_encrypt_finish (request, NULL, &encrypted_bin, &error);
   ASSERT_OR_PRINT (ret, error);
   bson_init_static (&out, encrypted_bin.data, encrypted_bin.len);
   printf("Final encrypted document: %s\n", tmp_json(&out));
   printf ("Did we get here? If not, we crashed!\n");
}

int
main (int argc, char **argv)
{
   mongocrypt_init ();
   printf ("Test runner\n");
   test_new_api ();
   mongocrypt_cleanup ();
}