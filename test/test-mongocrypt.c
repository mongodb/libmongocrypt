#include <stdio.h>
#include <stdlib.h>

#include <mongoc/mongoc.h>
#include <mongocrypt.h>

#define ASSERT_OR_PRINT(_statement, _err)             \
   do {                                               \
      if (!(_statement)) {                            \
         fprintf (stderr,                             \
                  "FAIL:%s:%d  %s()\n  %s\n  %s\n\n", \
                  __FILE__,                           \
                  __LINE__,                           \
                  BSON_FUNC,                          \
                  #_statement,                        \
                  _err.message);                      \
         fflush (stderr);                             \
         abort ();                                    \
      }                                               \
   } while (0)


static void
_setup (mongocrypt_opts_t *opts, bson_t *schema)
{
   bson_json_reader_t *reader;
   bson_error_t error;
   int status;

   reader = bson_json_reader_new_from_file ("./test/schema.json", &error);
   ASSERT_OR_PRINT (reader, error);

   bson_init (schema);
   status = bson_json_reader_read (reader, schema, &error);
   ASSERT_OR_PRINT (status == 1, error);

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
roundtrip_test (void)
{
   mongocrypt_opts_t *opts;
   mongocrypt_t *crypt;
   mongocrypt_error_t error;
   bson_t schema, out;
   bson_t *doc;
   mongocrypt_bson_t bson_schema = {0}, bson_doc = {0}, bson_out = {0};
   int ret;

   opts = mongocrypt_opts_new ();
   _setup (opts, &schema);

   crypt = mongocrypt_new (opts, &error);
   if (!crypt) {
      fprintf (stderr, "error creating crypt: %s\n", error.message);
      abort ();
   }

   doc = BCON_NEW ("name", "Todd Davis", "ssn", "457-55-5642");

   bson_schema.data = (uint8_t *) bson_get_data (&schema);
   bson_schema.len = schema.len;

   bson_doc.data = (uint8_t *) bson_get_data (doc);
   bson_doc.len = doc->len;

   ret = mongocrypt_encrypt (crypt, &bson_schema, &bson_doc, &bson_out, &error);
   ASSERT_OR_PRINT (ret, error);
   bson_init_static (&out, bson_out.data, bson_out.len);
   printf ("encrypted: %s\n", bson_as_json (&out, NULL));

   bson_destroy (doc);
   bson_destroy (&schema);
   mongocrypt_destroy (crypt);
   mongocrypt_opts_destroy (opts);
}

int
main (int argc, char **argv)
{
   mongocrypt_init ();
   printf ("Test runner\n");
   roundtrip_test ();
   mongocrypt_cleanup ();
}