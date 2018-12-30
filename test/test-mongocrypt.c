#include <stdio.h>
#include <stdlib.h>

#include "mongocrypt.h"

static void roundtrip_test(void) {
   mongoc_crypt_opts_t* opts;
   mongoc_crypt_t* crypt;
   mongoc_crypt_error_t error;

   opts = mongoc_crypt_opts_new();
   mongoc_crypt_opts_set_opt (opts, MONGOCRYPT_AWS_ACCESS_KEY_ID, getenv("AWS_ACCESS_KEY_ID"));
   mongoc_crypt_opts_set_opt (opts, MONGOCRYPT_AWS_SECRET_ACCESS_KEY, getenv("AWS_SECRET_ACCESS_KEY"));
   mongoc_crypt_opts_set_opt (opts, MONGOCRYPT_AWS_REGION, getenv("AWS_REGION"));
   mongoc_crypt_opts_set_opt (opts, MONGOCRYPT_DEFAULT_KEYVAULT_CLIENT_URI, "mongodb://localhost:27017");

   crypt = mongoc_crypt_new (opts, &error);
   if (!crypt) {
      fprintf(stderr, "error creating crypt: %s\n", error.message);
      abort();
   }

   mongoc_crypt_destroy (crypt);
   mongoc_crypt_opts_destroy (opts);
}

int main(int argc, char** argv) {
   printf("Test runner\n");
   roundtrip_test();
}