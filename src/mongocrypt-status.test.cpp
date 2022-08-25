#include <catch2/catch_test_macros.hpp>

#include "mongocrypt.h"

TEST_CASE ("Status length")
{
   mongocrypt_status_t *status = mongocrypt_status_new ();
   auto somestring = "something";
   const uint32_t errcode = 123;

   mongocrypt_status_set (
      status, MONGOCRYPT_STATUS_ERROR_CLIENT, errcode, somestring, 3);
   uint32_t out_len;
   const char *out = mongocrypt_status_message (status, &out_len);
   CHECK (out_len == 2);
   CHECK (Catch::StringRef (out) == "so");
   mongocrypt_status_destroy (status);
}
