
#include "mongocrypt.h"

#include "test-mongocrypt.h"

static void
_test_append_path (_mongocrypt_tester_t *t)
{
   char cwd[512 * 4];
   getcwd (cwd, sizeof cwd);
   mongocrypt_t *crypt = mongocrypt_new ();
   mongocrypt_setopt_append_csefle_search_path (crypt, cwd);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_csefle_lib (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_append_path);
}
