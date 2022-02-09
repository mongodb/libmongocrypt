
#include "mongocrypt.h"

#include "test-mongocrypt.h"
#include "mongocrypt-util-private.h"

static void
_test_csfle_load (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt = mongocrypt_new ();
   mongocrypt_setopt_log_handler (crypt, _mongocrypt_stdout_log_fn, NULL);
   mongocrypt_binary_t *schema_map = TEST_FILE ("./test/data/schema-map.json");
   ASSERT_OK (
      mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1),
      crypt);
   mongocrypt_setopt_append_csfle_search_path (crypt, "no-such-directory");
   mongocrypt_setopt_append_csfle_search_path (crypt, "$ORIGIN");
   ASSERT_OK (mongocrypt_setopt_schema_map (crypt, schema_map), crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   mongocrypt_destroy (crypt);
}

static void
_test_cur_exe_path ()
{
   current_exe_result self = current_module_path ();
   BSON_ASSERT (self.error == 0);
   BSON_ASSERT (self.path.len != 0);
   mstr_free (self.path);
}

void
_mongocrypt_tester_install_csfle_lib (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_csfle_load);
   INSTALL_TEST (_test_cur_exe_path);
}
