#include "mongocrypt.h"

#include "test-mongocrypt.h"
#include "mongocrypt-util-private.h"

static mongocrypt_t *
get_test_mongocrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt = mongocrypt_new ();
   mongocrypt_setopt_log_handler (crypt, _mongocrypt_stdout_log_fn, NULL);
   mongocrypt_binary_t *schema_map = TEST_FILE ("./test/data/schema-map.json");
   ASSERT_OK (
      mongocrypt_setopt_kms_provider_aws (crypt, "example", -1, "example", -1),
      crypt);
   ASSERT_OK (mongocrypt_setopt_schema_map (crypt, schema_map), crypt);
   return crypt;
}

static void
_test_csfle_no_paths (_mongocrypt_tester_t *tester)
{
   /// Test that mongocrypt_init succeeds if we have no search path
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   mongocrypt_destroy (crypt);
}

static void
_test_csfle_not_found (_mongocrypt_tester_t *tester)
{
   /// Test that mongocrypt_init succeeds even if the csfle library was not
   /// found but a search path was specified
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   mongocrypt_setopt_append_csfle_search_path (crypt, "/no-such-directory");
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   mongocrypt_destroy (crypt);
}

static void
_test_csfle_load (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   mongocrypt_setopt_append_csfle_search_path (crypt, "no-such-directory");
   mongocrypt_setopt_append_csfle_search_path (crypt, "$ORIGIN");
   mongocrypt_setopt_append_csfle_search_path (crypt, "another-no-such-dir");
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   mongocrypt_destroy (crypt);
}

static void
_test_csfle_path_override_okay (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   // Set to the absolute path to the DLL we download for testing:
   mongocrypt_setopt_set_csfle_lib_path_override (
      crypt, "$ORIGIN/mongo_csfle_v1" MCR_DLL_SUFFIX);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   mongocrypt_destroy (crypt);
}

static void
_test_csfle_path_override_fail (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   // Set to the absolute path to a file that does not exist
   mongocrypt_setopt_set_csfle_lib_path_override (
      crypt, "/no-such-file-or-directory/mongo_csfle_v1" MCR_DLL_SUFFIX);
   // This *would* succeed, but we don't use the search paths if an absolute
   // override was specified:
   mongocrypt_setopt_append_csfle_search_path (crypt, "$ORIGIN");
   ASSERT_FAILS (mongocrypt_init (crypt),
                 crypt,
                 "but we failed to open a dynamic library at that location");
   mongocrypt_destroy (crypt);
}

static void
_test_cur_exe_path ()
{
   current_module_result self = current_module_path ();
   BSON_ASSERT (self.error == 0);
   BSON_ASSERT (self.path.len != 0);
   mstr_free (self.path);
}

void
_mongocrypt_tester_install_csfle_lib (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_csfle_no_paths);
   INSTALL_TEST (_test_csfle_not_found);
   INSTALL_TEST (_test_csfle_load);
   INSTALL_TEST (_test_csfle_path_override_okay);
   INSTALL_TEST (_test_csfle_path_override_fail);
   INSTALL_TEST (_test_cur_exe_path);
}
