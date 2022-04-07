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
   // No csfle was loaded:
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt, NULL) == NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt) == 0);
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
   // No csfle was loaded:
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt, NULL) == NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt) == 0);
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
   // csfle WAS loaded:
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt, NULL) != NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt) != 0);
   mstr_view version =
      mstrv_view_cstr (mongocrypt_csfle_version_string (crypt, NULL));
   if (TEST_MONGOCRYPT_HAVE_REAL_CSFLE) {
      MSTR_ASSERT (true, version, starts_with, mstrv_lit ("mongo_csfle_v1-"));
   } else {
      MSTR_ASSERT (true, version, eq, mstrv_lit ("stubbed-mongo_csfle"));
   }
   mongocrypt_destroy (crypt);
}

static void
_test_csfle_load_twice (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt1 = get_test_mongocrypt (tester);
   mongocrypt_setopt_append_csfle_search_path (crypt1, "$ORIGIN");
   ASSERT_OK (mongocrypt_init (crypt1), crypt1);
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt1, NULL) != NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt1) != 0);

   // Make another one:
   mongocrypt_t *const crypt2 = get_test_mongocrypt (tester);
   mongocrypt_setopt_append_csfle_search_path (crypt2, "$ORIGIN");
   ASSERT_OK (mongocrypt_init (crypt2), crypt2);
   // csfle was loaded again:
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt2, NULL) != NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt2) != 0);

   mstr_view version =
      mstrv_view_cstr (mongocrypt_csfle_version_string (crypt1, NULL));
   if (TEST_MONGOCRYPT_HAVE_REAL_CSFLE) {
      MSTR_ASSERT (true, version, starts_with, mstrv_lit ("mongo_csfle_v1-"));
   } else {
      MSTR_ASSERT (true, version, eq, mstrv_lit ("stubbed-mongo_csfle"));
   }

   version = mstrv_view_cstr (mongocrypt_csfle_version_string (crypt2, NULL));
   if (TEST_MONGOCRYPT_HAVE_REAL_CSFLE) {
      MSTR_ASSERT (true, version, starts_with, mstrv_lit ("mongo_csfle_v1-"));
   } else {
      MSTR_ASSERT (true, version, eq, mstrv_lit ("stubbed-mongo_csfle"));
   }

   mongocrypt_destroy (crypt1);
   mongocrypt_destroy (crypt2);
}

static void
_test_csfle_load_twice_fail (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt1 = get_test_mongocrypt (tester);
   mongocrypt_setopt_append_csfle_search_path (crypt1, "$ORIGIN");
   ASSERT_OK (mongocrypt_init (crypt1), crypt1);
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt1, NULL) != NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt1) != 0);

   // Make another one, but finding a different dynamic library:
   mongocrypt_t *const crypt2 = get_test_mongocrypt (tester);
   mongocrypt_setopt_set_csfle_lib_path_override (
      crypt2, "$ORIGIN/stubbed-csfle-2.dll");
   // Loading a second different library is an error:
   ASSERT_FAILS (mongocrypt_init (crypt2),
                 crypt2,
                 "attempted to load a second CSFLE library");

   mstr_view version =
      mstrv_view_cstr (mongocrypt_csfle_version_string (crypt1, NULL));
   if (TEST_MONGOCRYPT_HAVE_REAL_CSFLE) {
      MSTR_ASSERT (true, version, starts_with, mstrv_lit ("mongo_csfle_v1-"));
   } else {
      MSTR_ASSERT (true, version, eq, mstrv_lit ("stubbed-mongo_csfle"));
   }

   mongocrypt_destroy (crypt1);
   mongocrypt_destroy (crypt2);
}

static void
_test_csfle_path_override_okay (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   // Set to the absolute path to the DLL we use for testing:
   mongocrypt_setopt_set_csfle_lib_path_override (
      crypt, "$ORIGIN/mongo_csfle_v1" MCR_DLL_SUFFIX);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   // csfle WAS loaded:
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt, NULL) != NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt) != 0);
   mstr_view version =
      mstrv_view_cstr (mongocrypt_csfle_version_string (crypt, NULL));
   if (TEST_MONGOCRYPT_HAVE_REAL_CSFLE) {
      MSTR_ASSERT (true, version, starts_with, mstrv_lit ("mongo_csfle_v1-"));
   } else {
      MSTR_ASSERT (true, version, eq, mstrv_lit ("stubbed-mongo_csfle"));
   }
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
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt, NULL) == NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt) == 0);
   mongocrypt_destroy (crypt);
}

static void
_test_cur_exe_path (_mongocrypt_tester_t *tester)
{
   current_module_result self = current_module_path ();
   BSON_ASSERT (self.error == 0);
   BSON_ASSERT (self.path.len != 0);
   mstr_free (self.path);
}

static void
_test_csfle_not_loaded_with_bypassqueryanalysis (_mongocrypt_tester_t *tester) {
   mongocrypt_t *const crypt = get_test_mongocrypt (tester);
   mongocrypt_setopt_append_csfle_search_path (crypt, "$ORIGIN");
   mongocrypt_setopt_bypass_query_analysis (crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   BSON_ASSERT (mongocrypt_csfle_version_string (crypt, NULL) == NULL);
   BSON_ASSERT (mongocrypt_csfle_version (crypt) == 0);

   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_csfle_lib (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_csfle_no_paths);
   INSTALL_TEST (_test_csfle_not_found);
   INSTALL_TEST (_test_csfle_load);
   INSTALL_TEST (_test_csfle_load_twice);
   INSTALL_TEST (_test_csfle_load_twice_fail);
   INSTALL_TEST (_test_csfle_path_override_okay);
   INSTALL_TEST (_test_csfle_path_override_fail);
   INSTALL_TEST (_test_cur_exe_path);
   INSTALL_TEST (_test_csfle_not_loaded_with_bypassqueryanalysis);
}
