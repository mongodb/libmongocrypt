#include "mongocrypt.h"

#include "mongocrypt-dll-private.h"
#include <mlib/path.h>

#include "test-mongocrypt.h"

static void
_test_load_simple_library (_mongocrypt_tester_t *t)
{
   (void) t;
   mstr self_path = mpath_current_exe_path ();

   mstr dll_path = mpath_join (mpath_parent (self_path.view),
                               mstrv_view_cstr ("test-dll.dll"));

   _mcr_dll lib = _mcr_dll_open (dll_path.data);
   BSON_ASSERT (_mcr_dll_error (lib) == NULL);

   int (*say_hello) (void) = _mcr_dll_sym (lib, "say_hello");
   BSON_ASSERT (say_hello != NULL);

   int rval = say_hello ();
   ASSERT_CMPINT (rval, ==, 42);

   _mcr_dll_close (lib);
   mstr_free (self_path);
   mstr_free (dll_path);
}

void
_mongocrypt_tester_install_dll (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_load_simple_library);
}
