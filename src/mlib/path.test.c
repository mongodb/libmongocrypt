#include "./path.h"

int
main ()
{
   mstr s = mstr_copy_cstr ("/foo/bar/baz.txt");
   MSTR_ASSERT_EQ (mpath_parent (s.view), mstrv_lit ("/foo/bar"));
   MSTR_ASSERT_EQ (mpath_parent (mpath_parent (s.view)), mstrv_lit ("/foo"));

   mstr_assign (&s, mpath_join (mpath_parent (s.view), mstrv_lit ("quux.pdf")));
#if _WIN32
   MSTR_ASSERT_EQ (s.view, mstrv_lit ("/foo/bar\\quux.pdf"));
#else
   MSTR_ASSERT_EQ (s.view, mstrv_lit ("/foo/bar/quux.pdf"));
#endif
   mstr_free (s);

   mpath_current_exe_result self = mpath_current_exe_path ();
   assert (self.error == 0);
   assert (self.path.len != 0);
   mstr_free (self.path);
}