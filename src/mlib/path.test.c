#include "./path.h"

#define CHECK(Expr)                                   \
   ((Expr) ? 0                                        \
           : ((fprintf (stderr,                       \
                        "%s:%d: Check '%s' failed\n", \
                        __FILE__,                     \
                        __LINE__,                     \
                        #Expr),                       \
               abort ()),                             \
              0))
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
}