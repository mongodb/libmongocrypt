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

#define TEST_DECOMP(Part, Given, Expect)                   \
   MSTR_ASSERT_EQ (mpath_##Part (mstrv_view_cstr (Given)), \
                   mstrv_view_cstr (Expect))

static void
test_make_absolute (const char *part, const char *base, const char *expect)
{
   mstr result =
      mpath_absolute_from (mstrv_view_cstr (part), mstrv_view_cstr (base));
   MSTR_ASSERT_EQ (result.view, mstrv_view_cstr (expect));
   mstr_free (result);
}

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

   TEST_DECOMP (parent, "/foo", "/");
   TEST_DECOMP (parent, "/foo/", "/foo");
   TEST_DECOMP (parent, "foo/", "foo");
   TEST_DECOMP (parent, ".", "");
   TEST_DECOMP (parent, "..", "");
   TEST_DECOMP (parent, "foo", "");
   TEST_DECOMP (parent, "/", "");
   TEST_DECOMP (parent, "foo/bar", "foo");
   TEST_DECOMP (parent, "/foo/bar", "/foo");
   TEST_DECOMP (parent, "///foo///bar", "///foo");
   TEST_DECOMP (parent, "/.", "/");

   TEST_DECOMP (filename, "foo.exe", "foo.exe");
   TEST_DECOMP (filename, "/foo.exe", "foo.exe");
   TEST_DECOMP (filename, "/", ".");
   TEST_DECOMP (filename, "/foo", "foo");
   TEST_DECOMP (filename, "/foo/", ".");
   TEST_DECOMP (filename, "/foo/..", "..");
   TEST_DECOMP (filename, "/foo/.", ".");
   TEST_DECOMP (filename, "", "");

   TEST_DECOMP (relative_path, "", "");
   TEST_DECOMP (relative_path, ".", ".");
   TEST_DECOMP (relative_path, "..", "..");
   TEST_DECOMP (relative_path, "foo", "foo");
   TEST_DECOMP (relative_path, "/", "");

   test_make_absolute ("foo", "/bar", "/bar/foo");
   test_make_absolute ("baz.txt", "/bar/foo/", "/bar/foo/baz.txt");

   mstr_free (s);
}