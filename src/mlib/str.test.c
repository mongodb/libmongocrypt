#include "./str.h"

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
   mstr str = mstr_copy_cstr ("foo");
   CHECK (str.len == 3);
   MSTR_ASSERT_EQ (str.view, mstrv_lit ("foo"));
   CHECK (strncmp (str.data, "foo", 3) == 0);

   mstr_inplace_append (&str, mstrv_lit ("bar"));
   MSTR_ASSERT_EQ (str.view, mstrv_lit ("foobar"));

   mstr_free (str);

   str = mstr_copy_cstr ("foobar");
   mstr_inplace_trunc (&str, 3);
   MSTR_ASSERT_EQ (str.view, mstrv_lit ("foo"));
   mstr_free (str);

   int pos = mstr_find (mstrv_lit ("foo"), mstrv_lit ("bar"));
   CHECK (pos == -1);

   pos = mstr_find (mstrv_lit ("foo"), mstrv_lit ("barbaz"));
   CHECK (pos == -1);

   pos = mstr_find (mstrv_lit ("foobar"), mstrv_lit ("bar"));
   CHECK (pos == 3);

   // Simple replacement:
   str = mstr_copy_cstr ("foo bar baz");
   mstr str2 = mstr_replace (str.view, mstrv_lit ("bar"), mstrv_lit ("foo"));
   MSTR_ASSERT_EQ (str2.view, mstrv_lit ("foo foo baz"));
   mstr_free (str);

   // Replace multiple instances:
   mstr_inplace_replace (&str2, mstrv_lit ("foo"), mstrv_lit ("baz"));
   MSTR_ASSERT_EQ (str2.view, mstrv_lit ("baz baz baz"));

   // Replace with a string containing the needle:
   mstr_inplace_replace (&str2, mstrv_lit ("baz"), mstrv_lit ("foo bar baz"));
   MSTR_ASSERT_EQ (str2.view,
                   mstrv_lit ("foo bar baz foo bar baz foo bar baz"));

   // Replace with empty string:
   mstr_inplace_replace (&str2, mstrv_lit ("bar "), mstrv_lit (""));
   MSTR_ASSERT_EQ (str2.view, mstrv_lit ("foo baz foo baz foo baz"));

   // Replacing a string that isn't there:
   mstr_inplace_replace (&str2, mstrv_lit ("quux"), mstrv_lit ("nope"));
   MSTR_ASSERT_EQ (str2.view, mstrv_lit ("foo baz foo baz foo baz"));

   // Replacing an empty string is just a duplication:
   mstr_inplace_replace (&str2, mstrv_lit (""), mstrv_lit ("never"));
   MSTR_ASSERT_EQ (str2.view, mstrv_lit ("foo baz foo baz foo baz"));

   mstr_free (str2);

   CHECK (mstrv_view_cstr ("foo\000bar").len == 3);
   CHECK (mstrv_lit ("foo\000bar").len == 7);
}
