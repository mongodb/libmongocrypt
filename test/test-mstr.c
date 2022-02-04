#include "test-mongocrypt.h"

#include "mlib-str-private.h"

static void
_test_mstr (_mongocrypt_tester_t *t)
{
   (void) t;
   mstr str = mstr_copy_cstr ("foo");
   ASSERT_CMPINT (str.len, ==, 3);
   MSTR_ASSERT_EQ (str.view, mstrv_lit ("foo"));
   BSON_ASSERT (strncmp (str.data, "foo", 3) == 0);

   mstr_inplace_append (&str, mstrv_lit ("bar"));
   MSTR_ASSERT_EQ (str.view, mstrv_lit ("foobar"));

   mstr_free (str);

   str = mstr_copy_cstr ("foobar");
   mstr_inplace_trunc (&str, 3);
   MSTR_ASSERT_EQ (str.view, mstrv_lit ("foo"));
   mstr_free (str);

   int pos = mstrv_find (mstrv_lit ("foo"), mstrv_lit ("bar"));
   ASSERT_CMPINT (pos, ==, -1);

   pos = mstrv_find (mstrv_lit ("foo"), mstrv_lit ("barbaz"));
   ASSERT_CMPINT (pos, ==, -1);

   pos = mstrv_find (mstrv_lit ("foobar"), mstrv_lit ("bar"));
   ASSERT_CMPINT (pos, ==, 3);
}

void
_mongocrypt_tester_install_mstr (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_mstr);
}
