#include "./charconv.h"

#define CHECK(Expr)                                   \
   ((Expr) ? 0                                        \
           : ((fprintf (stderr,                       \
                        "%s:%d: Check '%s' failed\n", \
                        __FILE__,                     \
                        __LINE__,                     \
                        #Expr),                       \
               abort ()),                             \
              0))

struct test_case {
   const char *given;
   int base;
   int64_t expect_value;
   int expect_error;
   int expect_n_parsed;
};

static void
check_conv_ (struct test_case t)
{
   printf ("Test parse '%s'\n", t.given);
   mstr_view str = mstrv_view_cstr (t.given);
   int64_t value = 0;
   mlib_conv_result res = mlib_i64_from_chars (&value, str, t.base);
   int64_t n_parsed = res.ptr - str.data;
   CHECK (res.ec == t.expect_error);
   CHECK (value == t.expect_value);
   if (res.ec == 0) {
      CHECK (n_parsed == str.len);
   } else {
      CHECK (n_parsed == t.expect_n_parsed);
   }
}

#define check_conv(...) (check_conv_ ((struct test_case) __VA_ARGS__))

int
main ()
{
   check_conv ({.given = "0", .base = 10, .expect_value = 0});
   check_conv ({.given = "10", .base = 10, .expect_value = 10});
   check_conv ({.given = "123", .base = 10, .expect_value = 123});
   check_conv ({.given = "-123", .base = 10, .expect_value = -123});
   check_conv ({.given = "badf00d", .base = 16, .expect_value = 0xbadf00d});
   check_conv ({.given = "9223372036854775807",
                .base = 10,
                .expect_value = UINT64_C (9223372036854775807)});
   check_conv ({.given = "9223372036854775808",
                .base = 10,
                .expect_error = ERANGE,
                .expect_n_parsed = 18});
   check_conv (
      {.given = "-9223372036854775808", .base = 10, .expect_value = INT64_MIN});
   check_conv ({.given = "-9223372036854775809",
                .base = 10,
                .expect_error = ERANGE,
                .expect_n_parsed = 19});
}