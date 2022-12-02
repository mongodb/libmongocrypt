#include "./int128.h"

#include <iostream>
#include <random>
#include <string_view>

// Basic checks with static_asserts, check constexpr correctness and fail fast
static_assert (mlib_int128_eq (MLIB_INT128 (0), MLIB_INT128_FROM_PARTS (0, 0)));
static_assert (mlib_int128_eq (MLIB_INT128 (4), MLIB_INT128_FROM_PARTS (4, 0)));
static_assert (mlib_int128_eq (MLIB_INT128 (34),
                               MLIB_INT128_FROM_PARTS (34, 0)));
static_assert (mlib_int128_eq (MLIB_INT128 (34 + 8),
                               MLIB_INT128_FROM_PARTS (42, 0)));
static_assert (mlib_int128_eq (MLIB_INT128_CAST (94),
                               MLIB_INT128_FROM_PARTS (94, 0)));
static_assert (mlib_int128_eq (mlib_int128_lshift (MLIB_INT128_CAST (1), 64),
                               MLIB_INT128_FROM_PARTS (0, 1)));
static_assert (mlib_int128_eq (mlib_int128_lshift (MLIB_INT128_CAST (1), 127),
                               MLIB_INT128_FROM_PARTS (0, 1ull << 63)));

static_assert (mlib_int128_scmp (MLIB_INT128_CAST (2), MLIB_INT128 (0)) > 0);
static_assert (mlib_int128_scmp (MLIB_INT128_CAST (-2), MLIB_INT128 (0)) < 0);
static_assert (mlib_int128_scmp (MLIB_INT128_CAST (0), MLIB_INT128 (0)) == 0);
// Unsigned compare doesn't believe in negative numbers:
static_assert (mlib_int128_ucmp (MLIB_INT128_CAST (-2), MLIB_INT128 (0)) > 0);

// Literals, for test convenience:
constexpr mlib_int128 operator""_i128 (const char *s)
{
   return mlib_int128_from_string (s);
}

static_assert (mlib_int128_eq (MLIB_INT128 (0), 0_i128));
static_assert (mlib_int128_eq (MLIB_INT128 (65025), 65025_i128));
static_assert (mlib_int128_eq (MLIB_INT128_FROM_PARTS (0, 1),
                               18446744073709551616_i128));
static_assert (mlib_int128_eq (MLIB_INT128_UMAX,
                               340282366920938463463374607431768211455_i128));


static_assert (mlib_int128_scmp (MLIB_INT128_SMIN, MLIB_INT128_SMAX) < 0);
static_assert (mlib_int128_scmp (MLIB_INT128_SMAX, MLIB_INT128_SMIN) > 0);
static_assert (mlib_int128_scmp (MLIB_INT128 (-12), MLIB_INT128 (0)) < 0);
static_assert (mlib_int128_scmp (MLIB_INT128 (12), MLIB_INT128 (0)) > 0);

// Simple arithmetic:
static_assert (mlib_int128_scmp (mlib_int128_add (MLIB_INT128_SMAX, 1_i128),
                                 MLIB_INT128_SMIN) == 0);
static_assert (mlib_int128_scmp (mlib_int128_negate (MLIB_INT128 (-42)),
                                 MLIB_INT128 (42)) == 0);
static_assert (mlib_int128_scmp (mlib_int128_sub (5_i128, 3_i128), 2_i128) ==
               0);
static_assert (mlib_int128_scmp (mlib_int128_sub (3_i128, 5_i128),
                                 mlib_int128_negate (2_i128)) == 0);
static_assert (mlib_int128_ucmp (mlib_int128_sub (3_i128, 5_i128),
                                 mlib_int128_sub (MLIB_INT128_UMAX, 1_i128)) ==
               0);

static_assert (mlib_int128_scmp (mlib_int128_lshift (1_i128, 127),
                                 MLIB_INT128_SMIN) == 0);

static_assert (
   mlib_int128_scmp (mlib_int128_rshift (mlib_int128_lshift (1_i128, 127), 127),
                     1_i128) == 0);


inline std::ostream &
operator<< (std::ostream &out, mlib_int128 v)
{
   out << mlib_int128_format (v).str;
   return out;
}

struct check_info {
   const char *filename;
   int line;
   const char *expr;
};

template <typename Left> struct [[nodiscard]] bound_lhs {
   check_info info;
   Left value;

#define DEFOP(Oper)                                              \
   template <typename Rhs> void operator Oper (Rhs rhs) noexcept \
   {                                                             \
      if (value Oper rhs) {                                      \
         return;                                                 \
      }                                                          \
      fprintf (stderr,                                           \
               "%s:%d: CHECK( %s ) failed!\n",                   \
               info.filename,                                    \
               info.line,                                        \
               info.expr);                                       \
      fprintf (stderr, "Expanded expression: ");                 \
      std::cerr << value << " " #Oper " " << rhs << '\n';        \
      exit (2);                                                  \
   }
   DEFOP (==)
   DEFOP (!=)
   DEFOP (<)
   DEFOP (<=)
   DEFOP (>)
   DEFOP (>=)
#undef DEFOP
};

struct check_magic {
   check_info info;

   template <typename Oper>
   bound_lhs<Oper>
   operator->*(Oper op)
   {
      return bound_lhs<Oper>{info, op};
   }
};

#undef CHECK
#define CHECK(Cond) check_magic{check_info{__FILE__, __LINE__, #Cond}}->*Cond


// Operators, for test convenience
constexpr bool
operator== (mlib_int128 l, mlib_int128 r)
{
   return mlib_int128_eq (l, r);
}

constexpr bool
operator<(mlib_int128 l, mlib_int128 r)
{
   return mlib_int128_scmp (l, r) < 0;
}
static_assert (mlib_int128 (MLIB_INT128_UMAX) ==
               340282366920938463463374607431768211455_i128);

// Check sign extension works correctly:
static_assert (mlib_int128 (MLIB_INT128_CAST (INT64_MIN)) ==
               mlib_int128_negate (9223372036854775808_i128));
static_assert (mlib_int128 (MLIB_INT128_CAST (INT64_MIN)) <
               mlib_int128_negate (9223372036854775807_i128));
static_assert (mlib_int128_negate (9223372036854775809_i128) <
               mlib_int128 (MLIB_INT128_CAST (INT64_MIN)));

// Runtime checks, easier to debug that static_asserts
int
main ()
{
   mlib_int128 zero = MLIB_INT128 (0);
   CHECK (true == mlib_int128_eq (zero, MLIB_INT128 (0)));
   CHECK (true == mlib_int128_eq (zero, 0_i128));
   CHECK (zero == mlib_int128{0});
   CHECK (zero == 0_i128);

   auto two = MLIB_INT128 (2);
   auto four = mlib_int128_add (two, two);
   CHECK (four == MLIB_INT128 (4));
   CHECK (four == 4_i128);
   CHECK (two == mlib_int128_add (two, zero));

   // Addition wraps:
   mlib_int128 max = MLIB_INT128_SMAX;
   auto more = mlib_int128_add (max, four);
   CHECK (more == mlib_int128_add (MLIB_INT128_SMIN, MLIB_INT128 (3)));

   // "Wrap" around zero:
   auto ntwo = MLIB_INT128 (-2);
   auto sum = mlib_int128_add (ntwo, four);
   CHECK (sum == two);

   auto eight = mlib_int128_lshift (two, 2);
   CHECK (eight == MLIB_INT128 (8));

   auto big = mlib_int128_lshift (two, 72);
   CHECK (mlib_int128_scmp (big, MLIB_INT128 (0)) > 0);

   auto four_v2 = mlib_int128_lshift (eight, -1);
   CHECK (four == four_v2);

   auto r = mlib_int128_divmod (27828649044156246570177174673037165454_i128,
                                499242349997913298655486252455941907_i128);

   CHECK (r.quotient == 55_i128);
   CHECK (r.remainder == 370319794271015144125430787960360569_i128);

   // Self-divide:
   r = mlib_int128_divmod (628698094597401606590302208_i128,
                           628698094597401606590302208_i128);
   CHECK (r.quotient == 1_i128);
   CHECK (r.remainder == 0_i128);

   // With no high-32 bits in the denominator
   r = mlib_int128_divmod (316356263640858117670580590964547584140_i128,
                           13463362962560749016052695684_i128);
   CHECK (r.quotient == 23497566285_i128);

   // Remainder correctness with high bit set:
   auto rem = mlib_int128_mod (292590981272581782572061492191999425232_i128,
                               221673222198185508195462959065350495048_i128);
   CHECK (rem == 70917759074396274376598533126648930184_i128);

   // Remainder with 64bit denom:
   rem = mlib_int128_mod (2795722437127403543495742528_i128, 708945413_i128);
   CHECK (rem == 619266642_i128);

   // 10-div:
   CHECK (mlib_int128_div (MLIB_INT128_SMAX, 10_i128) ==
          17014118346046923173168730371588410572_i128);

   int8_t n = -12;
   CHECK (mlib_int128_scmp (zero, MLIB_INT128_CAST (n)) > 0);
   CHECK (mlib_int128_ucmp (zero, MLIB_INT128_CAST (n)) < 0);

   auto _2pow127 = mlib_int128_pow2 (127);
   CHECK (std::string (mlib_int128_format (_2pow127).str) ==
          "170141183460469231731687303715884105728");

   for (int i = 0; i < 1'000'000; ++i) {
      std::uniform_int_distribution<std::uint64_t> dist;
      std::random_device r;
      auto bits = r ();
      mlib_int128 num = MLIB_INT128_FROM_PARTS (bits & 0b0001 * dist (r),
                                                bits & 0b0010 * dist (r));
      mlib_int128 denom = MLIB_INT128_FROM_PARTS (bits & 0b0100 * dist (r),
                                                  bits & 0b1000 * dist (r));
      if (mlib_int128_eq (denom, 0_i128)) {
         continue;
      }

      // Attempt a division, even if we have no "reference" value
      auto q = mlib_int128_divmod (num, denom);
      (void) q;
#ifdef __SIZEOF_INT128__
      std::cerr << "Testing: " << num << " ÷ " << denom << '\n';
      // When we have an existing i128 impl, test against that:
      mlib_int128 exp = {.unsigned_ = (num.unsigned_ / denom.unsigned_)};
      mlib_int128 exp2 = {.unsigned_ = (num.unsigned_ % denom.unsigned_)};
      CHECK (q.quotient == exp);
      CHECK (q.remainder == exp2);
#endif
   }
}
