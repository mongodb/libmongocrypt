#ifndef MC_DEC128_H_INCLUDED
#define MC_DEC128_H_INCLUDED

#include <inttypes.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mc_dec128_rounding_mode {
   MC_DEC128_ROUND_NEAREST_EVEN = 0,
   MC_DEC128_ROUND_DOWNWARD = 1,
   MC_DEC128_ROUND_UPWARD = 2,
   MC_DEC128_ROUND_TOWARD_ZERO = 3,
   MC_DEC128_ROUND_NEAREST_AWAY = 4,
   MC_DEC128_ROUND_DEFAULT = MC_DEC128_ROUND_NEAREST_EVEN,
} mc_dec128_rounding_mode;

typedef enum mc_dec128_flags {
   MC_DEC128_FLAG_INVALID = 0x1,
   MC_DEC128_FLAG_ZERODIV = 0x4,
   MC_DEC128_FLAG_OVERFLOW = 0x8,
   MC_DEC128_FLAG_UNDERFLOW = 0x10,
   MC_DEC128_FLAG_INEXACT = 0x20,
   MC_DEC128_FLAG_NONE = 0,
} mc_dec128_flags;

typedef struct mc_dec128_flagset {
   int bits;
} mc_dec128_flagset;

// This alignment conditional is the same conditions used in Intel's DFP library
#if defined _MSC_VER
#if defined _M_IX86 && !defined __INTEL_COMPILER
#define _mcDec128Align(n)
#else
#define _mcDec128Align(n) __declspec(align (n))
#endif
#else
#if !defined HPUX_OS
#define _mcDec128Align(n) __attribute__ ((aligned (n)))
#else
#define _mcDec128Align(n)
#endif
#endif

typedef struct _mcDec128Align (16) mc_dec128
{
   uint8_t _bid_bytes[16];
}
mc_dec128;

/// Expands to a dec128 constant value.
#ifdef __cplusplus
#define MC_DEC128_C(N) \
   mc_dec128 _mcDec128Const (((N) < 0 ? -(N) : (N)), ((N) < 0 ? 1 : 0))
#else
#define MC_DEC128_C(N) \
   _mcDec128Const (((N) < 0 ? -(N) : (N)), ((N) < 0 ? 1 : 0))
#endif

#define _mcDec128Const(N, Negate)                                   \
   {                                                                \
      {                                                             \
         (((uint64_t) N) & 0xff),                                   \
         (((uint64_t) N) >> 8 & 0xff),                              \
         (((uint64_t) N) >> 16 & 0xff),                             \
         (((uint64_t) N) >> 24 & 0xff),                             \
         (((uint64_t) N) >> 32 & 0xff),                             \
         (((uint64_t) N) >> 40 & 0xff),                             \
         (((uint64_t) N) >> 48 & 0xff),                             \
         (((uint64_t) N) >> 56 & 0xff),                             \
         0,                                                         \
         0,                                                         \
         0,                                                         \
         0,                                                         \
         0,                                                         \
         0,                                                         \
         1 << 6 /* 0b0010'0000 */,                                  \
         (1 << 5 | 1 << 4) | /* Set the sign bit: */ (Negate << 7), \
      },                                                            \
   }

static const mc_dec128 MC_DEC128_ZERO = MC_DEC128_C (0);
static const mc_dec128 MC_DEC128_ONE = MC_DEC128_C (1);
static const mc_dec128 MC_DEC128_MINUSONE = MC_DEC128_C (-1);

typedef struct mc_dec128_string {
   char str[48];
} mc_dec128_string;

/// Convert a double-precision binary floating point into a dec128
static inline mc_dec128
mc_dec128_from_double (double d)
{
   extern mc_dec128 __mongocrypt_binary64_to_bid128 (
      double d, mc_dec128_rounding_mode, mc_dec128_flagset *);
   mc_dec128_flagset zero_flags = {0};
   return __mongocrypt_binary64_to_bid128 (
      d, MC_DEC128_ROUND_DEFAULT, &zero_flags);
}

/// Parse a decimal string into a dec128
static inline mc_dec128
mc_dec128_from_string (const char *s)
{
   extern mc_dec128 __mongocrypt_bid128_from_string (
      const char *, mc_dec128_rounding_mode, mc_dec128_flagset *);
   mc_dec128_flagset flags = {0};
   return __mongocrypt_bid128_from_string (s, MC_DEC128_ROUND_DEFAULT, &flags);
}

/// Render a dec128 as an engineering-notation string.
static inline mc_dec128_string
mc_dec128_to_string (mc_dec128 d)
{
   extern void __mongocrypt_bid128_to_string (
      char *, mc_dec128 d, mc_dec128_flagset *);
   mc_dec128_flagset flags = {0};
   mc_dec128_string out = {{0}};
   __mongocrypt_bid128_to_string (out.str, d, &flags);
   return out;
}

/// Compare two dec128 numbers
#define DECL_IDF_COMPARE_1(Oper)                                               \
   static inline bool mc_dec128_##Oper (mc_dec128 left, mc_dec128 right)       \
   {                                                                           \
      extern int __mongocrypt_bid128_quiet_##Oper (                            \
         mc_dec128 left, mc_dec128 right, mc_dec128_flagset *);                \
      mc_dec128_flagset zero_flags = {0};                                      \
      return 0 != __mongocrypt_bid128_quiet_##Oper (left, right, &zero_flags); \
   }

#define DECL_IDF_COMPARE(Op) \
   DECL_IDF_COMPARE_1 (Op)   \
   DECL_IDF_COMPARE_1 (not_##Op)

DECL_IDF_COMPARE (equal)
DECL_IDF_COMPARE (greater)
DECL_IDF_COMPARE (greater_equal)
DECL_IDF_COMPARE (less)
DECL_IDF_COMPARE (less_equal)

#undef DECL_IDF_COMPARE
#undef DECL_IDF_COMPARE_1

/// Test properties of Decimal128 numbers
#define DECL_PREDICATE(Name, BIDName)                         \
   static inline bool mc_dec128_##Name (mc_dec128 d)          \
   {                                                          \
      extern int __mongocrypt_bid128_##BIDName (mc_dec128 d); \
      return 0 != __mongocrypt_bid128_##BIDName (d);          \
   }

DECL_PREDICATE (is_zero, isZero)
DECL_PREDICATE (is_negative, isSigned)
DECL_PREDICATE (is_inf, isInf)
DECL_PREDICATE (is_finite, isFinite)
DECL_PREDICATE (is_nan, isNaN)

#undef DECL_PREDICATE

/// Binary arithmetic operations on two Decimal128 numbers
#define DECL_IDF_BINOP_WRAPPER(Oper)                                          \
   static inline mc_dec128 mc_dec128_##Oper##_ex (                            \
      mc_dec128 left,                                                         \
      mc_dec128 right,                                                        \
      mc_dec128_rounding_mode mode,                                           \
      mc_dec128_flagset *flags)                                               \
   {                                                                          \
      extern mc_dec128 __mongocrypt_bid128_##Oper (                           \
         mc_dec128 left,                                                      \
         mc_dec128 right,                                                     \
         mc_dec128_rounding_mode rounding,                                    \
         mc_dec128_flagset *flags);                                           \
      mc_dec128_flagset zero_flags = {0};                                     \
      return __mongocrypt_bid128_##Oper (                                     \
         left, right, mode, flags ? flags : &zero_flags);                     \
   }                                                                          \
                                                                              \
   static inline mc_dec128 mc_dec128_##Oper (mc_dec128 left, mc_dec128 right) \
   {                                                                          \
      return mc_dec128_##Oper##_ex (                                          \
         left, right, MC_DEC128_ROUND_DEFAULT, NULL);                         \
   }

DECL_IDF_BINOP_WRAPPER (add)
DECL_IDF_BINOP_WRAPPER (mul)
DECL_IDF_BINOP_WRAPPER (div)
DECL_IDF_BINOP_WRAPPER (sub)

#undef DECL_IDF_BINOP_WRAPPER

#define DECL_IDF_UNOP_WRAPPER(Oper)                                         \
   static inline mc_dec128 mc_dec128_##Oper##_ex (mc_dec128 operand,        \
                                                  mc_dec128_flagset *flags) \
   {                                                                        \
      extern mc_dec128 __mongocrypt_bid128_##Oper (                         \
         mc_dec128 v, mc_dec128_rounding_mode, mc_dec128_flagset *);        \
      mc_dec128_flagset zero_flags = {0};                                   \
      return __mongocrypt_bid128_##Oper (                                   \
         operand, MC_DEC128_ROUND_DEFAULT, flags ? flags : &zero_flags);    \
   }                                                                        \
                                                                            \
   static inline mc_dec128 mc_dec128_##Oper (mc_dec128 operand)             \
   {                                                                        \
      return mc_dec128_##Oper##_ex (operand, NULL);                         \
   }

DECL_IDF_UNOP_WRAPPER (floor)
DECL_IDF_UNOP_WRAPPER (log10)
DECL_IDF_UNOP_WRAPPER (negate)
DECL_IDF_UNOP_WRAPPER (abs)
#undef DECL_IDF_UNOP_WRAPPER

/**
 * @brief Scale the given Decimal128 by a power of ten
 *
 * @param fac The value being scaled
 * @param exp The exponent: 10^exp is the scale factor
 * @param rounding Rounding behavior
 * @param flags Control/result flags
 * @return mc_dec128 The product
 */
static inline mc_dec128
mc_dec128_scale_ex (mc_dec128 fac,
                    long int exp,
                    mc_dec128_rounding_mode rounding,
                    mc_dec128_flagset *flags)
{
   extern mc_dec128 __mongocrypt_bid128_scalbln (
      mc_dec128 fac, long int, mc_dec128_rounding_mode, mc_dec128_flagset *);
   mc_dec128_flagset zero_flags = {0};
   return __mongocrypt_bid128_scalbln (
      fac, exp, rounding, flags ? flags : &zero_flags);
}

/**
 * @brief Scale the given Decimal128 by a power of ten
 *
 * @param fac The value being scaled
 * @param exp The exponent: 10^exp is the scale factor
 * @return mc_dec128 The product
 */
static inline mc_dec128
mc_dec128_scale (mc_dec128 fac, long int exp)
{
   return mc_dec128_scale_ex (fac, exp, MC_DEC128_ROUND_DEFAULT, NULL);
}

/// The result of a dec_128 modf operation
typedef struct mc_dec128_modf_result {
   /// The whole part of the result
   mc_dec128 whole;
   /// The fractional part of the result
   mc_dec128 frac;
} mc_dec128_modf_result;

static inline mc_dec128_modf_result
mc_dec128_modf_ex (mc_dec128 d, mc_dec128_flagset *flags)
{
   extern mc_dec128 __mongocrypt_bid128_modf (
      mc_dec128 d, mc_dec128 * iptr, mc_dec128_flagset *);
   mc_dec128_flagset zero_flags = {0};
   mc_dec128_modf_result res;
   res.frac =
      __mongocrypt_bid128_modf (d, &res.whole, flags ? flags : &zero_flags);
   return res;
}

static inline mc_dec128_modf_result
mc_dec128_modf (mc_dec128 d)
{
   return mc_dec128_modf_ex (d, NULL);
}

static inline mc_dec128
mc_dec128_rem_ex (mc_dec128 numer, mc_dec128 denom, mc_dec128_flagset *flags)
{
   extern mc_dec128 __mongocrypt_bid128_fmod (
      mc_dec128 numer, mc_dec128 denom, mc_dec128_flagset *);
   mc_dec128_flagset zero_flags = {0};
   return __mongocrypt_bid128_fmod (numer, denom, flags ? flags : &zero_flags);
}

static inline mc_dec128
mc_dec128_rem (mc_dec128 numer, mc_dec128 denom)
{
   return mc_dec128_rem_ex (numer, denom, NULL);
}

static inline int64_t
mc_dec128_to_int64_ex (mc_dec128 d, mc_dec128_flagset *flags)
{
   extern int64_t __mongocrypt_bid128_to_int64_int (mc_dec128 d,
                                                    mc_dec128_flagset *);
   mc_dec128_flagset zero_flags = {0};
   return __mongocrypt_bid128_to_int64_int (d, flags ? flags : &zero_flags);
}

static inline int64_t
mc_dec128_to_int64 (mc_dec128 d)
{
   return mc_dec128_to_int64_ex (d, NULL);
}

/// Create a decimal string from a dec128 number. The result must be freed.
static inline char *
mc_dec128_to_new_decimal_string (mc_dec128 d)
{
   if (mc_dec128_is_zero (d)) {
      // Just return "0"
      char *s = (char *) calloc (2, 1);
      s[0] = '0';
      return s;
   }

   if (mc_dec128_is_negative (d)) {
      // Negate the result, return a string with a '-' prefix
      d = mc_dec128_negate (d);
      char *s = mc_dec128_to_new_decimal_string (d);
      char *s1 = (char *) calloc (strlen (s) + 2, 1);
      s1[0] = '-';
      strcpy (s1 + 1, s);
      free (s);
      return s1;
   }

   if (mc_dec128_is_inf (d) || mc_dec128_is_nan (d)) {
      const char *r = mc_dec128_is_inf (d) ? "Infinity" : "NaN";
      char *c = (char *) calloc (strlen (r) + 1, 1);
      strcpy (c, r);
      return c;
   }

   const char DIGITS[] = "0123456789";
   const mc_dec128 TEN = MC_DEC128_C (10);

   // Format the whole and fractional part separately.
   mc_dec128_modf_result modf = mc_dec128_modf (d);

   if (mc_dec128_is_zero (modf.frac)) {
      // This is a non-zero integer
      // Allocate enough digits:
      mc_dec128 log10 = mc_dec128_modf (mc_dec128_log10 (d)).whole;
      int64_t ndigits = mc_dec128_to_int64 (log10) + 1;
      // +1 for null
      char *strbuf = (char *) calloc ((size_t) (ndigits + 1), 1);
      // Write the string backwards:
      char *optr = strbuf + ndigits - 1;
      while (!mc_dec128_is_zero (modf.whole)) {
         mc_dec128 rem = mc_dec128_rem (modf.whole, TEN);
         int64_t remi = mc_dec128_to_int64 (rem);
         if (remi < 0) {
            remi = 10 + remi;
         }
         *optr-- = DIGITS[remi];
         // Divide ten
         modf = mc_dec128_modf (mc_dec128_div (modf.whole, TEN));
      }
      return strbuf;
   } else if (mc_dec128_is_zero (modf.whole)) {
      // This is only a fraction (less than one, but more than zero)
      while (!mc_dec128_is_zero (mc_dec128_modf (d).frac)) {
         d = mc_dec128_mul (d, TEN);
      }
      // 'd' is now a whole number
      char *part = mc_dec128_to_new_decimal_string (d);
      char *buf = (char *) calloc (strlen (part) + 3, 1);
      buf[0] = '0';
      buf[1] = '.';
      strcpy (buf + 2, part);
      free (part);
      return buf;
   } else {
      // We have both a whole part and a fractional part
      char *whole = mc_dec128_to_new_decimal_string (modf.whole);
      char *frac = mc_dec128_to_new_decimal_string (modf.frac);
      char *ret = (char *) calloc (strlen (whole) + strlen (frac) + 1, 1);
      char *out = ret;
      strcpy (out, whole);
      out += strlen (whole);
      // "frac" contains a leading zero, which we don't want
      strcpy (out, frac + 1);
      free (whole);
      free (frac);
      return ret;
   }
}

#ifdef __cplusplus
} // extern "C"
#endif

#undef _mcDec128Align

#endif // MC_DEC128_H_INCLUDED
