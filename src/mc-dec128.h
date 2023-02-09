#ifndef MC_DEC128_H_INCLUDED
#define MC_DEC128_H_INCLUDED

// Required macros to enable certain libdfp features
#ifndef __STDC_WANT_DEC_FP__
#define __STDC_WANT_DEC_FP__ 1
#endif
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
#define __STDC_WANT_IEC_60559_DFP_EXT__ 1
#endif

// If libdfp is available, these will be intercepted by libdfp:
#include <math.h>
#include <fenv.h>
#include <stdlib.h>


#ifdef _DFP_MATH_H
// We included libdfp's math.h
#define MC_HAVE_LIBDFP 1
#define MC_IF_LIBDFP(...) __VA_ARGS__
#define MC_IF_IntelDFP(...)
#else
// No libdfp. Search for IntelDFP:
#define MC_HAVE_LIBDFP 0
#define MC_IF_LIBDFP(...)
#define MC_IF_IntelDFP(...) __VA_ARGS__
// Include the header that declares the DFP functions, which may be macros that
// expand to renamed symbols:
#include <bid_conf.h>
#include <bid_functions.h>
#endif

#include <bson/bson.h>

#include <mlib/macros.h>
#include <mlib/int128.h>
#include <mlib/endian.h>

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <float.h>

MLIB_C_LINKAGE_BEGIN

/// Rounding controls for Decimal128 operations
typedef enum mc_dec128_rounding_mode {
   MC_DEC128_ROUND_NEAREST_EVEN = 0,
   MC_DEC128_ROUND_DOWNWARD = 1,
   MC_DEC128_ROUND_UPWARD = 2,
   MC_DEC128_ROUND_TOWARD_ZERO = 3,
   MC_DEC128_ROUND_NEAREST_AWAY = 4,
   MC_DEC128_ROUND_DEFAULT = MC_DEC128_ROUND_NEAREST_EVEN,
} mc_dec128_rounding_mode;

typedef struct mc_dec128_flagset {
   MC_IF_IntelDFP (_IDEC_flags bits);
   MC_IF_LIBDFP (int bits);
} mc_dec128_flagset;

// This alignment conditional is the same conditions used in Intel's DFP
// library, ensuring we match the ABI of the library without pulling the header
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

MC_IF_LIBDFP (typedef _Decimal128 _mc_dec128_underlying);
MC_IF_IntelDFP (typedef BID_UINT128 _mc_dec128_underlying);

typedef union _mcDec128Align (16)
{
   uint64_t _words[2];
   _mc_dec128_underlying _underlying;
#if !defined(__INTELLISENSE__) && defined(__GNUC__) && defined(__amd64) && \
   !defined(__APPLE__) && !defined(__clang__)
   // If supported by the compiler, emit a field that can be used to visualize
   // the value in a debugger.
   float value_ __attribute__ ((mode (TD)));
#endif
}
mc_dec128;

#undef _mcDec128Align

/// Expands to a dec128 constant value.
#ifdef __cplusplus
#define MC_DEC128_C(N) \
   mc_dec128 _mcDec128Const (((N) < 0 ? -(N) : (N)), ((N) < 0 ? 1 : 0))
#else
#define MC_DEC128_C(N) \
   _mcDec128Const (((N) < 0 ? -(N) : (N)), ((N) < 0 ? 1 : 0))
#endif

#define MC_DEC128(N) MLIB_INIT (mc_dec128) MC_DEC128_C (N)

#define _mcDec128Combination(Bits) ((uint64_t) (Bits) << (47))
#define _mcDec128ZeroExpCombo _mcDec128Combination (1 << 7 | 1 << 13 | 1 << 14)
#define _mcDec128Const(N, Negate) \
   _mcDec128ConstFromParts (      \
      N, (_mcDec128ZeroExpCombo | ((uint64_t) (Negate) << 63)))
#define _mcDec128ConstFromParts(CoeffLow, HighWord)     \
   {                                                    \
      {                                                 \
         MLIB_IS_LITTLE_ENDIAN ? (uint64_t) (CoeffLow)  \
                               : (uint64_t) (HighWord), \
         MLIB_IS_LITTLE_ENDIAN ? (uint64_t) (HighWord)  \
                               : (uint64_t) (CoeffLow), \
      },                                                \
   }

static const mc_dec128 MC_DEC128_ZERO = MC_DEC128_C (0);
static const mc_dec128 MC_DEC128_ONE = MC_DEC128_C (1);
static const mc_dec128 MC_DEC128_MINUSONE = MC_DEC128_C (-1);

/// The greatest-magnitude finite negative value representable in a Decimal128
#define MC_DEC128_LARGEST_NEGATIVE \
   mc_dec128_from_string ("-9999999999999999999999999999999999E6111")
/// The least-magnitude non-zero negative value representable in a Decimal128
#define MC_DEC128_SMALLEST_NEGATIVE mc_dec128_from_string ("-1E-6176")
/// The greatest-magnitude finite positive value representable in a Decimal128
#define MC_DEC128_LARGEST_POSITIVE \
   mc_dec128_from_string ("9999999999999999999999999999999999E6111")
/// The least-magnitude non-zero positive value representable in a Decimal128
#define MC_DEC128_SMALLEST_POSITIVE mc_dec128_from_string ("1E-6176")
/// The normalized zero of Decimal128
#define MC_DEC128_NORMALIZED_ZERO MC_DEC128_C (0)
/// A zero of Decimal128 with the least exponent
#define MC_DEC128_NEGATIVE_EXPONENT_ZERO mc_dec128_from_string ("0E-6176")
#define _mcDec128InfCombo \
   _mcDec128Combination (1 << 15 | 1 << 14 | 1 << 13 | 1 << 12)
#define _mcDec128QuietNaNCombo \
   _mcDec128Combination (1 << 15 | 1 << 14 | 1 << 13 | 1 << 12 | 1 << 11)

/// Positive infinity of Decimal128
#define MC_DEC128_POSITIVE_INFINITY \
   _mcDec128ConstFromParts (0, _mcDec128InfCombo)
/// Negative infinity of Decimal128
#define MC_DEC128_NEGATIVE_INFINITY \
   _mcDec128ConstFromParts (0, _mcDec128InfCombo | 1ull << 63)
/// Positve quiet NaN of Decimal128
#define MC_DEC128_POSITIVE_NAN \
   _mcDec128ConstFromParts (0, _mcDec128QuietNaNCombo)
/// Negative quiet NaN of Decimal128
#define MC_DEC128_NEGATIVE_NAN \
   _mcDec128ConstFromParts (0, _mcDec128QuietNaNCombo | 1ull << 63)

/// Convert an mc_dec128 value to the DFP library's type
static inline _mc_dec128_underlying
_mc_to_dfp (mc_dec128 d)
{
   _mc_dec128_underlying r;
   memcpy (&r, &d, sizeof d);
   return r;
}

/// Convert the DFP library's type to a mc_dec128 value
static inline mc_dec128
_dfp_to_mc (_mc_dec128_underlying d)
{
   mc_dec128 r;
   memcpy (&r, &d, sizeof d);
   return r;
}

#if MC_HAVE_LIBDFP
// Store a floating-point environment, and the rounding mode.
struct _mc_fenv {
   fenv_t fenv;
   int rnd;
};

// Save the current floating-point environment and set the rounding mode
static inline int
_mc_push_fenv (int rnd, struct _mc_fenv *env)
{
   // Suspent the fenv:
   int err = feholdexcept (&env->fenv);
   assert (!err && "Error while holding floating-point environment");
   // Save the rounding mode:
   env->rnd = fe_dec_getround ();
   // swap the rounding mode:
   switch (rnd) {
   case MC_DEC128_ROUND_TOWARD_ZERO:
      err = fe_dec_setround (FE_DEC_TOWARDZERO);
      break;
   case MC_DEC128_ROUND_NEAREST_AWAY:
      err = fe_dec_setround (FE_DEC_TONEARESTFROMZERO);
      break;
   case MC_DEC128_ROUND_NEAREST_EVEN:
      err = fe_dec_setround (FE_DEC_TONEAREST);
      break;
   case MC_DEC128_ROUND_DOWNWARD:
      err = fe_dec_setround (FE_DEC_DOWNWARD);
      break;
   case MC_DEC128_ROUND_UPWARD:
      err = fe_dec_setround (FE_DEC_UPWARD);
      break;
   default:
      // No constant set, so do nothing.
      break;
   }
   assert (!err && "Error while reading floating-point rounding mode");
   (void) err;
   return 1;
}

// Restore the previously saved mode and environment:
static inline void
_mc_pop_fenv (struct _mc_fenv *env, mc_dec128_flagset *flags)
{
   // Get current exceptions:
   fexcept_t exc;
   int err = fegetexceptflag (&exc, FE_ALL_EXCEPT);
   assert (!err && "Error while reading floating-point exceptions");
   if (flags) {
      // Caller wants them:
      flags->bits = (int) exc;
   } else {
      // Caller doesn't want to check them, so fire a signal if applicable:
      if (exc & (FE_DIVBYZERO | FE_INVALID)) {
         fprintf (stderr, "Unhandled floating-point exception %d\n", exc);
         fflush (stderr);
         raise (SIGFPE);
      }
   }
   // Restore the rounding mode:
   err = fe_dec_setround (env->rnd);
   assert (!err && "Error while restoring rounding mode");
   // Restore the fenv:
   err = feupdateenv (&env->fenv);
   assert (!err && "Error while restoring floating-point env");
   (void) err;
}

// clang-format off
/**
 * @brief Suspend the current floating-point environment and set the rounding mode.
 *
 * @param Rounding Set the roundin mode for Decimal128, or `-1` to not set a new mode.
 * @param FlagsPtr When restoring the environment, write floating-point exceptions through this pointer.
 *
 * Use this macro as a prefix to a compound statement. The compound statement will have the body protected.
 *
 * @note If `FlagsPtr` is NULL and an FE_DIVBYZERO or FE_INVALID exception occurs, SIGFPE will be raised.
 * @note DO NOT `return` from within the block.
 */
#define MC_HOLD_FENV(Rounding, FlagsPtr) \
   for (int _fe_once = 1; _fe_once; _fe_once = 0) \
   for (struct _mc_fenv _fe_env; _fe_once && _mc_push_fenv(Rounding, &_fe_env); _fe_once = 0, _mc_pop_fenv(&_fe_env, FlagsPtr)) \
   for (; _fe_once; _fe_once = 0)
// clang-format on
#endif /// libdfp

/**
 * @brief Convert a double-precision binary floating point value into the
 * nearest Decimal128 value
 *
 * @param d The number to conver
 * @param rnd The rounding mode in case the value is not exactly representable
 * @param flags Out param for exception/error flags (Optional)
 */
static inline mc_dec128
mc_dec128_from_double_ex (double d,
                          mc_dec128_rounding_mode rnd,
                          mc_dec128_flagset *flags)
{
   MC_IF_IntelDFP ({
      mc_dec128_flagset zero_flags = {0};
      return _dfp_to_mc (
         binary64_to_bid128 (d, rnd, flags ? &flags->bits : &zero_flags.bits));
   });
   MC_IF_LIBDFP ({
      mc_dec128 r;
      MC_HOLD_FENV (rnd, flags)
      {
         // GCC will handle the double → Decimal128 promotion
         r = _dfp_to_mc (d);
      }
      return r;
   });
}

/**
 * @brief Convert a double-precision binary floating point value into the
 * nearest Decimal128 value
 */
static inline mc_dec128
mc_dec128_from_double (double d)
{
   return mc_dec128_from_double_ex (d, MC_DEC128_ROUND_DEFAULT, NULL);
}

/**
 * @brief Convert a string representation of a number into the nearest
 * Decimal128 value
 *
 * @param s The string to parse. MUST be null-terminated
 * @param rnd The rounding mode to use if the result is not representable
 * @param flags Out param for exception/error flags (Optional)
 */
extern mc_dec128
mc_dec128_from_string_ex (const char *s,
                          mc_dec128_rounding_mode rnd,
                          mc_dec128_flagset *flags);

/**
 * @brief Convert a string representation of a number into the nearest
 * Decimal128 value
 */
static inline mc_dec128
mc_dec128_from_string (const char *s)
{
   return mc_dec128_from_string_ex (s, MC_DEC128_ROUND_DEFAULT, NULL);
}

/**
 * @brief A type capable of holding a string rendering of a Decimal128 in
 * engineering notation.
 */
typedef struct mc_dec128_string {
   /// The character array of the rendered value. Null-terminated
   char str[48];
} mc_dec128_string;

/**
 * @brief Render a Decimal128 value as a string (in engineering notation)
 *
 * @param d The number to represent
 * @param flags Output parameter for exception/error flags (optional)
 */
extern mc_dec128_string
mc_dec128_to_string_ex (mc_dec128 d, mc_dec128_flagset *flags);

/**
 * @brief Render a Decimal128 value as a string (in engineering notation)
 */
static inline mc_dec128_string
mc_dec128_to_string (mc_dec128 d)
{
   return mc_dec128_to_string_ex (d, NULL);
}

/// Compare two dec128 numbers
#define DECL_IDF_COMPARE_1(Oper, Builtin)                                  \
   static inline bool mc_dec128_##Oper##_ex (                              \
      mc_dec128 left, mc_dec128 right, mc_dec128_flagset *flags)           \
   {                                                                       \
      _mc_dec128_underlying l = _mc_to_dfp (left), r = _mc_to_dfp (right); \
      MC_IF_IntelDFP ({                                                    \
         mc_dec128_flagset zero_flags = {0};                               \
         return 0 != bid128_quiet_##Oper (                                 \
                        l, r, flags ? &flags->bits : &zero_flags.bits);    \
      });                                                                  \
      MC_IF_LIBDFP ({                                                      \
         bool r = false;                                                   \
         MC_HOLD_FENV (-1, flags)                                          \
         {                                                                 \
            r = l Builtin r;                                               \
         }                                                                 \
         return r;                                                         \
      });                                                                  \
   }                                                                       \
                                                                           \
   static inline bool mc_dec128_##Oper (mc_dec128 left, mc_dec128 right)   \
   {                                                                       \
      return mc_dec128_##Oper##_ex (left, right, NULL);                    \
   }


#define DECL_IDF_COMPARE(Op, Builtin) DECL_IDF_COMPARE_1 (Op, Builtin)

DECL_IDF_COMPARE (equal, ==)
DECL_IDF_COMPARE (not_equal, !=)
DECL_IDF_COMPARE (greater, >)
DECL_IDF_COMPARE (greater_equal, >=)
DECL_IDF_COMPARE (less, <)
DECL_IDF_COMPARE (less_equal, <=)

#undef DECL_IDF_COMPARE
#undef DECL_IDF_COMPARE_1

/// Test properties of Decimal128 numbers
#define DECL_PREDICATE(Name, BIDName)                         \
   static inline bool mc_dec128_##Name (mc_dec128 d)          \
   {                                                          \
      _mc_dec128_underlying v = _mc_to_dfp (d);               \
      MC_IF_IntelDFP ({ return 0 != bid128_##BIDName (v); }); \
      MC_IF_LIBDFP ({ return 0 != Name##d128 (v); });         \
   }

DECL_PREDICATE (isinf, isInf)
DECL_PREDICATE (isfinite, isFinite)
DECL_PREDICATE (isnan, isNaN)

#undef DECL_PREDICATE

/// Binary arithmetic operations on two Decimal128 numbers
#define DECL_IDF_BINOP_WRAPPER(Oper, Builtin)                                 \
   static inline mc_dec128 mc_dec128_##Oper##_ex (                            \
      mc_dec128 left,                                                         \
      mc_dec128 right,                                                        \
      mc_dec128_rounding_mode mode,                                           \
      mc_dec128_flagset *flags)                                               \
   {                                                                          \
      _mc_dec128_underlying l = _mc_to_dfp (left), r = _mc_to_dfp (right);    \
      _mc_dec128_underlying ret;                                              \
      MC_IF_IntelDFP ({                                                       \
         mc_dec128_flagset zero_flags = {0};                                  \
         ret = bid128_##Oper (                                                \
            l, r, mode, flags ? &flags->bits : &zero_flags.bits);             \
      });                                                                     \
      MC_IF_LIBDFP (MC_HOLD_FENV (mode, flags) { ret = l Builtin r; });       \
      return _dfp_to_mc (ret);                                                \
   }                                                                          \
                                                                              \
   static inline mc_dec128 mc_dec128_##Oper (mc_dec128 left, mc_dec128 right) \
   {                                                                          \
      return mc_dec128_##Oper##_ex (                                          \
         left, right, MC_DEC128_ROUND_DEFAULT, NULL);                         \
   }

DECL_IDF_BINOP_WRAPPER (add, +)
DECL_IDF_BINOP_WRAPPER (mul, *)
DECL_IDF_BINOP_WRAPPER (div, /)
DECL_IDF_BINOP_WRAPPER (sub, -)

#undef DECL_IDF_BINOP_WRAPPER

/// Unary arithmetic operations on two Decimal128 numbers
#define DECL_IDF_UNOP_WRAPPER(Oper)                                         \
   static inline mc_dec128 mc_dec128_##Oper##_ex (mc_dec128 operand,        \
                                                  mc_dec128_flagset *flags) \
   {                                                                        \
      _mc_dec128_underlying ret, op = _mc_to_dfp (operand);                 \
      MC_IF_LIBDFP (MC_HOLD_FENV (-1, flags) { ret = Oper##d128 (op); });   \
      MC_IF_IntelDFP ({                                                     \
         mc_dec128_flagset zero_flags = {0};                                \
         ret = bid128_##Oper (op,                                           \
                              MC_DEC128_ROUND_DEFAULT,                      \
                              flags ? &flags->bits : &zero_flags.bits);     \
      });                                                                   \
      return _dfp_to_mc (ret);                                              \
   }                                                                        \
                                                                            \
   static inline mc_dec128 mc_dec128_##Oper (mc_dec128 operand)             \
   {                                                                        \
      return mc_dec128_##Oper##_ex (operand, NULL);                         \
   }

DECL_IDF_UNOP_WRAPPER (log2)
DECL_IDF_UNOP_WRAPPER (log10)
#undef DECL_IDF_UNOP_WRAPPER

static inline mc_dec128
mc_dec128_round_integral_ex (mc_dec128 value,
                             mc_dec128_rounding_mode direction,
                             mc_dec128_flagset *flags)
{
   MC_IF_IntelDFP ({
      BID_UINT128 bid = _mc_to_dfp (value);
      mc_dec128_flagset zero_flags = {0};
      _IDEC_flags *fl = flags ? &flags->bits : &zero_flags.bits;
      switch (direction) {
      case MC_DEC128_ROUND_TOWARD_ZERO:
         return _dfp_to_mc (bid128_round_integral_zero (bid, fl));
      case MC_DEC128_ROUND_NEAREST_AWAY:
         return _dfp_to_mc (bid128_round_integral_nearest_away (bid, fl));
      case MC_DEC128_ROUND_NEAREST_EVEN:
         return _dfp_to_mc (bid128_round_integral_nearest_even (bid, fl));
      case MC_DEC128_ROUND_DOWNWARD:
         return _dfp_to_mc (bid128_round_integral_negative (bid, fl));
      case MC_DEC128_ROUND_UPWARD:
         return _dfp_to_mc (bid128_round_integral_positive (bid, fl));
      default:
         abort ();
      }
   });
   MC_IF_LIBDFP ({
      _Decimal128 d = _mc_to_dfp (value);
      MC_HOLD_FENV (direction, flags)
      {
         d = rintd128 (d);
      }
      return _dfp_to_mc (d);
   });
}

static inline mc_dec128
mc_dec128_negate (mc_dec128 operand)
{
   MC_IF_IntelDFP (return _dfp_to_mc (bid128_negate (_mc_to_dfp (operand))););
   MC_IF_LIBDFP (return _dfp_to_mc (-_mc_to_dfp (operand)));
}

static inline mc_dec128
mc_dec128_abs (mc_dec128 operand)
{
   MC_IF_IntelDFP (return _dfp_to_mc (bid128_abs (_mc_to_dfp (operand))));
   MC_IF_LIBDFP (return _dfp_to_mc (fabsd128 (_mc_to_dfp (operand))));
}

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
   _mc_dec128_underlying ret;
   MC_IF_LIBDFP (MC_HOLD_FENV (rounding, flags) {
      ret = scalblnd128 (_mc_to_dfp (fac), exp);
   });
   MC_IF_IntelDFP ({
      mc_dec128_flagset zero_flags = {0};
      ret = bid128_scalbln (_mc_to_dfp (fac),
                            exp,
                            rounding,
                            flags ? &flags->bits : &zero_flags.bits);
   });
   return _dfp_to_mc (ret);
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

/**
 * @brief Split a Decimal128 into its whole and fractional parts.
 *
 * The "whole" value is the integral value of the Decimal128 rounded towards
 * zero. The "frac" part is the remainder after removing the whole.
 *
 * @param d The value to inspect
 * @param flags Results status flags
 */
static inline mc_dec128_modf_result
mc_dec128_modf_ex (mc_dec128 d, mc_dec128_flagset *flags)
{
   _mc_dec128_underlying frac, whole;
   _mc_dec128_underlying val = _mc_to_dfp (d);
   MC_IF_LIBDFP (MC_HOLD_FENV (-1, flags) { frac = modfd128 (val, &whole); });
   MC_IF_IntelDFP ({
      mc_dec128_flagset zero_flags = {0};
      frac = bid128_modf (val, &whole, flags ? &flags->bits : &zero_flags.bits);
   });
   mc_dec128_modf_result res;
   res.frac = _dfp_to_mc (frac);
   res.whole = _dfp_to_mc (whole);
   return res;
}

/**
 * @brief Split a Decimal128 into its whole and fractional parts.
 *
 * The "whole" value is the integral value of the Decimal128 rounded towards
 * zero. The "frac" part is the remainder after removing the whole.
 *
 * @param d The value to inspect
 */
static inline mc_dec128_modf_result
mc_dec128_modf (mc_dec128 d)
{
   return mc_dec128_modf_ex (d, NULL);
}

/**
 * @brief Compute the "fmod", the remainder after decimal division rounding
 * towards zero.
 *
 * @param numer The dividend of the modulus
 * @param denom The divisor of the modulus
 * @param flags Control/status flags
 */
static inline mc_dec128
mc_dec128_fmod_ex (mc_dec128 numer, mc_dec128 denom, mc_dec128_flagset *flags)
{
   _mc_dec128_underlying ret;
   _mc_dec128_underlying num = _mc_to_dfp (numer), den = _mc_to_dfp (denom);
   MC_IF_LIBDFP (MC_HOLD_FENV (-1, flags) { ret = fmodd128 (num, den); });
   MC_IF_IntelDFP ({
      mc_dec128_flagset zero_flags = {0};
      ret = bid128_fmod (num, den, flags ? &flags->bits : &zero_flags.bits);
   });
   return _dfp_to_mc (ret);
}

/**
 * @brief Compute the "fmod", the remainder after decimal division rounding
 * towards zero.
 *
 * @param numer The dividend of the modulus
 * @param denom The divisor of the modulus
 */
static inline mc_dec128
mc_dec128_fmod (mc_dec128 numer, mc_dec128 denom)
{
   return mc_dec128_fmod_ex (numer, denom, NULL);
}

/**
 * @brief Obtain the a 64-bit binary integer value for the given Decimal128
 * value, nearest rounding toward zero.
 *
 * @param d The value to inspect
 * @param flags Control/status flags
 */
static inline int64_t
mc_dec128_to_int64_ex (mc_dec128 d, mc_dec128_flagset *flags)
{
   int64_t ret;
   _mc_dec128_underlying v = _mc_to_dfp (d);
   MC_IF_LIBDFP (MC_HOLD_FENV (MC_DEC128_ROUND_TOWARD_ZERO, flags) {
      ret = llrintd128 (v);
   });
   MC_IF_IntelDFP ({
      mc_dec128_flagset zero_flags = {0};
      ret = bid128_to_int64_int (v, flags ? &flags->bits : &zero_flags.bits);
   });
   return ret;
}

/**
 * @brief Obtain the a 64-bit binary integer value for the given Decimal128
 * value, nearest rounding toward zero.
 *
 * @param d The value to inspect
 */
static inline int64_t
mc_dec128_to_int64 (mc_dec128 d)
{
   return mc_dec128_to_int64_ex (d, NULL);
}

/// Constants for inspection/deconstruction of Decimal128
enum {
   /// Least non-canonical combination bits value
   MC_DEC128_COMBO_NONCANONICAL = 3 << 15,
   /// Least combination value indicating infinity
   MC_DEC128_COMBO_INFINITY = 0x1e << 12,
   /// The greatest Decimal128 biased exponent
   MC_DEC128_MAX_BIASED_EXPONENT = 6143 + 6144,
   /// The exponent bias of Decimal128
   MC_DEC128_EXPONENT_BIAS = 6143 + 33, // +33 to include the 34 decimal digits
   /// Minimum exponent value (without bias)
   MC_DEC_MIN_EXPONENT = -6143,
   /// Maximum exponent value (without bias)
   MC_DEC_MAX_EXPONENT = 6144,
};

/// Obtain the value of the combination bits of a decimal128
static inline uint32_t
mc_dec128_combination (mc_dec128 d)
{
   // Grab the high 64 bits:
   uint64_t hi = d._words[MLIB_IS_LITTLE_ENDIAN ? 1 : 0];
   // Sign is the 64th bit:
   int signpos = 64 - 1;
   // Combo is the next 16 bits:
   int fieldpos = signpos - 17;
   int fieldmask = (1 << 17) - 1;
   return (uint32_t) ((hi >> fieldpos) & (uint32_t) fieldmask);
}

/**
 * @brief Obtain the value of the high 49 bits of the Decimal128 coefficient
 */
static inline uint64_t
mc_dec128_coeff_high (mc_dec128 d)
{
   uint64_t hi_field_mask = (1ull << 49) - 1;
   uint32_t combo = mc_dec128_combination (d);
   if (combo < MC_DEC128_COMBO_NONCANONICAL) {
      uint64_t hi = d._words[MLIB_IS_LITTLE_ENDIAN ? 1 : 0];
      return hi & hi_field_mask;
   } else {
      return 0;
   }
}

/**
 * @brief Obtain the value of the low 64 bits of the Decimal128 coefficient
 */
static inline uint64_t
mc_dec128_coeff_low (mc_dec128 d)
{
   uint32_t combo = mc_dec128_combination (d);
   if (combo < MC_DEC128_COMBO_NONCANONICAL) {
      uint64_t lo = d._words[MLIB_IS_LITTLE_ENDIAN ? 0 : 1];
      return lo;
   } else {
      return 0;
   }
}

/**
 * @brief Obtain the full coefficient of the given Decimal128 number. Requires a
 * 128-bit integer.
 */
static inline mlib_int128
mc_dec128_coeff (mc_dec128 d)
{
   // Hi bits
   uint64_t hi = mc_dec128_coeff_high (d);
   // Lo bits
   uint64_t lo = mc_dec128_coeff_low (d);
   // Shift and add
   mlib_int128 hi_128 = mlib_int128_lshift (MLIB_INT128_CAST (hi), 64);
   return mlib_int128_add (hi_128, MLIB_INT128_CAST (lo));
}

/**
 * @brief Test if a number is a normal zero
 *
 * @retval true If `d` is non-NaN and non-Inf and has a zero value, regardless
 * of sign or exponent
 * @retval false Otherwise
 */
static inline bool
mc_dec128_is_zero (mc_dec128 d)
{
   mlib_int128 coeff = mc_dec128_coeff (d);
   return !mc_dec128_isnan (d) && mc_dec128_isfinite (d) &&
          mlib_int128_eq (coeff, MLIB_INT128 (0));
}

/**
 * @brief Test if a number is a normal negative (has the sign-bit set)
 *
 * @retval true If `d` is not NaN nor Inf and has the sign-bit set
 * @retval false Otherwise
 */
static inline bool
mc_dec128_is_negative (mc_dec128 d)
{
   uint64_t hi = d._words[MLIB_IS_LITTLE_ENDIAN ? 1 : 0];
   return !mc_dec128_isnan (d) && mc_dec128_isfinite (d) && (hi & (1ull << 63));
}

/**
 * @brief Obtain the biased value of the Decimal128 exponent.
 *
 * The value is "biased" in that its binary value not actually zero for 10^0. It
 * is offset by half the exponent range (the "bias") so it can encode the full
 * positive and negative exponent range. The bias value is defined as
 * MC_DEC128_EXPONENT_BIAS.
 */
static inline uint32_t
mc_dec128_get_biased_exp (mc_dec128 d)
{
   uint32_t combo = mc_dec128_combination (d);
   if (combo < MC_DEC128_COMBO_NONCANONICAL) {
      return combo >> 3;
   }
   if (combo >= MC_DEC128_COMBO_INFINITY) {
      return MC_DEC128_MAX_BIASED_EXPONENT + 1;
   } else {
      return (combo >> 1) & ((1 << 14) - 1);
   }
}

/// Create a decimal string from a dec128 number. The result must be freed.
extern char *
mc_dec128_to_new_decimal_string (mc_dec128 d);

static inline mc_dec128
mc_dec128_from_bson_iter (bson_iter_t *it)
{
   bson_decimal128_t b;
   if (!bson_iter_decimal128 (it, &b)) {
      mc_dec128 nan = MC_DEC128_POSITIVE_NAN;
      return nan;
   }
   mc_dec128 ret;
   memcpy (&ret, &b, sizeof b);
   return ret;
}

static inline bson_decimal128_t
mc_dec128_to_bson_decimal128 (mc_dec128 v)
{
   bson_decimal128_t ret;
   memcpy (&ret, &v, sizeof ret);
   return ret;
}

MLIB_C_LINKAGE_END

#endif // MC_DEC128_H_INCLUDED
