#include "./mc-dec128.h"

mc_dec128_string
mc_dec128_to_string_ex (mc_dec128 d, mc_dec128_flagset *flags)
{
   mc_dec128_string out = {{0}};
#if MC_HAVE_LIBDFP
   MC_HOLD_FENV (-1, flags)
   {
      int ignore = strfromd128 (out.str, sizeof out.str, "%A", _mc_to_dfp (d));
      (void) ignore;
      out.str[(sizeof out.str) - 1] = 0;
   }
#else
   mc_dec128_flagset zero_flags = {0};
   bid128_to_string (
      out.str, _mc_to_dfp (d), flags ? &flags->bits : &zero_flags.bits);
#endif
   return out;
}

mc_dec128
mc_dec128_from_string_ex (const char *s,
                          mc_dec128_rounding_mode rnd,
                          mc_dec128_flagset *flags)
{
#if MC_HAVE_LIBDFP
   mc_dec128 ret;
   char *fin = NULL;
   MC_HOLD_FENV (rnd, flags)
   {
      ret = _dfp_to_mc (strtod128 (s, &fin));
   }
   return ret;
#else
   mc_dec128_flagset zero_flags = {0};
   return _dfp_to_mc (bid128_from_string (
      (char *) s, rnd, flags ? &flags->bits : &zero_flags.bits));
#endif
}


char *
mc_dec128_to_new_decimal_string (mc_dec128 d)
{
   if (mc_dec128_is_zero (d)) {
      // Just return "0"
      char *s = (char *) calloc (2, 1);
      if (s) {
         s[0] = '0';
      }
      return s;
   }

   if (mc_dec128_is_negative (d)) {
      // Negate the result, return a string with a '-' prefix
      d = mc_dec128_negate (d);
      char *s = mc_dec128_to_new_decimal_string (d);
      if (!s) {
         return NULL;
      }
      char *s1 = (char *) calloc (strlen (s) + 2, 1);
      if (s1) {
         s1[0] = '-';
         strcpy (s1 + 1, s);
      }
      free (s);
      return s1;
   }

   if (mc_dec128_isinf (d) || mc_dec128_isnan (d)) {
      const char *r = mc_dec128_isinf (d) ? "Infinity" : "NaN";
      char *c = (char *) calloc (strlen (r) + 1, 1);
      if (c) {
         strcpy (c, r);
      }
      return c;
   }

   const char DIGITS[] = "0123456789";
   const mc_dec128 TEN = MC_DEC128_C (10);

   // Format the whole and fractional part separately.
   mc_dec128_modf_result modf = mc_dec128_modf (d);

   if (mc_dec128_is_zero (modf.frac)) {
      // This is a non-zero integer
      // Allocate enough digits:
      mc_dec128 log10 = mc_dec128_round_integral_ex (
         mc_dec128_log10 (d), MC_DEC128_ROUND_UPWARD, NULL);
      int64_t ndigits = mc_dec128_to_int64 (log10);
      // +1 for null
      char *strbuf = (char *) calloc ((size_t) (ndigits + 1), 1);
      if (strbuf) {
         // Write the string backwards:
         char *optr = strbuf + ndigits - 1;
         while (!mc_dec128_is_zero (modf.whole)) {
            mc_dec128 rem = mc_dec128_fmod (modf.whole, TEN);
            int64_t remi = mc_dec128_to_int64 (rem);
            *optr-- = DIGITS[remi];
            // Divide ten
            modf = mc_dec128_modf (mc_dec128_div (modf.whole, TEN));
         }
      }
      return strbuf;
   } else if (mc_dec128_is_zero (modf.whole)) {
      // This is only a fraction (less than one, but more than zero)
      while (!mc_dec128_is_zero (mc_dec128_modf (d).frac)) {
         d = mc_dec128_mul (d, TEN);
      }
      // 'd' is now a whole number
      char *part = mc_dec128_to_new_decimal_string (d);
      if (!part) {
         return NULL;
      }
      char *buf = (char *) calloc (strlen (part) + 3, 1);
      if (buf) {
         buf[0] = '0';
         buf[1] = '.';
         strcpy (buf + 2, part);
      }
      free (part);
      return buf;
   } else {
      // We have both a whole part and a fractional part
      char *whole = mc_dec128_to_new_decimal_string (modf.whole);
      if (!whole) {
         return NULL;
      }
      char *frac = mc_dec128_to_new_decimal_string (modf.frac);
      if (!frac) {
         free (whole);
         return NULL;
      }
      char *ret = (char *) calloc (strlen (whole) + strlen (frac) + 1, 1);
      if (ret) {
         char *out = ret;
         strcpy (out, whole);
         out += strlen (whole);
         // "frac" contains a leading zero, which we don't want
         strcpy (out, frac + 1);
      }
      free (whole);
      free (frac);
      return ret;
   }
}
