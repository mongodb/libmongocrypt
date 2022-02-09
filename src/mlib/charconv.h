#ifndef MLIB_CHARCONV_H
#define MLIB_CHARCONV_H

#include "str.h"

#include <inttypes.h>
#include <assert.h>
#include <errno.h>

/**
 * @brief The result of a pointer-to-value conversion operation
 */
typedef struct mlib_conv_result {
   /// Pointer to the first non-parsed character
   const char *ptr;
   /// An error code for the operation. Zero on success.
   int ec;
} mlib_conv_result;

/**
 * @brief Obtain the numeric value of the given character in base36
 *
 * @param c An alphanumeric character
 * @return int An integral value between zero and thirty-six, or -1 if `c` is
 * not an alphanumeric
 */
static int
mlib_charval (char c)
{
   if (c >= '0' && c <= '9') {
      return c - '0';
   }
   if (c >= 'A' && c <= 'Z') {
      // Shift to lowercase:
      c += ('a' - 'A');
   }
   if (c >= 'a' && c <= 'z') {
      return 10 + (c - 'a');
   }
   return -1;
}

static inline mlib_conv_result
mlib_u64_from_chars_bounded (uint64_t *const into,
                             const mstr_view string,
                             const int base,
                             const uint64_t max)
{
   assert (base >= 2);
   assert (base <= 36);
   const char *iter = string.data;
   const char *const end = string.data + string.len;

   uint64_t ret = 0;
   int fac = 1;

   for (; iter != end; ++iter) {
      ret *= (uint64_t) base;
      int cval = mlib_charval (*iter);
      if (cval == -1 || cval >= base) {
         break;
      }
      uint64_t remain = max - ret;
      if (cval > remain) {
         return (mlib_conv_result){.ptr = iter, .ec = ERANGE};
      }
      ret += (uint64_t) cval;
   }
   if (iter == string.data) {
      // No chars were parsed
      return (mlib_conv_result){.ptr = iter, .ec = EINVAL};
   }
   *into = ret * fac;
   return (mlib_conv_result){.ptr = iter, .ec = 0};
}

/**
 * @brief Convert the given string into an unsigned 64bit number
 *
 * @param into The result will be written into this pointer
 * @param string The integral string to parse
 * @param base The radix of the parse. Must be between 2 and 36, inclusive
 * @return mlib_conv_result Result information about the conversion
 */
static inline mlib_conv_result
mlib_u64_from_chars (uint64_t *const into,
                     const mstr_view string,
                     const int base)
{
   return mlib_u64_from_chars_bounded (into, string, base, UINT64_MAX);
}

/**
 * @brief Convert the given string into a signed 64bit number
 *
 * @param into The result will be written into this pointer
 * @param string The integral string to parse
 * @param base The radix of the parse. Must be between 2 and 36, inclusive
 * @return mlib_conv_result Result information about the conversion
 */
static inline mlib_conv_result
mlib_i64_from_chars (int64_t *const into, mstr_view string, const int base)
{
   int fac = 1;
   if (string.len && string.data[0] == '-') {
      fac = -1;
      string = mstrv_subview (string, 1, ~0);
   }

   uint64_t us = 0;
   uint64_t max = INT64_MAX;
   if (fac < 0) {
      max = (uint64_t) (-(INT64_MIN + 1)) + 1;
   }
   const mlib_conv_result res =
      mlib_u64_from_chars_bounded (&us, string, base, max);
   if (res.ec) {
      return res;
   }
   if (us == max) {
      // unsigned wrap will take care of the sign
      *into = (int64_t) us;
   } else {
      *into = (int64_t) us * fac;
   }
   return res;
}

#endif // MLIB_CHARCONV_H