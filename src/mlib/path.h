#ifndef MONGOCRYPT_PATH_PRIVATE_H
#define MONGOCRYPT_PATH_PRIVATE_H

#include "./user-check.h"

#include "./str.h"

#include <inttypes.h>

/**
 * @brief The preferred path separator for the current platform
 */
static const char MPATH_PREFERRED_PATH_SEPARATOR =
#ifdef _WIN32
   '\\'
#else
   '/'
#endif
   ;

/**
 * @brief Determine if the given character is a path separator on the current
 * platform.
 */
static inline bool
mpath_is_sep (char c)
{
#ifdef _WIN32
   return c == '/' || c == '\\';
#else
   return c == '/';
#endif
}

/**
 * @brief Determine whethre the given path string has a trailing path separator
 */
static inline bool
mpath_has_trailing_sep (mstr_view path)
{
   return path.len && mpath_is_sep (path.data[path.len - 1]);
}

/**
 * @brief Obtain the parent path of the given path.
 *
 * @param path A path string
 * @return mstr_view A substring of the given path string that views only the
 * parent directory of the given path.
 */
static inline mstr_view
mpath_parent (mstr_view path)
{
   // Remove trailing separators:
   while (mpath_has_trailing_sep (path)) {
      path = mstrv_remove_suffix (path, 1);
   }
   // Remove everything that isn't a path separator:
   while (path.len != 0 && !mpath_has_trailing_sep (path)) {
      path = mstrv_remove_suffix (path, 1);
   }
   // Remove trailing separators again
   while (mpath_has_trailing_sep (path)) {
      path = mstrv_remove_suffix (path, 1);
   }
   // The result is the parent path.
   return path;
}

/**
 * @brief Join the two given paths into a single path
 *
 * The two strings will be combined into a single string with a path separator
 * between them. If either string is empty, the other string will be copied
 * without modification.
 *
 * @param base The left-hand of the join
 * @param suffix The right-hand of the join
 * @return mstr A new string resulting from the join
 */
static inline mstr
mpath_join (mstr_view base, mstr_view suffix)
{
   if (!base.len) {
      return mstr_copy (suffix);
   }
   if (mpath_has_trailing_sep (base)) {
      return mstr_append (base, suffix);
   }
   if (!suffix.len) {
      return mstr_copy (base);
   }
   if (mpath_is_sep (suffix.data[0])) {
      return mstr_append (base, suffix);
   }
   // We must insert a path separator between the two strings
   mstr_mut r = mstr_new (base.len + suffix.len + 1);
   char *p = r.data;
   memcpy (p, base.data, base.len);
   p += base.len;
   *p++ = MPATH_PREFERRED_PATH_SEPARATOR;
   memcpy (p, suffix.data, suffix.len);
   return r.mstr;
}

#endif // MONGOCRYPT_PATH_PRIVATE_H
