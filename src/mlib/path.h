#ifndef MONGOCRYPT_PATH_PRIVATE_H
#define MONGOCRYPT_PATH_PRIVATE_H

#include "./user-check.h"

#include <mlib/str.h>

/**
 * @brief Determine if the given character is a path separator on the current
 * platform.
 */
mcr_cxx_inline bool
mpath_is_sep (char c)
{
#ifdef _WIN32
   return c == '/' || c == '\\';
#else
   return c == '/';
#endif
}

mcr_cxx_inline bool
mpath_has_trailing_sep (mstr_view path)
{
   return path.len && mpath_is_sep (path.data[path.len - 1]);
}

mcr_cxx_inline mstr_view
mpath_parent (mstr_view path)
{
   // Remove trailing separators:
   while (mpath_has_trailing_sep (path)) {
      path.len--;
   }
   // Remove everything that isn't a path separator:
   while (path.len != 0 && !mpath_is_sep (path.data[path.len - 1])) {
      path.len--;
   }
   // Remove trailing separators again
   while (mpath_has_trailing_sep (path)) {
      path.len--;
   }
   // The result is the parent path.
   return path;
}

mcr_cxx_inline mstr
mpath_join (mstr_view base, mstr_view suffix)
{
   if (!base.len) {
      return mpath_join (mstrv_view_cstr ("./"), suffix);
   }
   if (mpath_has_trailing_sep (base)) {
      return mstr_append (base, suffix);
   }
   mstr_mut r = mstr_new (base.len + suffix.len + 1);
   char *p = r.data;
   memcpy (p, base.data, base.len);
   p += base.len;
   *p++ = '/';
   memcpy (p, suffix.data, suffix.len);
   return r.mstr;
}

#if _WIN32

#include <windows.h>

mcr_cxx_inline mstr
mpath_current_exe_path ()
{
   int len = GetModuleFileNameW (NULL, NULL, 0);
   wchar_t *path = calloc (len + 1, sizeof (wchar_t));
   GetModuleFileNameW (NULL, path, len);
   mstr_narrow_result narrow = mstr_win32_narrow (path);
   // GetModuleFileNameW should never return invalid Unicode:
   assert (narrow.error == 0);
   return narrow.string;
}

#endif

#endif // MONGOCRYPT_PATH_PRIVATE_H
