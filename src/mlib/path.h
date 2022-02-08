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

/**
 * @brief The result type of mpath_current_exe_path()
 *
 * The @ref mpath_current_exe_result::path member must be freed with mstr_free()
 */
typedef struct mpath_current_exe_result {
   /// The resulting executable path
   mstr path;
   /// An error, if the path could not be obtained
   int error;
} mpath_current_exe_result;

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <unistd.h>
#endif

#if __APPLE__
// For loading the current exe path
#include <mach-o/dyld.h>
#endif

/**
 * @brief Obtain the path to the calling executable module
 *
 * On Unix-like platforms, this will be the actual executable file. On Windows,
 * this may be the path to the DLL that contains the caller.
 *
 * @return mpath_current_exe_result A result object of the operation. Check the
 * `.error` member for non-zero. The `.path` member must be freed with
 * mtsr_free()
 */
static inline mpath_current_exe_result
mpath_current_exe_path ()
{
#ifdef _WIN32
   int len = GetModuleFileNameW (NULL, NULL, 0);
   wchar_t *path = calloc (len + 1, sizeof (wchar_t));
   GetModuleFileNameW (NULL, path, len);
   mstr_narrow_result narrow = mstr_win32_narrow (path);
   // GetModuleFileNameW should never return invalid Unicode:
   assert (narrow.error == 0);
   return (mpath_current_exe_result){.path = narrow.string, .error = 0};
#elif defined(__linux__)
   mstr_mut ret = mstr_new (8096);
   ssize_t n_len = readlink ("/proc/self/exe", ret.data, ret.len);
   if (n_len < 0) {
      mstr_free (ret.mstr);
      return (mpath_current_exe_result){.path = MSTR_NULL, .error = errno};
   }
   mstrm_resize (&ret, (size_t) n_len);
   return (mpath_current_exe_result){.path = ret.mstr, .error = 0};
#elif defined(__APPLE__)
   char nil = 0;
   uint32_t bufsize = 0;
   _NSGetExecutablePath (&nil, &bufsize);
   mstr_mut ret = mstr_new (bufsize);
   _NSGetExecutablePath (ret.data, &bufsize);
   return (mpath_current_exe_result){.path = ret.mstr, .error = 0};
#else
#error "Don't know how to get the executable path on this platform"
#endif
}

#endif // MONGOCRYPT_PATH_PRIVATE_H
