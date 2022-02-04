#ifndef MONGOCRYPT_PATH_PRIVATE_H
#define MONGOCRYPT_PATH_PRIVATE_H

#include "./user-check.h"

#include <mlib/str.h>

#include <inttypes.h>

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

static inline bool
mpath_has_trailing_sep (mstr_view path)
{
   return path.len && mpath_is_sep (path.data[path.len - 1]);
}

static inline mstr_view
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

static inline mstr
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
