#ifndef MONGOCRYPT_PATH_PRIVATE_H
#define MONGOCRYPT_PATH_PRIVATE_H

#include "./user-check.h"

#include "./str.h"

#include <inttypes.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

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
 * @brief Obtain the path string denoting the application's current working
 * directory
 *
 * @return mstr A new string which must be freed with mstr_free()
 */
static inline mstr
mpath_current_path ()
{
#if _WIN32
   while (1) {
      DWORD len = GetCurrentDirectoryW (0, NULL);
      wchar_t *wstr = calloc (sizeof (wchar_t), len);
      DWORD got_len = GetCurrentDirectoryW (len, wstr);
      if (got_len > len) {
         free (wstr);
         continue;
      }
      mstr_narrow_result nar = mstr_win32_narrow (wstr);
      free (wstr);
      assert (nar.error == 0);
      return nar.string;
   }
#else
   mstr_mut mut = mstr_new (8096);
   char *p = getcwd (mut.data, mut.len);
   if (p == NULL) {
      mstr_free (mut.mstr);
      return MSTR_NULL;
   }
   mstr ret = mstr_copy_cstr (mut.data);
   mstr_free (mut.mstr);
   return ret;
#endif
}

/**
 * @brief Determine whether the given path string has a trailing path separator
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
   if (mpath_has_trailing_sep (path)) {
      // Remove trailing separators:
      while (mpath_has_trailing_sep (path)) {
         path = mstrv_remove_suffix (path, 1);
      }
      return path;
   }
   // Remove everything that isn't a path separator:
   while (path.len != 0 && !mpath_has_trailing_sep (path)) {
      path = mstrv_remove_suffix (path, 1);
   }
   // Remove trailing separators again
   while (path.len > 1 && mpath_has_trailing_sep (path)) {
      path = mstrv_remove_suffix (path, 1);
   }
   // The result is the parent path.
   return path;
}

/**
 * @brief Obtain the filename denoted by the given path.
 *
 * The returned path will include no directory separators. If the given path
 * ends with a directory separator, the single-dot '.' path is returned instead.
 */
static inline mstr_view
mpath_filename (mstr_view path)
{
   if (!path.len) {
      return path;
   }
   const char *it = path.data + path.len;
   while (it != path.data && !mpath_is_sep (it[-1])) {
      --it;
   }
   size_t off = it - path.data;
   mstr_view fname = mstrv_subview (path, off, path.len);
   if (fname.len == 0) {
      return mstrv_lit (".");
   }
   return fname;
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
 * @brief Obtain the root name (drive letter) for the given path, if present
 *
 * If the path does not have a drive letter, returns an empty string
 */
static inline mstr_view
mpath_win32_root_name (mstr_view path)
{
   if (path.len > 1) {
      char c = path.data[0];
      if (path.len > 2 && path.data[1] == ':' &&
          ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) {
         return mstrv_subview (path, 0, 2);
      }
   }
   return mstrv_subview (path, 0, 0);
}

/**
 * @brief Obtain the root name for the given path.
 *
 * On Windows, this will return the drive letter, if present. Otherwise, this
 * will return an empty string.
 */
static inline mstr_view
mpath_root_name (mstr_view path)
{
#ifdef _WIN32
   return mpath_win32_root_name (path);
#else
   return mstrv_subview (path, 0, 0);
#endif
}

/**
 * @brief Obtain the root directory component of the given POSIX filepath, if
 * present.
 *
 * If there is no root directory component, returns an empty string.
 */
static inline mstr_view
mpath_posix_root_directory (mstr_view path)
{
   if (path.len && mpath_is_sep (path.data[0])) {
      return mstrv_subview (path, 0, 1);
   }
   return mstrv_subview (path, 0, 0);
}

/**
 * @brief Returns the root directory component of the given Win32 filepath, if
 * present.
 *
 * @note This will not include the drive letter of the path, if present.
 */
static inline mstr_view
mpath_win32_root_directory (mstr_view path)
{
   mstr_view rname = mpath_win32_root_name (path);
   path = mstrv_subview (path, rname.len, path.len);
   return mpath_posix_root_directory (path);
}

/**
 * @brief Return the root directory of the given path, if present.
 */
static inline mstr_view
mpath_root_directory (mstr_view path)
{
#ifdef _WIN32
   return mpath_win32_root_directory (path);
#else
   return mpath_posix_root_directory (path);
#endif
}

/**
 * @brief Obtain the root filepath of the given path.
 *
 * This will include both the root name and the root filepath, if present.
 */
static inline mstr_view
mpath_root_path (mstr_view path)
{
   mstr_view rname = mpath_root_name (path);
   mstr_view rdir = mpath_root_directory (path);
   return mstrv_subview (path, 0, rname.len + rdir.len);
}

/**
 * @brief Determine whether the given Win32 filepath designates a single
 * unambiguous file location.
 *
 * @note A Win32 filepath without a drive letter is not absolute!
 */
static inline bool
mpath_win32_is_absolute (mstr_view path)
{
   return mpath_win32_root_name (path).len &&
          mpath_win32_root_directory (path).len;
}

/**
 * @brief Determine whether the given POSIX filepath designates a single
 * unambiguous filesystem location.
 */
static inline bool
mpath_posix_is_absolute (mstr_view path)
{
   return path.len && mpath_is_sep (path.data[0]);
}

/**
 * @brief Determine whether the given filepath designates a single unambiguous
 * filesystem location.
 *
 * @note The defintion of "absolute" varies on the host platform.
 */
static inline bool
mpath_is_absolute (mstr_view path)
{
#ifdef _WIN32
   return mpath_win32_is_absolute (path);
#else
   return mpath_posix_is_absolute (path);
#endif
}

/**
 * @brief Obtain a relative path from the given filepath
 *
 * If the path has a root path, returns the content of the path following that
 * root path, otherwise returns the same path itself.
 */
static inline mstr_view
mpath_relative_path (mstr_view path)
{
   mstr_view root = mpath_root_path (path);
   return mstrv_subview (path, root.len, path.len);
}

/**
 * @brief Given a Win32 filepath, normalize all directory separators to the
 * back-slash character '\'
 *
 * @note The return value must be given to mstr_free()
 */
static inline mstr
mpath_win32_to_native (mstr_view path)
{
   mstr_mut ret = mstr_new (path.len);
   const char *p = path.data;
   char *out = ret.data;
   const char *stop = path.data + path.len;
   for (; p != stop; ++p, ++out) {
      if (*p == '/' || *p == '\\') {
         *out = '\\';
      } else {
         *out = *p;
      }
   }
   return ret.mstr;
}

/**
 * @brief Convert the given path to a native-system preferred path format
 *
 * @note The return value must be given to mstr_free()
 */
static inline mstr
mpath_to_native (mstr_view path)
{
#ifndef _WIN32
   return mstr_copy (path);
#else
   return mpath_win32_to_native (path);
#endif
}

/**
 * @brief Determine whether the given path is relative (not absolute)
 */
static inline bool
mpath_is_relative (mstr_view path)
{
   return !mpath_is_absolute (path);
}

/**
 * @brief Convert the given path to an absolute path, if it is not already.
 *
 * @note The return value must be given to mstr_free()
 */
static inline mstr
mpath_absolute (mstr_view path);

/**
 * @brief Resolve a path to an absolute path from the given base path.
 *
 * @note This is not the same as mpath_join(): If the given path is already
 * absolute, returns that path unchanged. Otherwise, resolves that path as being
 * relative to `base`.
 *
 * @note If `base` is also a relative path, it will also be given to
 * mpath_absolute() to resolve it.
 */
static inline mstr
mpath_absolute_from (mstr_view path, mstr_view base)
{
   mstr_view rname = mpath_root_name (path);
   mstr_view rdir = mpath_root_directory (path);
   if (rname.len) {
      if (rdir.len) {
         return mstr_copy (path);
      } else {
         mstr abs_base = mpath_absolute (base);
         mstr_view base_rdir = mpath_root_directory (abs_base.view);
         mstr_view base_relpath = mpath_relative_path (abs_base.view);
         mstr_view relpath = mpath_relative_path (path);
         mstr ret = mstr_copy (rname);
         mstr_assign (&ret, mpath_join (ret.view, base_rdir));
         mstr_assign (&ret, mpath_join (ret.view, base_relpath));
         mstr_assign (&ret, mpath_join (ret.view, relpath));
         mstr_free (abs_base);
         return ret;
      }
   } else {
      // No root name
      if (rdir.len) {
         mstr abs_base = mpath_absolute (base);
         mstr_view base_rname = mpath_root_name (abs_base.view);
         mstr ret = mpath_join (base_rname, path);
         mstr_free (abs_base);
         return ret;
      } else {
         mstr abs_base = mpath_absolute (base);
         mstr r = mpath_join (abs_base.view, path);
         mstr_free (abs_base);
         return r;
      }
   }
}

static inline mstr
mpath_absolute (mstr_view path)
{
   if (mpath_is_absolute (path)) {
      return mstr_copy (path);
   }
   mstr cur = mpath_current_path ();
   mstr ret = mpath_absolute_from (path, cur.view);
   mstr_free (cur);
   return ret;
}

#endif // MONGOCRYPT_PATH_PRIVATE_H
