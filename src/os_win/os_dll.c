#include "../mongocrypt-dll-private.h"

#ifdef _WIN32

#include <mlib/str.h>
#include <mlib/path.h>
#include <mlib/error.h>

#include <string.h>
#include <stdio.h>

#include <windows.h>

mcr_dll
mcr_dll_open (const char *filepath_)
{
   // Convert all slashes to the native Windows separator
   mstr filepath =
      mpath_to_format (MPATH_WIN32, mstrv_view_cstr (filepath_), MPATH_WIN32);
   // Check if the path is just a filename.
   bool is_just_filename =
      mstr_eq (mpath_filename (filepath.view, MPATH_WIN32), filepath.view);
   if (!is_just_filename) {
      // If the path is only a filename, we'll allow LoadLibrary() to do a
      // proper full DLL search. If the path is NOT just a filename, resolve the
      // given path to a single unambiguous absolute path t suppress
      // LoadLibrary()'s DLL search behavior.
      mstr_assign (&filepath, mpath_absolute (filepath.view, MPATH_WIN32));
   }
   mstr_widen_result wide = mstr_win32_widen (filepath.view);
   mstr_free (filepath);
   if (wide.error) {
      return (mcr_dll){._native_handle = NULL,
                       .error_string = merror_system_error_string (wide.error)};
   }
   HMODULE lib = LoadLibraryW (wide.wstring);
   if (lib == NULL) {
      return (mcr_dll){._native_handle = NULL,
                       .error_string =
                          merror_system_error_string (GetLastError ())};
   }
   free (wide.wstring);
   return (mcr_dll){.error_string = NULL, ._native_handle = lib};
}

void
mcr_dll_close_handle (mcr_dll dll)
{
   if (dll._native_handle) {
      FreeLibrary (dll._native_handle);
   }
}

void *
mcr_dll_sym (mcr_dll dll, const char *sym)
{
   return GetProcAddress (dll._native_handle, sym);
}

#endif
