#include "../mongocrypt-dll-private.h"

#ifdef _WIN32

#include <mlib/str.h>
#include <mlib/path.h>
#include <mlib/error.h>

#include <string.h>
#include <stdio.h>

#include <windows.h>

_mcr_dll
_mcr_dll_open (const char *filepath_)
{
   // Convert all slashes to the native Windows separator
   mstr filepath = mpath_win32_to_native (mstrv_view_cstr (filepath_));
   DWORD flag = 0;
   // Check if the path is just a filename.
   bool is_just_filename =
      mstr_eq (mpath_filename (filepath.view), filepath.view);
   if (!is_just_filename) {
      // If the path is only a filename, we'll allow LoadLibrary() to do a
      // proper full DLL search. If the path is NOT just a filename, resolve the
      // given path to a single unambiguous absolute path, so suppress
      // LoadLibrary()'s DLL search behavior.
      mstr_assign (&filepath, mpath_absolute (filepath.view));
   }
   mstr_widen_result wide = mstr_win32_widen (filepath.view);
   mstr_free (filepath);
   if (wide.error) {
      return (_mcr_dll){._native_handle = NULL,
                        .error_string =
                           merror_system_error_string (wide.error)};
   }
   HMODULE lib = LoadLibraryW (wide.wstring);
   if (lib == NULL) {
      return (_mcr_dll){._native_handle = NULL,
                        .error_string =
                           merror_system_error_string (GetLastError ())};
   }
   free (wide.wstring);
   return (_mcr_dll){.error_string = NULL, ._native_handle = lib};
}

void
_mcr_dll_close_handle (_mcr_dll dll)
{
   if (dll._native_handle) {
   }
}

void *
_mcr_dll_sym (_mcr_dll dll, const char *sym)
{
   return GetProcAddress (dll._native_handle, sym);
}

#endif
