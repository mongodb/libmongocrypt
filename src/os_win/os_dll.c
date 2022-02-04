#include "../mongocrypt-dll-private.h"

#ifdef _WIN32

#include <mlib/str.h>
#include <mlib/error.h>

#include <string.h>
#include <stdio.h>

#include <windows.h>

#undef widen

_mcr_dll
_mcr_dll_open (const char *filepath)
{
   mstr_widen_result wide = mstr_win32_widen (mstrv_view_cstr (filepath));
   if (wide.error) {
      return (_mcr_dll){._native_handle = NULL,
                        ._error_string =
                           merror_system_error_string (wide.error)};
   }
   HMODULE lib = LoadLibraryW (wide.wstring);
   if (lib == NULL) {
      return (_mcr_dll){._native_handle = NULL,
                        ._error_string =
                           merror_system_error_string (GetLastError ())};
   }
   free (wide.wstring);
   return (_mcr_dll){._error_string = NULL, ._native_handle = lib};
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
