#include "../mongocrypt-dll-private.h"

#ifndef _WIN32

#include <string.h>
#include <stdio.h>

#include <dlfcn.h>

_mcr_dll
_mcr_dll_open (const char *filepath)
{
   void *handle = dlopen (filepath, RTLD_LAZY | RTLD_LOCAL);
   if (handle == NULL) {
      // Failed to open. Return NULL and copy the error message
      return (_mcr_dll){
         ._native_handle = NULL,
         ._error_string = strdup (dlerror ()),
      };
   } else {
      // Okay
      return (_mcr_dll){
         ._native_handle = handle,
         ._error_string = NULL,
      };
   }
}

void
_mcr_dll_close_handle (_mcr_dll dll)
{
   if (dll._native_handle) {
      dlclose (dll._native_handle);
   }
}

void *
_mcr_dll_sym (_mcr_dll dll, const char *sym)
{
   return dlsym (dll._native_handle, sym);
}

#endif
