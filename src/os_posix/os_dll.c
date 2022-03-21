#include "../mongocrypt-dll-private.h"

#ifndef _WIN32

#include <string.h>
#include <stdio.h>

#include <dlfcn.h>

mcr_dll
mcr_dll_open (const char *filepath)
{
   void *handle = dlopen (filepath, RTLD_LAZY | RTLD_LOCAL);
   if (handle == NULL) {
      // Failed to open. Return NULL and copy the error message
      return (mcr_dll){
         ._native_handle = NULL,
         .error_string = mstr_copy_cstr (dlerror ()),
      };
   } else {
      // Okay
      return (mcr_dll){
         ._native_handle = handle,
         .error_string = MSTR_NULL,
      };
   }
}

void
mcr_dll_close_handle (mcr_dll dll)
{
   if (dll._native_handle) {
      dlclose (dll._native_handle);
   }
}

void *
mcr_dll_sym (mcr_dll dll, const char *sym)
{
   return dlsym (dll._native_handle, sym);
}

#endif
