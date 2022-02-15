/*
 * Copyright 2021-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Turn on libc extensions so that we can use dladdr() on Unix-like systems
#if defined(__has_include) && \
   !(defined(_GNU_SOURCE) || defined(_DARWIN_C_SOURCE))
#if __has_include(<features.h>)
// We're using a glibc-compatible library
#define _GNU_SOURCE
#elif __has_include(<Availability.h>)
// We're on Apple/Darwin
#define _DARWIN_C_SOURCE
#endif
#else // No __has_include
#if __GNUC__ < 5
// Best guess on older GCC is that we are using glibc
#define _GNU_SOURCE
#endif
#endif

#include "mongocrypt-util-private.h"

#include "mlib/thread.h"

#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

bool
size_to_uint32 (size_t in, uint32_t *out)
{
   if (in > UINT32_MAX) {
      return false;
   }
   *out = (uint32_t) in;
   return true;
}

current_module_result
current_module_path ()
{
   mstr ret_str = MSTR_NULL;
   int ret_error = 0;
#ifdef _WIN32
   DWORD acc_size = 512;
   while (!ret_str.data && !ret_error) {
      // Loop until we allocate a large enough buffer or get an error
      wchar_t *path = calloc (acc_size + 1, sizeof (wchar_t));
      SetLastError (0);
      GetModuleFileNameW (NULL, path, acc_size);
      if (GetLastError () == ERROR_INSUFFICIENT_BUFFER) {
         // Try again with more buffer
         acc_size *= 2;
      } else if (GetLastError () != 0) {
         ret_error = GetLastError ();
      } else {
         mstr_narrow_result narrow = mstr_win32_narrow (path);
         // GetModuleFileNameW should never return invalid Unicode:
         assert (narrow.error == 0);
         ret_str = narrow.string;
      }
      free (path);
   }
#elif defined(_GNU_SOURCE) || defined(_DARWIN_C_SOURCE)
   // Darwin/BSD/glibc define extensions for finding dynamic library info from
   // the address of a symbol.
   Dl_info info;
   int rc = dladdr ((const void *) current_module_path, &info);
   if (rc == 0) {
      // Failed to resolve the symbol
      ret_error = ENOENT;
   } else {
      ret_str = mstr_copy_cstr (info.dli_fname);
   }
#else
#error "Don't know how to get the module path on this platform"
#endif
   return (current_module_result){.path = ret_str, .error = ret_error};
}
