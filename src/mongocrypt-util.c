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
// We're only a glibc-compatible library
#define _GNU_SOURCE
#elif __has_include(<Availability.h>)
// We're on Apple/Darwin
#define _DARWIN_C_SOURCE
#endif
#endif

#include "mongocrypt-util-private.h"

#include "mlib/thread.h"
#include "mlib/charconv.h"

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

static mstr THIS_MODULE_PATH;
static int THIS_MODULE_ERROR;
static mlib_once_flag INIT_THIS_MODULE_PATH = MLIB_ONCE_INITIALIZER;

static void
free_this_module_path (void)
{
   mstr_free (THIS_MODULE_PATH);
}

static void
do_init_this_module_path (void)
{
   atexit (free_this_module_path);
#ifdef _WIN32
   int len = GetModuleFileNameW (NULL, NULL, 0);
   wchar_t *path = calloc (len + 1, sizeof (wchar_t));
   GetModuleFileNameW (NULL, path, len);
   mstr_narrow_result narrow = mstr_win32_narrow (path);
   // GetModuleFileNameW should never return invalid Unicode:
   assert (narrow.error == 0);
   THIS_MODULE_PATH = narrow.string;
#elif defined(_GNU_SOURCE) || defined(_DARWIN_C_SOURCE)
   // Darwin/BSD/glibc define extensions for finding dynamic library info from
   // the address of a symbol.
   Dl_info info;
   int rc = dladdr ((const void *) do_init_this_module_path, &info);
   if (rc == 0) {
      // Failed to resolve the symbol
      THIS_MODULE_ERROR = ENOENT;
      return;
   }
   THIS_MODULE_PATH = mstr_copy_cstr (info.dli_fname);
#else
#error "Don't know how to get the module path on this platform"
#endif
}

current_module_result
current_module_path ()
{
   mlib_call_once (&INIT_THIS_MODULE_PATH, do_init_this_module_path);
   return (current_module_result){.path = THIS_MODULE_PATH.view,
                                  .error = THIS_MODULE_ERROR};
}
