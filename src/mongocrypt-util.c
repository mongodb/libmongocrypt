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

#include "mongocrypt-util-private.h"

#include "mlib/charconv.h"


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


bool
size_to_uint32 (size_t in, uint32_t *out)
{
   if (in > UINT32_MAX) {
      return false;
   }
   *out = (uint32_t) in;
   return true;
}

read_file_result
read_file (mstr_view filepath_, const size_t max_read)
{
   errno = 0;
   mstr filepath = mstr_copy (filepath_);
   FILE *f = fopen (filepath.data, "rb");
   if (!f) {
      return (read_file_result){.content = MSTR_NULL, .error = errno};
   }
   char buf[512];
   mstr content = mstr_new (0).mstr;
   while (1) {
      const size_t nread = fread (buf, 1, sizeof buf, f);
      if (nread <= 0) {
         break;
      }
      mstr_inplace_append (&content, mstrv_view_data (buf, (size_t) nread));
      if (content.len > max_read) {
         break;
      }
   }
   mstr_free (filepath);
   if (content.len > max_read) {
      mstr_inplace_trunc (&content, max_read);
      return (read_file_result){.content = content, .error = EFBIG};
   }
   return (read_file_result){.content = content};
}

current_module_result
current_module_path ()
{
#ifdef _WIN32
   int len = GetModuleFileNameW (NULL, NULL, 0);
   wchar_t *path = calloc (len + 1, sizeof (wchar_t));
   GetModuleFileNameW (NULL, path, len);
   mstr_narrow_result narrow = mstr_win32_narrow (path);
   // GetModuleFileNameW should never return invalid Unicode:
   assert (narrow.error == 0);
   return (current_module_result){.path = narrow.string, .error = 0};
#elif defined(__linux__)
   // We find the path to the current executable module by reading the path to
   // the executable that is loaded into memory. We find the appropriate module
   // by finding the mapping that contains the address of our own function.
   const read_file_result maps_file =
      read_file (mstrv_lit ("/proc/self/maps"), 1024 * 1024 * 8);
   mstr found_map = MSTR_NULL;
   if (maps_file.error != 0) {
      // Failed to open the maps file
      mstr_free (maps_file.content);
      return (current_module_result){.path = found_map, .error = errno};
   }
   // Find the address of the current function in the maps
   const uint64_t this_fn_addr = (uint64_t) (&current_module_path);
   mstr line = MSTR_NULL;
   mstr maps_str = maps_file.content;
   MSTR_ITER_SPLIT (line, maps_str.view, mstrv_lit ("\n"))
   {
      // Find the filename for the executable for this map:
      const int spsp_pos = mstr_rfind (line, mstrv_lit ("  "));
      if (spsp_pos < 0) {
         continue;
      }
      const mstr_view mapped = mstrv_subview (line, spsp_pos + 2, SIZE_MAX);
      // Find the first space:
      int space_pos = mstr_find (line, mstrv_lit (" "));
      if (space_pos < 0) {
         continue;
      }
      // The map's address range is split with a hyphen:
      const mstr_view range = mstrv_subview (line, 0, space_pos);
      int hyphen_pos = mstr_find (range, mstrv_lit ("-"));
      if (hyphen_pos < 0) {
         continue;
      }
      // The two parts:
      const mstr_view low_str = mstrv_subview (range, 0, hyphen_pos);
      const mstr_view high_str =
         mstrv_subview (range, hyphen_pos + 1, SIZE_MAX);
      uint64_t low = 0;
      mlib_conv_result res = mlib_u64_from_chars (&low, low_str, 16);
      if (res.ec || res.ptr != (low_str.data + low_str.len)) {
         continue;
      }
      uint64_t high = 0;
      res = mlib_u64_from_chars (&high, high_str, 16);
      if (res.ec || res.ptr != (high_str.data + high_str.len)) {
         continue;
      }
      if (this_fn_addr < low || this_fn_addr > high) {
         // Not in this one
         continue;
      }
      // We've found the mapping that contains the current function.
      found_map = mstr_copy (mapped);
      break;
   }
   mstr_free (line);
   mstr_free (maps_str);
   if (found_map.data) {
      // We found the mapping in the proc maps file
      return (current_module_result){.path = found_map, .error = 0};
   }
   return (current_module_result){.path = MSTR_NULL, .error = ENOENT};
#elif defined(__APPLE__)
   char nil = 0;
   uint32_t bufsize = 0;
   _NSGetExecutablePath (&nil, &bufsize);
   mstr_mut ret = mstr_new (bufsize);
   _NSGetExecutablePath (ret.data, &bufsize);
   return (current_module_result){.path = ret.mstr, .error = 0};
#else
#error "Don't know how to get the executable path on this platform"
#endif
}