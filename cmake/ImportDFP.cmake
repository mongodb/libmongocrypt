#[[
   This file handles importing the DFP (decimal floating point) library for decimal128 support. It
   is patterned after ImportBSON in this same directory.

   This file defines, exports, and installs one INTERFACE target: _mongocrypt::dfp.

   The target(s) from this file are used to link the DFP library correctly for the build
   configuration of libmongocrypt. At find_package() time, we can resolve these interface targets
   to link to the DFP library based on the build configurations of libmongocrypt.

   In the initial implementation both mongo::mongocrypt and mongo::mongocrypt_static must link to
   _mongocrypt::dfp (this is because if we link to the Intel DFP which is vendored with
   libmongocrypt then we will link the object files directly and if we use the system Intel DFP then
   we will be linking with .a static library archives).

   The default behavior is to use the Intel DFP which is vendored in this repository. By setting
   MONGOCRYPT_DFP_DIR=USE-SYSTEM the build will assume that an appropriate DFP implementation
   can be found in a location where it has been installed system-wide (most likely under /usr or
   /usr/local). It will search for an installation of IntelDFP or of libdfp.
]]

if (DEFINED MONGOCRYPT_DFP_DIR AND NOT MONGOCRYPT_DFP_DIR STREQUAL "USE-SYSTEM")
   message (FATAL_ERROR "The only valid value  for MONGOCRYPT_DFP_DIR is USE-SYSTEM")
endif ()

function (_import_dfp)
   if (NOT _MONGOCRYPT_SYSTEM_DFP_LIB OR NOT _MONGOCRYPT_SYSTEM_DFP_INCLUDE_DIR)
      message (CHECK_START "Searching for a decimal floating-point library")
      # Clear prior settings if either one may have been unset:
      unset (_MONGOCRYPT_SYSTEM_DFP_LIB CACHE)
      unset (_MONGOCRYPT_SYSTEM_DFP_INCLUDE_DIR CACHE)
      # Search for the IntelDFP library:
      find_library (
         _inteldfp_lib
         NAMES bidgcc000 "${CMAKE_STATIC_LIBRARY_PREFIX}bidgcc000${CMAKE_STATIC_LIBRARY_SUFFIX}"
         NO_CACHE
         )
      # Search for the libdfp library:
      find_library (
         _libdfp_lib
         NAMES dfp "${CMAKE_STATIC_LIBRARY_PREFIX}dfp${CMAKE_STATIC_LIBRARY_SUFFIX}"
         NO_CACHE
         )

      # Search for the include-path for IntelDFP:
      find_path (_inteldfp_bid_conf_h_dir bid_conf.h NO_CACHE)
      # Search for math.h contained in libdfp:
      find_file (_libdfp_dfp_math_h "dfp/math.h" NO_CACHE)

      set (_lib NOTFOUND)
      set (_inc_dir NOTFOUND)
      if (_inteldfp_lib AND _inteldfp_bid_conf_h_dir)
         # Use libdfp:
         message (CHECK_PASS "Using IntelDFP: ${_inteldfp_lib}")
         set (_lib "${_inteldfp_lib}")
         set (_inc_dir "${_inteldfp_bid_conf_h_dir}")
      elseif (_libdfp_lib AND _libdfp_dfp_math_h)
         # Use libdfp:
         message (CHECK_PASS "Using libdfp: ${_libdfp_lib}")
         set (_lib "${_libdfp_lib}")
         # We want to add the 'dfp/' directory as an include-dir, so it intercepts
         # the default stdlib headers:
         get_filename_component (_inc_dir "${_libdfp_dfp_math_h}" DIRECTORY)
      else ()
         # Nope:
         message (CHECK_FAIL "No decimal floating-point library was found.")
         message (SEND_ERROR "Failed to import a decimal floating-point library from the system")
      endif ()

      set (_MONGOCRYPT_SYSTEM_DFP_LIB "${_lib}" CACHE PATH "System DFP library to use")
      set (_MONGOCRYPT_SYSTEM_DFP_INCLUDE_DIR "${_inc_dir}" CACHE PATH "include-search-dir for the system DFP library")
      mark_as_advanced (_MONGOCRYPT_SYSTEM_DFP_LIB _MONGOCRYPT_SYSTEM_DFP_INCLUDE_DIR)
   endif ()

   add_library (_mongocrypt::system-dfp UNKNOWN IMPORTED)
   set_target_properties (
      _mongocrypt::system-dfp PROPERTIES
      IMPORTED_LOCATION "${_MONGOCRYPT_SYSTEM_DFP_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "${_MONGOCRYPT_SYSTEM_DFP_INCLUDE_DIR}"
      )
endfunction ()

# This library is used to pivot the used DFP library at configure/find_package time:
add_library (_mongocrypt-dfp INTERFACE)
add_library (mongocrypt::dfp ALIAS _mongocrypt-dfp)
install (TARGETS _mongocrypt-dfp EXPORT mongocrypt_targets)

if (NOT DEFINED MONGOCRYPT_DFP_DIR)
   # The user did not provide a MONGOCRYPT_DFP_DIR, so we'll set one up
   include (IntelDFP)
elseif (MONGOCRYPT_DFP_DIR STREQUAL "USE-SYSTEM")
   message (STATUS "NOTE: Using system-wide DFP library. This is intended only for package maintainers.")

   # Do the import in a function to isolate variable scope
   _import_dfp ()

   # Link to the import target for the system's DFP library.
   # mongocrypt-config.cmake will later add a matching IMPORTED target
   # for downstream users during find_package()
   target_link_libraries (_mongocrypt-dfp INTERFACE _mongocrypt::system-dfp)
   # Hints for mongocrypt-config.cmake:
   set (USE_SYSTEM_DFP "ON")
   get_target_property (_loc _mongocrypt::system-dfp IMPORTED_LOCATION)
   get_filename_component (SYSTEM_DFP_FILENAME "${_loc}" NAME)
endif ()
