#[[
   This file handles importing the DFP (decimal floating point) library for decimal128 support. It
   is patterned after ImportBSON in this same directory.

   Initially, the only supported DFP implementation is Intel DFP. However, this module will allow
   for the future addition of support for libdfp.

   This file defines, exports, and installs one INTERFACE target: mongocrypt::intel_dfp.

   The target(s) from this file are used to link the DFP library correctly for the build
   configuration of libmongocrypt. At find_package() time, we can resolve these interface targets
   to link to the DFP library based on the build configurations of libmongocrypt.

   In the initial implementation both mongo::mongocrypt and mongo::mongocrypt_static must link to
   mongocrypt::intel_dfp (this is because if we link to the Intel DFP which is vendored with
   libmongocrypt then we will link the object files directly and if we use the system Intel DFP then
   we will be linking with .a static library archives).

   The default behavior is to use the Intel DFP which is vendored in this repository. By setting
   MONGOCRYPT_DFP_DIR=USE-SYSTEM the build will assume that an appropriate Intel DFP implementation
   can be found in a location where it has been installed system-wide (most likely under /usr or
   /usr/local).
]]

if (DEFINED MONGOCRYPT_DFP_DIR AND NOT MONGOCRYPT_DFP_DIR STREQUAL "USE-SYSTEM")
   message (FATAL_ERROR "The only valid value  for MONGOCRYPT_DFP_DIR is USE-SYSTEM")
endif ()

function (_import_dfp)
   find_library (_MONGOCRYPT_SYSTEM_INTEL_DFP_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}bidgcc000${CMAKE_STATIC_LIBRARY_SUFFIX}")
   find_path (_MONGOCRYPT_SYSTEM_INTEL_DFP_INCLUDE_DIR bid_conf.h)
   add_library (intel_dfp STATIC IMPORTED)
   set_target_properties (intel_dfp PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${_MONGOCRYPT_SYSTEM_INTEL_DFP_INCLUDE_DIR}"
      )
   set_property (TARGET intel_dfp PROPERTY IMPORTED_LOCATION "${_MONGOCRYPT_SYSTEM_INTEL_DFP_STATIC}")
   set_property (
      CACHE _MONGOCRYPT_SYSTEM_INTEL_DFP_INCLUDE_DIR
      PROPERTY ADVANCED
      TRUE
      )
endfunction ()

if (NOT DEFINED MONGOCRYPT_DFP_DIR)
   # The user did not provide a MONGOCRYPT_DFP_DIR, so we'll set one up
   include (IntelDFP)
elseif (MONGOCRYPT_DFP_DIR STREQUAL "USE-SYSTEM")
   message (STATUS "NOTE: Using system-wide Intel DFP library. This is intended only for package maintainers.")
   set (USE_SYSTEM_INTEL_DFP "ON")
   # Do the import in a function to isolate variable scope
   _import_dfp ()

   # Define interface targets to be used to control the DFP used at both build and import time.
   # Refer to mongocrypt-config.cmake to see how these targets are used by consumers
   add_library (_mongocrypt-intel_dfp INTERFACE)
   add_library (mongocrypt::intel_dfp ALIAS _mongocrypt-intel_dfp)
   install (
      TARGETS _mongocrypt-intel_dfp
      EXPORT mongocrypt_targets
      )

   # Link to Intel DFP, only exporting that usage for the local build tree.
   # The mongocrypt-config file will later add the appropriate link library for downstream
   # users during find_package()
   target_link_libraries (_mongocrypt-intel_dfp INTERFACE $<BUILD_INTERFACE:intel_dfp>)

endif ()

