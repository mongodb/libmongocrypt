#[[
   This file defines, exports, and installs two INTERFACE targets: '_mongocrypt::libbson_for_static'
   and '_mongocrypt::libbson_for_shared', that are used to link libbson correctly for the build
   configuration of libmongocrypt. At find_package() time, we can resolve these interface targets
   to link to the appropriate libbson based on the build configurations of libmongocrypt.

   mongo::mongocrypt must link to _mongocrypt::libbson_for_shared, and mongo::mongocrypt_static must
   link to _mongocrypt::libbson_for_static.

   At configure+build time, these target will create BUILD_INTERFACE-only usage requirements
   appropriate for libmongocrypt to build against a libbson. Once these targets are installed,
   they retain no usage requirements defined here.

   Instead, the installed version of these targets will be manipulated in mongocrypt-config.cmake
   based on user settings and build configuration options of the installed libmongocrypt in order
   to ensure that users have satisfied the linking requirements of libmongocrypt.
   Refer to mongocrypt-config.cmake for more information

   This file calls add_subdirectory(EXCLUDE_FROM_ALL) on a mongo-c-driver project directory. This
   will expose libbson targets that we can link and use for the libmongocrypt build.

   The boolean option USE_SHARED_LIBBSON controls the behavior of libbson_for_shared:

   If USE_SHARED_LIBBSON=FALSE:

   - libbson_for_shared will transitively link the static libbson from the MONGOCRYPT_MONGOC_DIR.
   - The result is that mongo::mongocrypt (which is a SHARED library) will have the translation
     units of libbson directly embedded into the resulting binary.
   - The symbols from libbson that are merged into mongo::mongocrypt will be suppressed using
     linker scripts such that consumers of mongo::mongocrypt will not see the libbson symbols that
     were statically linked into the shared library. This allows consumers to link against a
     completely independent libbson without interfering with the libbson symbols that were merged
     into mongo::mongocrypt
   - The installed libbson_for_shared will have no usage requirements.

   If USE_SHARED_LIBBSON=TRUE:

   - libbson_for_shared will transitively use the shared libbson library from
     the MONGOCRYPT_MONGOC_DIR.
   - mongo::mongocrypt will be built with a dynamic link requirement on a libbson dynamic
     library, which must be resolved at runtime by consumers. The translation units from the
     MONGOCRYPT_MONGOC_DIR *will not* be included in the mongo::mongocrypt library.
   - The installed libbson_for_shared will dynamically link to a libbson on the user's system by
     using a find_library() call.

   In both of the above cases, libbson_for_static will require that the final consumer
   provide their own definitions of the libbson symbols, regardless of the value
   of USE_SHARED_LIBBSON.
]]

include (CheckCSourceCompiles)
include (CMakePushCheckState)

cmake_push_check_state ()
   # Even though we aren't going to use the system's libbson, try to detect whether it has
   # extra-alignment enabled. We want to match that setting as our default, for convenience
   # purposes only.
   find_path (SYSTEM_BSON_INCLUDE_DIR bson/bson.h PATH_SUFFIXES libbson-1.0)
   if (SYSTEM_BSON_INCLUDE_DIR AND NOT DEFINED ENABLE_EXTRA_ALIGNMENT)
      set (CMAKE_REQUIRED_INCLUDES "${SYSTEM_BSON_INCLUDE_DIR}")
      set (_extra_alignment_default OFF)
      check_c_source_compiles ([[
         #include <bson/bson.h>

         int main() { }
      ]] HAVE_SYSTEM_LIBBSON)

      if (HAVE_SYSTEM_LIBBSON)
         # We have a libbson, check for extra alignment
         check_c_source_compiles ([[
            #include <bson/bson.h>

            #ifndef BSON_EXTRA_ALIGN
            #error "Not extra-aligned"
            #endif

            int main() {}
         ]] SYSTEM_LIBBSON_IS_EXTRA_ALIGNED)
         if (SYSTEM_LIBBSON_IS_EXTRA_ALIGNED)
            # Extra aligned! We'll use extra alignment by default.
            set (_extra_alignment_default ON)
         endif ()
      endif ()
   endif ()
cmake_pop_check_state ()

set (init OFF)
if (DEFINED ENABLED_SHARED_BSON)
   message (STATUS "ENABLE_SHARED_BSON is now named USE_SHARED_LIBBSON")
   set (init "${ENABLE_SHARED_BSON}")
endif ()
option (USE_SHARED_LIBBSON "Dynamically link libbson for the libmongocrypt dynamic library (default is static)" ${init})

if (NOT DEFINED MONGOCRYPT_MONGOC_DIR)
   # The user did not provide a MONGOCRYPT_MONGOC_DIR, so we'll get one
   include (FetchContent OPTIONAL)
   if (NOT COMMAND FetchContent_Declare)
      # We need FetchContent in order to download the project.
      message (FATAL_ERROR
            "No MONGOCRYPT_MONGOC_DIR setting was defined, and the FetchContent.cmake "
            "module is not available. Upgrade your CMake version, or provide a "
            "MONGOCRYPT_MONGOC_DIR path to a mongo-c-driver directory (This is required "
            "for libmongocrypt to find a libbson to use and link against).")
   endif ()
   include (FetchMongoC)
   # The FetchMongoC module defines a MONGOCRYPT_MONGOC_DIR for us to use
endif ()

function (_import_bson)
   if (MONGOCRYPT_MONGOC_DIR STREQUAL "USE-SYSTEM" AND USE_SHARED_LIBBSON AND NOT ENABLE_ONLINE_TESTS)
      message (STATUS "NOTE: Using system-wide libbson library. This is intended only for package maintainers.")
      find_library (_MONGOCRYPT_SYSTEM_LIBBSON_SHARED "${CMAKE_SHARED_LIBRARY_PREFIX}bson-1.0${CMAKE_SHARED_LIBRARY_SUFFIX}")
      find_library (_MONGOCRYPT_SYSTEM_LIBBSON_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}bson-static-1.0${CMAKE_STATIC_LIBRARY_SUFFIX}")
      find_path (_MONGOCRYPT_SYSTEM_LIBBSON_INCLUDE_DIR bson/bson.h PATH_SUFFIXES libbson-1.0)
      add_library (bson_shared SHARED IMPORTED)
      add_library (bson_static STATIC IMPORTED)
      set_target_properties (bson_shared bson_static PROPERTIES
         IMPORTED_CONFIGURATIONS "Release"
         INTERFACE_INCLUDE_DIRECTORIES "${_MONGOCRYPT_SYSTEM_LIBBSON_INCLUDE_DIR}"
         )
      set_property (TARGET bson_shared PROPERTY IMPORTED_LOCATION "${_MONGOCRYPT_SYSTEM_LIBBSON_SHARED}")
      set_property (TARGET bson_static PROPERTY IMPORTED_LOCATION "${_MONGOCRYPT_SYSTEM_LIBBSON_STATIC}")
      set_property (
         CACHE _MONGOCRYPT_SYSTEM_LIBBSON_SHARED
               _MONGOCRYPT_SYSTEM_LIBBSON_INCLUDE_DIR
         PROPERTY ADVANCED
         TRUE
      )
   else ()
      message (STATUS "Using [${MONGOCRYPT_MONGOC_DIR}] as a sub-project for libbson")
      # Disable AWS_AUTH, to prevent it from building the kms-message symbols, which we build ourselves
      set (ENABLE_MONGODB_AWS_AUTH OFF CACHE BOOL "Disable kms-message content in mongoc for libmongocrypt" FORCE)
      # Disable install() for the libbson static library. We'll do it ourselves
      set (ENABLE_STATIC BUILD_ONLY)
      # Disable libzstd, which isn't necessary for libmongocrypt and isn't necessarily available.
      set (ENABLE_ZSTD OFF CACHE BOOL "Toggle libzstd for the mongoc subproject (not required by libmongocrypt)")
      # Disable snappy, which isn't necessary for libmongocrypt and isn't necessarily available.
      set (ENABLE_SNAPPY OFF CACHE BOOL "Toggle snappy for the mongoc subproject (not required by libmongocrypt)")
      # Disable deprecated automatic init and cleanup. (May be overridden by the user)
      set (ENABLE_AUTOMATIC_INIT_AND_CLEANUP OFF CACHE BOOL "Enable automatic init and cleanup (GCC only)")
      # Disable over-alignment of bson types. (May be overridden by the user)
      set (ENABLE_EXTRA_ALIGNMENT ${_extra_alignment_default} CACHE BOOL "Toggle extra alignment of bson_t")
      # We don't want the subproject to find libmongocrypt
      set (ENABLE_CLIENT_SIDE_ENCRYPTION OFF CACHE BOOL "Disable client-side encryption for the libmongoc subproject")
      # Clear `BUILD_VERSION` so C driver does not use a `BUILD_VERSION` meant for libmongocrypt.
      # Both libmongocrypt and C driver support setting a `BUILD_VERSION` to override the version.
      if (DEFINED CACHE{BUILD_VERSION})
         set (saved_cached_build_version "${BUILD_VERSION}")
         unset (BUILD_VERSION CACHE) # Undefine cache variable.
      endif ()
      if (DEFINED BUILD_VERSION)
         set (saved_build_version "${BUILD_VERSION}")
         unset (BUILD_VERSION) # Undefine normal variable.
      endif ()
      # Disable building tests in C driver:
      set (ENABLE_TESTS OFF)
      set (BUILD_TESTING OFF)
      # Disable counters in C driver. Counters are not supported on all platforms.
      set (ENABLE_SHM_COUNTERS OFF)
      # Add the subdirectory as a project. EXCLUDE_FROM_ALL to inhibit building and installing of components unless requested
      # SYSTEM (on applicable CMake versions) to prevent warnings (particularly from -Wconversion/-Wsign-conversion) from the C driver code
      if (CMAKE_VERSION VERSION_GREATER 3.25)
         add_subdirectory ("${MONGOCRYPT_MONGOC_DIR}" _mongo-c-driver EXCLUDE_FROM_ALL SYSTEM)
      else ()
         add_subdirectory ("${MONGOCRYPT_MONGOC_DIR}" _mongo-c-driver EXCLUDE_FROM_ALL)
      endif ()
      if (DEFINED saved_cached_build_version)
         set (BUILD_VERSION "${saved_cached_build_version}" CACHE STRING "Library version")
      endif ()
      if (DEFINED saved_build_version)
         set (BUILD_VERSION "${saved_build_version}")
      endif ()
      if (TARGET mongoc_static)
         # Workaround: Embedded mongoc_static does not set its INCLUDE_DIRECTORIES for user targets
         target_include_directories (mongoc_static
            PUBLIC
               "$<BUILD_INTERFACE:${MONGOCRYPT_MONGOC_DIR}/src/libmongoc/src>"
               "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/_mongo-c-driver/src/libmongoc/src/mongoc>"
            )
      endif ()
   endif ()
endfunction ()

# Do the import in a function to isolate variable scope
_import_bson ()

# Define interface targets to be used to control the libbson used at both build and import time.
# Refer to mongocrypt-config.cmake to see how these targets are used by consumers
add_library (_mongocrypt-libbson_for_static INTERFACE)
add_library (_mongocrypt-libbson_for_shared INTERFACE)
add_library (_mongocrypt::libbson_for_static ALIAS _mongocrypt-libbson_for_static)
add_library (_mongocrypt::libbson_for_shared ALIAS _mongocrypt-libbson_for_shared)
install (
   TARGETS _mongocrypt-libbson_for_static _mongocrypt-libbson_for_shared
   EXPORT mongocrypt_targets
)

# Link to the requested libbson, only exporting that usage for the local build tree.
# The mongocrypt-config file will later add the appropriate link library for downstream
# users during find_package()
if (USE_SHARED_LIBBSON)
   target_link_libraries (_mongocrypt-libbson_for_shared INTERFACE $<BUILD_INTERFACE:bson_shared>)
else ()
   target_link_libraries (_mongocrypt-libbson_for_shared INTERFACE $<BUILD_INTERFACE:bson_static>)
endif ()
# libbson_for_static always links to the static libbson:
target_link_libraries (_mongocrypt-libbson_for_static INTERFACE $<BUILD_INTERFACE:bson_static>)

if (TARGET mongoc_static)
   # And an alias to the mongoc target for use in some test cases
   add_library (_mongocrypt::mongoc ALIAS mongoc_static)
endif ()

# Put the libbson dynamic library into the current binary directory (plus possible config suffix).
# This ensures that libbson DLL will resolve on Windows when it searches during tests
set_property (TARGET bson_shared PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

if (ENABLE_STATIC)
   # We are going to build a static libmongocrypt.
   # We want the static libbson target from the embedded mongoc. Enable the static library as
   # part of "all", and install the archive alongside the rest of our static libraries.
   # (Useful for some users for convenience of static-linking libmongocrypt: CDRIVER-3187)
   set_target_properties (bson_static PROPERTIES
      EXCLUDE_FROM_ALL FALSE
      OUTPUT_NAME bson-static-for-libmongocrypt
      )
   install (
      FILES $<TARGET_FILE:bson_static>
      DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      RENAME ${CMAKE_STATIC_LIBRARY_PREFIX}bson-static-for-libmongocrypt${CMAKE_STATIC_LIBRARY_SUFFIX}
      )
endif ()
