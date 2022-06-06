#[[
   This file defines, exports, and installs two INTERFACE targets: '_mongocrypt::libbson_for_static'
   and '_mongocrypt::libbson_for_shared', that are used to link libbson correctly for the build
   configuration of libmongocrypt.

   mongo::mongocrypt must link to _mongocrypt::libbson_for_shared, and mongo::mongocrypt_static must
   link to _mongocrypt::libbson_for_static.

   These target will create BUILD_INTERFACE-only usage requirements appropriate for libmongocrypt to
   build against a libbson. The installed version of these targets will be manipulated in
   mongocrypt-config.cmake based on user settings and build configuration options.

   This file calls add_subdirectory(EXCLUDE_FROM_ALL) on a mongo-c-driver project directory. This
   will expose a bson_static target that we then link into _mongocrypt::libbson_*.

   The boolean option USE_SHARED_LIBBSON controls the behavior of libbson_for_shared:

   If USE_SHARED_LIBBSON=FALSE:

   - libbson_for_shared will transitively link the static libbson from the MONGOCRYPT_MONGOC_DIR.
   - The result is that mongo::mongocrypt (which is a SHARED library) will have the translation
     units of libbson directly embedded into the resulting binary.
   - The symbols from libbson that are merged into mongo::mongocrypt will be supressed using
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
     using a find library.

   In both of the above cases, libbson_for_static will require that the final consumer
   provide their own definitions of the libbson symbols, regardless of the value
   of USE_SHARED_LIBBSON.
]]

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
   # The FetchMongoC module defines a MONGOCRYPT_MONGOC_DIR for use to use
endif ()

message (STATUS "Using [${MONGOCRYPT_MONGOC_DIR}] as a sub-project for libbson")

function (_import_bson_add_subdir)
   # Disable AWS_AUTH, to prevent it from building the kms-message symbols, which we build ourselves
   set (ENABLE_MONGODB_AWS_AUTH OFF)
   # Disable install() for the libbson static library. We'll do it ourselves
   set (ENABLE_STATIC BUILD_ONLY)
   # Disable over-alignment of bson types
   set (ENABLE_EXTRA_ALIGNMENT OFF)

   # Add the subdirectory as a project. EXCLUDE_FROM_ALL to inhibit building and installing of components unless requested
   add_subdirectory ("${MONGOCRYPT_MONGOC_DIR}" _mongo-c-driver EXCLUDE_FROM_ALL)
endfunction ()

# Do the add_subdirectory() in a function to isolate variable scope
_import_bson_add_subdir ()

# Define an interface target to be used to pivot the used libbson at build and import time
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
target_link_libraries (_mongocrypt-libbson_for_static INTERFACE $<BUILD_INTERFACE:bson_static>)

# And an alias to the mongoc target for use in some test cases
add_library (_mongocrypt::mongoc ALIAS mongoc_shared)
# Workaround: Embedded mongoc_shared does not set its INCLUDE_DIRECTORIES for user targets
target_include_directories (mongoc_shared
   PUBLIC
      "$<BUILD_INTERFACE:${MONGOCRYPT_MONGOC_DIR}/src/libmongoc/src>"
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/_mongo-c-driver/src/libmongoc/src/mongoc>"
   )

if (ENABLE_STATIC)
   # We are going to build a static libmongocrypt.
   # We want the static libbson target from the embedded mongoc. Enable the static library as
   # part of "all", and install the archive alongside the rest of our static libraries.
   # (Useful for some users for convenience of static-linking libmongocrypt: CDRIVER-3187)
   set_property (TARGET bson_static PROPERTY EXCLUDE_FROM_ALL FALSE)
   install (FILES $<TARGET_FILE:bson_static> DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif ()
