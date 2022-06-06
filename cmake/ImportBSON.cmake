#[[
   This file defines, exports, and installs an INTERFACE target '_mongocrypt::libbson' that is used
   to link libbson correctly for the build configuration of libmongocrypt.

   If using the system's libbson, we want to use the system's libbson headers and link to the
   system's dynamic libbson. The generated _mongocrypt::libbson will define these usage
   requirements properly for transitive targets.

   If statically linking an embedded libbson project (the default), the '_mongocrypt::libbson' will
   link against the external libbson.
]]

set (init OFF)
if (DEFINED ENABLED_SHARED_BSON)
   message (STATUS "ENABLE_SHARED_BSON is now named USE_SHARED_LIBBSON")
   set (init "${ENABLE_SHARED_BSON}")
endif ()
option (USE_SHARED_LIBBSON "Dynamically link libbson (default is static)" ${init})

# Obtain a copy of libmongoc for libbson that we will use in libmongocrypt, and
# libmongoc for the csfle tests.
include (FetchContent OPTIONAL)

if (NOT DEFINED MONGOCRYPT_MONGOC_DIR)
   # Set the tag that we will fetch.
   set (MONGOC_FETCH_TAG_FOR_LIBBSON "1.17.0" CACHE STRING "The Git tag of mongo-c-driver that will be fetched to obtain libbson")
   # The user did not provide a MONGOCRYPT_MONGOC_DIR, so we'll get one
   if (NOT COMMAND FetchContent_Declare)
      # We need FetchContent in order to download the project.
      message (FATAL_ERROR
               "No MONGOCRYPT_MONGOC_DIR setting was defined, and the FetchContent.cmake "
               "module is not available. Upgrade your CMake version, or provide a "
               "MONGOCRYPT_MONGOC_DIR path to a mongo-c-driver directory (This is required "
               "for libmongocrypt to find a libbson to use and link against).")
   endif ()
   # Fetch the source archive for the requested tag from GitHub
   FetchContent_Declare (
      embedded_mcd
      URL "https://github.com/mongodb/mongo-c-driver/archive/refs/tags/${MONGOC_FETCH_TAG_FOR_LIBBSON}.tar.gz"
      )
   # Populate it:
   FetchContent_GetProperties(embedded_mcd)
   if (NOT embedded_mcd_POPULATED)
      message (STATUS "Downloading mongo-c-driver ${MONGOC_FETCH_TAG_FOR_LIBBSON} for libbson")
      FetchContent_Populate (embedded_mcd)
   endif ()
   # Store the directory path to the external mongoc project:
   get_filename_component (MONGOCRYPT_MONGOC_DIR "${embedded_mcd_SOURCE_DIR}" ABSOLUTE)
   # The project wants a VERSION_CURRENT file. We know that based on the tag.
   file (WRITE "${embedded_mcd_SOURCE_DIR}/VERSION_CURRENT" "${MONGOC_FETCH_TAG_FOR_LIBBSON}")
endif ()

message (STATUS "Using [${MONGOCRYPT_MONGOC_DIR}] as a sub-project for libbson")

# Disable AWS_AUTH, to prevent it from building the kms-message symbols, which we build ourselves
set (ENABLE_MONGODB_AWS_AUTH OFF)
# Disable install() for the libbson static library. We'll do it ourselves
set (ENABLE_STATIC BUILD_ONLY)
# Disable over-alignment of bson types
set (ENABLE_EXTRA_ALIGNMENT OFF)

# Add the subdirectory as a project. EXCLUDE_FROM_ALL to inhibit building and installing of components unless requested
add_subdirectory ("${MONGOCRYPT_MONGOC_DIR}" _mongo-c-driver EXCLUDE_FROM_ALL)

# Define an interface target to be used to pivot the used libbson at build and import time
add_library (_mongocrypt-libbson INTERFACE)
add_library (_mongocrypt::libbson ALIAS _mongocrypt-libbson)
install (TARGETS _mongocrypt-libbson EXPORT mongocrypt_targets)

# Link to the requested libbson, only exporting that usage for the local build tree.
# The mongocrypt-config file will later add the appropriate link library for downstream
# users.
set (_link_to $<IF:$<BOOL:${USE_SHARED_LIBBSON}>,bson_shared,bson_static>)
target_link_libraries (_mongocrypt-libbson INTERFACE $<BUILD_INTERFACE:${_link_to}>)

# And an alias to the mongoc target for use in some test cases
add_library (_mongocrypt::mongoc ALIAS mongoc_shared)
# Workaround: Embedded mongoc_shared does not set its INCLUDE_DIRECTORIES for user targets
target_include_directories (mongoc_shared
   PUBLIC
      "$<BUILD_INTERFACE:${MONGOCRYPT_MONGOC_DIR}/src/libmongoc/src>"
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/_mongo-c-driver/src/libmongoc/src/mongoc>"
   )

if (ENABLE_STATIC)
   # We want the static libbson target from the embedded mongoc. Enable the static library as
   # part of "all", and install the archive alongside the rest of our static libraries.
   # (Useful for some users for convenience of static-linking libmongocrypt: CDRIVER-3187)
   set_property (TARGET bson_static PROPERTY EXCLUDE_FROM_ALL FALSE)
   install (FILES $<TARGET_FILE:bson_static> DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif ()
