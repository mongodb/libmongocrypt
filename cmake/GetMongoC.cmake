# Obtain a copy of libmongoc for libbson that we will use in libmongocrypt, and
# libmongoc for the csfle tests.
include (FetchContent OPTIONAL)

# Set the tag that we will fetch.
if (NOT DEFINED MONGOCRYPT_MONGOC_FETCH_TAG)
   set (MONGOCRYPT_MONGOC_FETCH_TAG "1.17.0")
endif ()

if (NOT DEFINED MONGOCRYPT_MONGOC_DIR)
   # The user did not provide a MONGOCRYPT_MONGOC_DIR, so we'll get one
   if (NOT COMMAND FetchContent_Declare)
      # We need FetchContent in order to download the project.
      message (FATAL_ERROR
               "No MONGOCRYPT_MONGOC_DIR setting was defined, and the FetchContent.cmake "
               "module is not available. Upgrade your CMake version, or provide a "
               "MONGOCRYPT_MONGOC_DIR path to a mongo-c-driver directory.")
   endif ()
   # Fetch the source archive for the requested tag from GitHub
   FetchContent_Declare (
      embedded_mcd
      URL "https://github.com/mongodb/mongo-c-driver/archive/refs/tags/${MONGOCRYPT_MONGOC_FETCH_TAG}.tar.gz"
      )
   # Populate it:
   FetchContent_GetProperties(embedded_mcd)
   if (NOT embedded_mcd_POPULATED)
      FetchContent_Populate (embedded_mcd)
   endif ()
   # Store the directory path to the external mongoc project:
   get_filename_component (MONGOCRYPT_MONGOC_DIR "${embedded_mcd_SOURCE_DIR}" ABSOLUTE)
   # The project wants a VERSION_CURRENT file. We know that based on the tag.
   file (WRITE "${embedded_mcd_SOURCE_DIR}/VERSION_CURRENT" "${MONGOCRYPT_MONGOC_FETCH_TAG}")
endif ()

# Disable AWS_AUTH, to prevent it from building the kms-message symbols, which we build ourselves
set (ENABLE_MONGODB_AWS_AUTH OFF)
# Disable install() for the libbson static library. We'll do it ourselves
set (ENABLE_STATIC BUILD_ONLY)
# Disable over-alignment of bson types
set (ENABLE_EXTRA_ALIGNMENT OFF CACHE BOOL "Toggle extra alignment in libbson")
# External mongo-c-driver does not build warning-free
if (MSVC)
   add_compile_options (/w)
else ()
   add_compile_options (-w)
endif ()
# Add the subdirectory as a project. EXCLUDE_FROM_ALL to inhibit building and installing of components unless requested
add_subdirectory ("${MONGOCRYPT_MONGOC_DIR}" _ext_mongoc EXCLUDE_FROM_ALL)

# Define an interface target to be used to pivot the used libbson at build and import time
add_library (_mongocrypt-libbson INTERFACE)
add_library (_mongocrypt::libbson ALIAS _mongocrypt-libbson)
install (TARGETS _mongocrypt-libbson EXPORT mongocrypt_targets)

# Link to the requested libbson, only exporting that usage for the local build tree.
# The mongocrypt-config file will later add the appropriate link library for downstream
# users.
if (ENABLE_SHARED_BSON)
   target_link_libraries (_mongocrypt-libbson INTERFACE $<BUILD_INTERFACE:bson_shared>)
else ()
   target_link_libraries (_mongocrypt-libbson INTERFACE $<BUILD_INTERFACE:bson_static>)
endif ()

# And an alias to the mongoc target for use in some test cases
add_library (_mongocrypt::mongoc ALIAS mongoc_shared)
# Workaround: Embedded mongoc_shared does not set its INCLUDE_DIRECTORIES for user targets
target_include_directories (mongoc_shared
   PUBLIC
      "$<BUILD_INTERFACE:${MONGOCRYPT_MONGOC_DIR}/src/libmongoc/src>"
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/_ext_mongoc/src/libmongoc/src/mongoc>"
   )

if (ENABLE_STATIC)
   # We want the static libbson target from the embedded mongoc. Enable the static library as
   # part of "all", and install the archive alongside the rest of our static libraries.
   # (Useful for some users for convenience of static-linking libmongocrypt: CDRIVER-3187)
   set_property (TARGET bson_static PROPERTY EXCLUDE_FROM_ALL FALSE)
   install (TARGETS bson_static ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif ()
