include (FetchContent)

# Set the tag that we will fetch.
# When updating the version of libbson, also update the version in etc/purls.txt and .evergreen/prep_c_driver_source.sh
set (MONGOC_FETCH_TAG_FOR_LIBBSON "2.1.0" CACHE STRING "The Git tag of mongo-c-driver that will be fetched to obtain libbson")

# Add an option to disable patching if a patch command is unavailable.
option (LIBBSON_PATCH_ENABLED "Whether to apply patches to the libbson library" ON)
set (patch_disabled OFF)
if (NOT LIBBSON_PATCH_ENABLED)
    set (patch_disabled ON)
endif ()

include (Patch)
make_patch_command (patch_command
    STRIP_COMPONENTS 1
    DIRECTORY "<SOURCE_DIR>"
    DISABLED "${patch_disabled}"
    PATCHES
        ${PROJECT_SOURCE_DIR}/etc/libbson-remove-GCC-diagnostic-pragma.patch
        ${PROJECT_SOURCE_DIR}/etc/mongo-common-test-harness.patch
    )

# Fetch the source archive for the requested tag from GitHub
FetchContent_Declare (
    embedded_mcd
    URL "https://github.com/mongodb/mongo-c-driver/archive/refs/tags/${MONGOC_FETCH_TAG_FOR_LIBBSON}.tar.gz"
    PATCH_COMMAND ${patch_command} --verbose
    SOURCE_SUBDIR "NO_ADD_SUBDIRECTORY" # add_subdirectory() is handled by ImportBSON.cmake.
    )
# Populate it:
FetchContent_GetProperties (embedded_mcd)
if (NOT embedded_mcd_POPULATED)
    message (STATUS "Downloading mongo-c-driver ${MONGOC_FETCH_TAG_FOR_LIBBSON} for libbson")
    if("${CMAKE_VERSION}" VERSION_LESS "3.18.0")
        # SOURCE_SUBDIR is not yet supported.
        FetchContent_Populate(embedded_mcd)
    else()
        FetchContent_MakeAvailable(embedded_mcd)
    endif()
endif ()
# Store the directory path to the external mongoc project:
get_filename_component (MONGOCRYPT_MONGOC_DIR "${embedded_mcd_SOURCE_DIR}" ABSOLUTE)
# The project wants a VERSION_CURRENT file. We know that based on the tag.
file (WRITE "${embedded_mcd_SOURCE_DIR}/VERSION_CURRENT" "${MONGOC_FETCH_TAG_FOR_LIBBSON}")
