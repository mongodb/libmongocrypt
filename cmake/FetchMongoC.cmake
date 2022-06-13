include (FetchContent)

# Set the tag that we will fetch.
set (MONGOC_FETCH_TAG_FOR_LIBBSON "1.17.3" CACHE STRING "The Git tag of mongo-c-driver that will be fetched to obtain libbson")

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
