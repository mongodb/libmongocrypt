# Try to find a variable named 'varname' in the local scope, or as an environment variable.
# If unset, defines 'varname' to the value of ${ARGN}
function (_getvar varname)
    if (DEFINED "${varname}")
        return ()
    endif()
    if (DEFINED "ENV{${varname}}")
        set ("${varname}" "$ENV{${varname}}" PARENT_SCOPE)
        message (STATUS "Using ${varname} from environment for getting CSFLE (Value \"${${varname}}\")")
    endif ()
    set ("${varname}" "${ARGN}" PARENT_SCOPE)
endfunction ()

# Set the MongoDB server commit from which we will pull a CSFLE binary
_getvar (CSFLE_COMMIT "1938ca8564fb969f68058d68c55f632eec78a665")
# The version we will download:
_getvar (CSFLE_VERSION "5.3.0-alpha2")
# The source branch:
_getvar (CSFLE_BRANCH "master")
# The build number:
_getvar (CSFLE_BUILDNUM "47")

# Generate the filename suffix
string (SUBSTRING "g${CSFLE_COMMIT}" 0 8 _suffix)
if (WIN32)
    set (_ext ".zip")
    set (_runtime_lib_dir "bin")
else ()
    set (_ext ".tgz")
    set (_runtime_lib_dir "lib")
endif ()

if (EXISTS "/etc/lsb-release" OR EXISTS "/etc/redhat-release")
    # Get a Linux binary that is reasonable ABI compatible with our platforms under test
    set (_task "enterprise-rhel-80-64-bit-dynamic-required")
elseif (WIN32)
    set (_task "enterprise-windows-required")
elseif (APPLE)
    set (_task "enterprise-macos-arm64")
else ()
    if (NOT DEFINE DCSFLE_FROM_TASK)
        message (WARNING "No CSFLE task already known for this platform.")
    endif ()
endif ()

_getvar (CSFLE_FROM_TASK "${_task}")
_getvar (CSFLE_FILENAME_EXT "${_ext}")
_getvar (CSFLE_FILENAME "mongo_csfle_v1-${CSFLE_VERSION}-${CSFLE_BUILDNUM}-${_suffix}${CSFLE_FILENAME_EXT}")

_getvar (CSFLE_URL "https://mciuploads.s3.amazonaws.com/mongodb-mongo-${CSFLE_BRANCH}/mongo_csfle/${CSFLE_FROM_TASK}/${CSFLE_COMMIT}/${CSFLE_FILENAME}")

string (MD5 _url_hash "${CSFLE_URL}")
string (SUBSTRING "${_url_hash}" 0 5 _hash_part)
get_filename_component(CSFLE_LOCAL_FILE "${CMAKE_CURRENT_BINARY_DIR}/csfle-${_hash_part}${CSFLE_FILENAME_EXT}" ABSOLUTE)

if (NOT EXISTS "${CSFLE_LOCAL_FILE}")
    message (STATUS "Downloading CSFLE for use in testing from ${CSFLE_URL}")
    file (DOWNLOAD "${CSFLE_URL}" "${CSFLE_LOCAL_FILE}.tmp"
        SHOW_PROGRESS
        STATUS result
        LOG log
        )
    list (GET result 0 rc)
    list (GET result 1 message)
    if (rc)
        message (FATAL_ERROR "Failure while downloading CSFLE: ${message} [${rc}]:\n${log}")
    endif ()
    file (RENAME "${CSFLE_LOCAL_FILE}.tmp" "${CSFLE_LOCAL_FILE}")
    message (STATUS "Local archive written: ${CSFLE_LOCAL_FILE}")
endif ()

_getvar (CSFLE_LIBRARY_NAME "mongo_csfle_v1${CMAKE_SHARED_LIBRARY_SUFFIX}")
_getvar (CSFLE_ARCHIVE_SUBDIR "${_runtime_lib_dir}")

get_filename_component (_copy_stamp "${CMAKE_CURRENT_BINARY_DIR}/csfle-copied.stamp" ABSOLUTE)

add_custom_command (
    OUTPUT "${_copy_stamp}"
    DEPENDS "${CSFLE_LOCAL_FILE}"
    COMMAND
        "${CMAKE_COMMAND}" -E tar xf "${CSFLE_LOCAL_FILE}" "${CSFLE_ARCHIVE_SUBDIR}/${CSFLE_LIBRARY_NAME}"
    COMMAND
        "${CMAKE_COMMAND}" -E rename "${CSFLE_ARCHIVE_SUBDIR}/${CSFLE_LIBRARY_NAME}" "$<TARGET_FILE_DIR:${CSFLE_GET_FOR_TARGET}>/${CSFLE_LIBRARY_NAME}"
    COMMAND
        "${CMAKE_COMMAND}" -E touch "${_copy_stamp}"
    COMMENT "Extracting CSFLE library"
    )

add_custom_target (extract-csfle ALL DEPENDS "${_copy_stamp}" "${CSFLE_GET_FOR_TARGET}")
