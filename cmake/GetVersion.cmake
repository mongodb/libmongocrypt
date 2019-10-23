# Defines a function to get the version (possibly suffixed with prerelease info)
# from git history.
#
# This may be run as an independent script, like so:
# cmake -P ./cmake/GetVersion.cmake
# And the computed version is printed to stderr (since printing to stdout with
# cmake's "message" function would prefix with "-- ")
function (GetVersion OUTVAR)
    execute_process (
        COMMAND git describe --tags --match "1.*"
        OUTPUT_VARIABLE VERSION_WITH_SUFFIX
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git describe' failed: '${GIT_ERROR}'")
    endif ()

    execute_process (
        COMMAND git describe --tags --abbrev=0 --match "1.*"
        OUTPUT_VARIABLE VERSION
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git describe' failed: '${GIT_ERROR}'")
    endif ()

    # If "git describe --abbrev=0" has the same result as "git describe", then the current commit
    # is tagged, so return that.
    if (VERSION STREQUAL VERSION_WITH_SUFFIX)
        set (${OUTVAR} ${VERSION} PARENT_SCOPE)
        return ()
    endif ()

    # Otherwise, append our custom suffix -<date>-git<short hash>
    execute_process (
        COMMAND git rev-parse --revs-only --short=10 HEAD^{commit}
        OUTPUT_VARIABLE SUFFIX_SHA
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git describe' failed: '${GIT_ERROR}'")
    endif ()

    string (TIMESTAMP SUFFIX_DATE "%Y%m%d")

    set (${OUTVAR} "${VERSION}+${SUFFIX_DATE}git${SUFFIX_SHA}" PARENT_SCOPE)

endfunction (GetVersion)

if (CMAKE_SCRIPT_MODE_FILE)
    GetVersion (MONGOCRYPT_VERSION)
    message (${MONGOCRYPT_VERSION})
endif ()