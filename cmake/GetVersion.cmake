# Defines a function to get the version (possibly suffixed with prerelease info)
# from git history.
#
# This may be run as an independent script, like so:
# cmake -DRELEASE_BRANCH_REF=origin/r1.5 -P ./cmake/GetVersion.cmake
# And the computed version is printed to stderr (since printing to stdout with
# cmake's "message" function would prefix with "-- ")
#
# Note that specifying -DRELEASE_BRANCH_REF=origin/r1.5 tells the script to base
# its version calculation on that particular branch.  It should point to the
# latest available release branch.  This is necessary to ensure that calling the
# script while checked out to a branch other than the latest release branch
# returns a sensible version number.  Put more concretely, given the latest
# release branch as origin/r1.5, running this script while checked out on the
# master branch will return a version number like 1.6.0-dev+...
#
# The general approach of this function is to produce a sequence of versions
# which distinguish between development versions, release candidates, prerelease
# builds which fall between release candidates, and actual releases.  This
# sequence might look approximately like:
#
# tag:1.0.0 [commit with release tag]
# 1.0.1-dev+20191107git12345 [subsequent untagged commits after release tag]
# tag:1.0.1-rc0 [first candidate for next release]
# 1.0.1-pre1+20191108git23456 [subsequent untagged commits after RC]
# tag:1.0.1-rc1 [second candidate for next release]
# 1.0.1-pre2+20191109git34567 [subsequent untagged commits after RC]
# tag:1.0.1-rc2 [third candidate for next release]
# tag:1.0.1 [commit with release tag]
#
# Note that some of these may be skipped along the way, depending on what ends
# up being included in a particular release cycle.
#
function (GetVersion OUTVAR)
    # First we check "git describe" against the currently checked out commit,
    # so that if it is tagged we pick that up
    execute_process (
        COMMAND git describe --tags --match "1.*"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE LOCAL_VERSION_WITH_SUFFIX
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git describe' failed: '${GIT_ERROR}'")
    endif ()

    execute_process (
        COMMAND git describe --tags --abbrev=0 --match "1.*"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE LOCAL_VERSION
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git describe' failed: '${GIT_ERROR}'")
    endif ()

    # If "git describe --abbrev=0" has the same result as "git describe", then the current commit
    # is tagged, so return that.
    if (LOCAL_VERSION STREQUAL LOCAL_VERSION_WITH_SUFFIX)
            set (${OUTVAR} ${LOCAL_VERSION} PARENT_SCOPE)
        return ()
    endif ()

    # Next we check "git describe" against the specified branch reference, so
    # we are certain to get a version at least as high as the last release tag
    execute_process (
        COMMAND git describe --tags --match "1.*" ${RELEASE_BRANCH_REF}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE VERSION_WITH_SUFFIX
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git describe' failed: '${GIT_ERROR}'")
    endif ()

    execute_process (
        COMMAND git describe --tags --abbrev=0 --match "1.*" ${RELEASE_BRANCH_REF}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
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

    # Otherwise, construct a version based on the next release version
    execute_process (
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE CURRENT_BRANCH
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine branch: 'git rev-parse' failed: '${GIT_ERROR}'")
    endif ()


    # A list of version components separated by dots and dashes: "1.0.0-[prerelease-marker]"
    string (REGEX MATCHALL "[^.-]+" VERSION_PARTS ${VERSION})

    list (LENGTH VERSION_PARTS VERSION_LENGTH)
    list (GET VERSION_PARTS 0 MAJOR_VERSION)
    list (GET VERSION_PARTS 1 MINOR_VERSION)
    list (GET VERSION_PARTS 2 PATCH_VERSION)
    set (PRERELEASE_VERSION "")
    if (CURRENT_BRANCH STREQUAL "master")
        # We need a version in the next minor sequence
        math (EXPR MINOR_VERSION "${MINOR_VERSION} + 1")
        set (PATCH_VERSION "0")
        set (PRERELEASE_VERSION "-dev")
    elseif (VERSION_LENGTH GREATER 3)
        # The version we are starting with is already a pre-release of the next
        list (GET VERSION_PARTS 3 PRERELEASE_VERSION)
        string (REGEX MATCHALL "(alpha|beta|rc|[0-9]+)" PRERELEASE_PARTS ${PRERELEASE_VERSION})
        list (LENGTH PRERELEASE_PARTS PRERELEASE_LENGTH)
        if (PRERELEASE_LENGTH EQUAL 2)
            list (GET PRERELEASE_PARTS 0 PRE_PT_ONE)
            list (GET PRERELEASE_PARTS 1 PRE_PT_TWO)
            math (EXPR PRE_PT_TWO "${PRE_PT_TWO} + 1")
            set (PRERELEASE_VERSION "-pre${PRE_PT_TWO}")
        else ()
        endif ()
    else ()
        # The version we are starting with is the last release, so we increment
        # the patch component to get the next version
        math (EXPR PATCH_VERSION "${PATCH_VERSION} + 1")
        set (PRERELEASE_VERSION "-dev")
    endif ()
    set (VERSION "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}${PRERELEASE_VERSION}")

    # Append our custom suffix +<date>git<short hash>
    execute_process (
        COMMAND git rev-parse --revs-only --short=10 HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE SUFFIX_SHA
        RESULT_VARIABLE GIT_STATUS
        ERROR_VARIABLE GIT_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT GIT_STATUS STREQUAL 0)
        message (FATAL_ERROR "Unable to determine version: 'git rev-parse' failed: '${GIT_ERROR}'")
    endif ()

    string (TIMESTAMP SUFFIX_DATE "%Y%m%d")

    set (${OUTVAR} "${VERSION}+${SUFFIX_DATE}git${SUFFIX_SHA}" PARENT_SCOPE)

endfunction (GetVersion)

if (CMAKE_SCRIPT_MODE_FILE)
    GetVersion (MONGOCRYPT_VERSION)
    message (${MONGOCRYPT_VERSION})
endif ()
