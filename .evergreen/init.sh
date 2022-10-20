#!/bin/bash

# Initial variables and helper functions for the libmongocrypt build

## Variables set by this file:

# EVG_DIR = The path to the directory containing this script file
# LIBMONGOCRYPT_DIR = The path to the libmongocrypt source directory
# OS_NAME = One of 'windows', 'linux', 'macos', or 'unknown'

## (All of the above directory paths are native absolute paths)

## This script defines the following commands:

# * abspath <path>
#       Convert a given path into an absolute path. Relative paths are
#       resolved relative to the working directory.
#
# * have_command <command>
#       Return zero if <command> is the name of a command that can be executed,
#       returns non-zero otherwise.
#
# * run_chdir <dirpath> <command> [args ...]
#       Run the given command with a working directory given by <dirpath>
#
# * log <message>
#       Print <message> to stderr
#
# * fail <message>
#       Print <message> to stderr and return non-zero
#
# * native_path <path>
#       On MinGW/Cygwin/MSYS, convert the given Cygwin path to a Windows-native
#       path. NOTE: the MinGW runtime will almost always automatically convert
#       filepaths automatically when passed to non-MinGW programs, so this
#       utility is not usually needed.

set -o errexit
set -o pipefail
set -o nounset

# Inhibit msys path conversion
export MSYS2_ARG_CONV_EXCL="*"

if test "${TRACE:-0}" != "0"; then
    set -o xtrace
fi

# Write a message to stderr
function log() {
    echo "${@}" 1>&2
    return 0
}

function debug() {
    if test "${DEBUG:-0}" != "0"; then
        log "${@}"
    fi
}

# Print a message and return non-zero
function fail() {
    log "${@}"
    return 1
}

# Determine whether we can execute the given name as a command
function have_command() {
    test "$#" -eq 1 || fail "have_command expects a single argument"
    if type "${1}" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Run a command in a different directory:
# * run_chdir <dir> [command ...]
function run_chdir() {
    test "$#" -gt 1 || fail "run_chdir expects at least two arguments"
    local _dir="$1"
    shift
    pushd "$_dir" > /dev/null
    debug "Run in directory [$_dir]:" "$@"
    "$@"
    local _rc=$?
    popd > /dev/null
    return $_rc
}

# Given a path string, convert it to an absolute path with no redundant components or directory separators
function abspath() {
    test "$#" -eq 1 || fail "abspath expects a single argument"
    local ret
    local arg="$1"
    debug "Resolve path [$arg]"
    # The parent path:
    local _parent
    _parent="$(dirname "$arg")"
    # The filename part:
    local _fname
    _fname="$(basename "$arg")"
    # There are four cases to consider from dirname:
    if test "$_parent" = "."; then  # The parent is '.' as in './foo'
        # Replace the leading '.' with the working directory
        _parent="$PWD"
    elif test "$_parent" = ".."; then  # The parent is '..' as in '../foo'
        # Replace a leading '..' with the parent of the working directory
        _parent="$(dirname "$PWD")"
    elif test "$arg" = "$_parent"; then  # The parent is itself, as in '/'
        # A root directory is its own parent according to 'dirname'
        printf %s "$arg"
        return 0
    else  # The parent is some other path, like 'foo' in 'foo/bar'
        # Resolve the parent path
        _parent="$(set +x; DEBUG=0 abspath "$_parent")"
    fi
    # At this point $_parent is an absolute path
    if test "$_fname" = ".."; then
        # Strip one component
        ret="$(dirname "$_parent")"
    elif test "$_fname" = "."; then
        # Drop a '.' at the end of a path
        ret="$_parent"
    else
        # Join the result
        ret="$_parent/$_fname"
    fi
    # Remove duplicate dir separators
    while [[ "$ret" =~ "//" ]]; do
        ret="${ret//\/\///}"
    done
    debug "Resolved to: [$arg] -> [$ret]"
    printf %s "$ret"
}

# Get the platform name: One of 'windows', 'macos', 'linux', or 'unknown'
function os_name() {
    have_command uname || fail "No 'uname' executable found"

    debug "Uname is [$(uname -a)]"
    local _uname
    _uname="$(uname | tr '[:upper:]' '[:lower:]')"
    local _os_name="unknown"

    if [[ "$_uname" =~ .*cywin|windows|mingw|msys.* ]] || have_command cmd.exe; then
        _os_name="windows"
    elif test "$_uname" = 'darwin'; then
        _os_name='macos'
    elif test "$_uname" = 'linux'; then
        _os_name='linux'
    fi

    printf %s "$_os_name"
}

# Ensure the given path is in a native format (converts cygwin paths to Windows-local paths)
function native_path() {
    test "$#" -eq 1 || fail "native_path expects one argument"
    if test "$OS_NAME" = "windows"; then
        have_command cygpath || fail "No 'cygpath' command is available, but we require it to normalize file paths."
        debug "Convert path [$1]"
        local r
        r="$(cygpath -w "$1")"
        debug "Convert to [$r]"
        printf %s "$r"
    else
        printf %s "$1"
    fi
}

# Join the given arguments with the given joiner string. Writes to stdout
# Usage: join_str <joiner> [argv [...]]
function join_str() {
    local joiner first
    joiner="$1"
    first="${2-}"
    if shift 2; then
        # Print each element. Do a string-replace of the beginning of each
        # subsequent string with the joiner.
        printf "%s" "$first" "${@/#/$joiner}"
    fi
}

OS_NAME="$(os_name)"

_init_sh_this_file="$(abspath "${BASH_SOURCE[0]}")"
_init_sh_evg_dir="$(dirname "${_init_sh_this_file}")"

# Get the EVG dir as a native absolute path. All other path vars are derived from
# this one, and will therefore remain as native paths
EVG_DIR="$(native_path "${_init_sh_evg_dir}")"
LIBMONGOCRYPT_DIR="$(dirname "${EVG_DIR}")"

# Executes CMake via the cache-managing script
run_cmake() {
    command bash "$EVG_DIR/cmake.sh" "$@"
}

# Executes CTest via the cache-managing script
run_ctest() {
    command bash "$EVG_DIR/ctest.sh" "$@"
}

EXE_SUFFIX=""
if test "$OS_NAME" = "windows"; then
    EXE_SUFFIX=".exe"
fi

if test "${USER_CACHES_DIR:=${XDG_CACHE_HOME:-}}" = ""; then
    case "$OS_NAME" in
    linux)
        USER_CACHES_DIR=$HOME/.cache
        ;;
    macos)
        USER_CACHES_DIR=$HOME/Library/Caches
        ;;
    windows)
        USER_CACHES_DIR=${LOCALAPPDATA:-$USERPROFILE/.cache}
        ;;
    *)
        log "Using ~/.cache as fallback user caching directory"
        USER_CACHES_DIR="$(abspath ~/.cache)"
    esac
fi

# Ensure we are dealing with a complete path
USER_CACHES_DIR="$(abspath "$USER_CACHES_DIR")"

: "${BUILD_CACHE_BUST:=1}"
: "${BUILD_CACHE_DIR:="$USER_CACHES_DIR/libmongocrypt/build.$BUILD_CACHE_BUST"}"

# Silence shellcheck:
: "$LIBMONGOCRYPT_DIR,$EXE_SUFFIX"
