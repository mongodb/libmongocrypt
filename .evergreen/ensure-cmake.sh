#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

# The version that we will attempt to obtain:
: "${CMAKE_VERSION:=3.21.4}"

# Root of all cached versions
: "${CMAKE_CACHES_ROOT:="$BUILD_CACHE_DIR/cmake"}"
# Cache directory for this particular version:
: "${CMAKE_CACHE_DIR:="$CMAKE_CACHES_ROOT/$CMAKE_VERSION"}"

# The executable that we want to use (can be overriden by an invoker)
: "${CMAKE_EXE:="$CMAKE_CACHE_DIR/bin/cmake$EXE_SUFFIX"}"
: "${CTEST_EXE:="${CMAKE_EXE%cmake*}ctest"}"

# Downloads a prebuilt CMake binary:
_download_cmake() {
    # Directory where we will extract to (temporary)
    declare extract_dir="$CMAKE_CACHE_DIR.tmp"
    debug "Temporary extraction dir: [$extract_dir]"
    test -d "$extract_dir" && rm -r -- "$extract_dir"
    mkdir -p "$extract_dir"

    # The path for the downloaded archive (may be zip or tgz)
    declare archive="$CMAKE_CACHE_DIR.archive"
    debug "Temporary archive file: [$archive]"

    # The --strip-components for tar (different on macos)
    declare strip_components=1
    # By default we will use tar. (Windows uses unzip)
    declare use=tar

    # Common prefix:
    declare url_base="https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION"

    # Select the URL and options:
    case "$OS_NAME" in
    linux)
        declare arch
        arch="$(uname -m)"
        url="$url_base/cmake-$CMAKE_VERSION-Linux-$arch.tar.gz"
        ;;
    macos)
        url="$url_base/cmake-$CMAKE_VERSION-macos10.10-universal.tar.gz"
        # We're pulling out the app bundle contents, so we need to skip more intermediate directories
        strip_components=3
        ;;
    windows)
        url="$url_base/cmake-$CMAKE_VERSION-windows-x86_64.zip"
        # On windows we use 'unzip'
        use=unzip
        ;;
    *)
        fail "Unrecognized platform $(uname -a)"
        ;;
    esac

    # Download the file:
    log "Downloading [$url] ..."
    curl --retry 5 -LsS --max-time 120 --fail --output "$archive" "$url"

    # Extract the downloaded archive:
    log "Extracting to [$CMAKE_CACHE_DIR] ..."
    case $use in
    tar)
        debug "Expand with 'tar' into [$extract_dir]"
        tar -x -f "$archive" -C "$extract_dir" --strip-components=$strip_components
        ;;
    unzip)
        # Unzip has no --strip-components, so we need to move the files ourself
        debug "Expand with 'unzip' into [$extract_dir.1]"
        unzip -o -qq "$archive" -d "$extract_dir.1"
        mv -- "$extract_dir.1"/cmake-$CMAKE_VERSION-*/* "$extract_dir"
        ;;
    esac

    # Check that we got the file:
    declare test_file="$extract_dir/bin/cmake$EXE_SUFFIX"
    debug "Checking for file [$test_file]"
    test -f "$test_file" || fail "Download+extract did not produce the expected file [$test_file]??"
    # Put the temporary extracted dir into its final location:
    test -d "$CMAKE_CACHE_DIR" && rm -r -- "$CMAKE_CACHE_DIR"
    mv -- "$extract_dir" "$CMAKE_CACHE_DIR"
}

# Ensures that we have a CMake executable matching our cache settings:
_ensure_cmake() {
    # If we already have the executable, we don't need to get one
    debug "Expecting CMake executable [$CMAKE_EXE]"
    debug "Expecting CTest executable [$CTEST_EXE]"
    if test -f "$CMAKE_EXE"; then
        return 0
    fi

    declare arch
    arch="$(uname -m)"

    # Otherwise we need to obtain it
    log "Obtaining CMake $CMAKE_VERSION for $OS_NAME-$arch"
    case "$OS_NAME-$arch" in
    linux-x86_64|linux-aarch64|windows-*|macos-*)
        # Currently, we just download a pre-built binary. In the future, we may want to build from source.
        _download_cmake
        ;;
    *)
        fail "We don't know how to automatically obtain CMake $CMAKE_VERSION for this platform"
        ;;
    esac
}

_ensure_cmake
