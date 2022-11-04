#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

test -n "${NINJA_EXE-}" || fail "Set \$NINJA_EXE to point to a filepath where we will write the Ninja executable"

: "${NINJA_VERSION:=1.10.2}"

_download_ninja() {
    declare extract_dir="$BUILD_CACHE_DIR/ninja.tmp"
    declare archive=$BUILD_CACHE_DIR/ninja.bin

    declare url_base="https://github.com/ninja-build/ninja/releases/download/v$NINJA_VERSION"
    declare fname
    case "$OS_NAME" in
    linux)
        fname="ninja-linux.zip"
        ;;
    macos)
        fname="ninja-mac.zip"
        ;;
    windows)
        fname="ninja-win.zip"
        ;;
    esac

    declare url="$url_base/$fname"
    log "Downloading Ninja Zip [$url]"
    mkdir -p "$BUILD_CACHE_DIR"
    curl --retry 5 -LsS --max-time 120 --fail --output "$archive" "$url"

    unzip -qq -o "$archive" "ninja$EXE_SUFFIX" -d "$extract_dir"
    mkdir -p -- "$(dirname "$NINJA_EXE")"
    mv -- "$extract_dir/ninja$EXE_SUFFIX" "$NINJA_EXE"
}

_build_ninja() {
    declare extract_dir="$BUILD_CACHE_DIR/ninja-src"
    declare src_tgz="$BUILD_CACHE_DIR/ninja-src.tgz"
    declare url="https://github.com/ninja-build/ninja/archive/refs/tags/v$NINJA_VERSION.tar.gz"
    if test -d "$extract_dir"; then rm -r -- "$extract_dir"; fi
    mkdir -p -- "$extract_dir"

    log "Downloading Ninja source [$url]"
    mkdir -p "$BUILD_CACHE_DIR"
    curl --retry 5 -LsS --max-time 120 --fail --output "$src_tgz" "$url"
    tar -x -f "$src_tgz" -C "$extract_dir" --strip-components=1

    log "Building Ninja from source"
    declare build_dir="$extract_dir/build"
    run_cmake -S "$extract_dir" -B "$build_dir" -D CMAKE_BUILD_TYPE=Release
    run_cmake --build "$build_dir" --config Release --target ninja
    run_cmake --install "$build_dir" --config Release --prefix "$build_dir/root"
    mkdir -p -- "$(dirname "$NINJA_EXE")"
    mv -- "$build_dir/root/bin/ninja$EXE_SUFFIX" "$NINJA_EXE"
}

_ensure_ninja() {
    debug "Expecting Ninja executable [$NINJA_EXE]"
    if test -f "$NINJA_EXE"; then
        debug "Ninja executable [$NINJA_EXE] is already present. Nothing to do."
        return 0
    fi
    declare arch
    arch="$(uname -m)"

    case "$OS_NAME-$arch" in
    linux-x86_64|windows-x86_64|macos-*)
        # Download a pre-built version
        _download_ninja
        ;;
    linux-*|windows-*)
        _build_ninja
        ;;
    *)
        fail "We don't know how to automatically obtain a Ninja executable for this platform"
        ;;
    esac
}

_ensure_ninja
