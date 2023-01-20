#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

test -n "${NINJA_EXE-}" || fail "Set \$NINJA_EXE to point to a filepath where we will write the Ninja executable"

# 1.8.2 is chosen as the last pre-built version that supports RHEL 6
: "${NINJA_VERSION:=1.8.2}"

_ninja_cache_dir="${BUILD_CACHE_DIR}/ninja-${NINJA_VERSION}"

_download_ninja() {
    declare extract_dir="$_ninja_cache_dir/ninja.d"
    declare expect_exe="$extract_dir/ninja$EXE_SUFFIX"
    if test -f "$expect_exe"; then
        debug "Using downloaded Ninja executable [$expect_exe]"
        mkdir -p -- "$(dirname "$NINJA_EXE")"
        cp -- "$expect_exe" "$NINJA_EXE"
        return 0
    fi

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
    declare archive=$_ninja_cache_dir/ninja.bin
    mkdir -p -- "$_ninja_cache_dir"
    curl --retry 5 -LsS --max-time 120 --fail --output "$archive" "$url"
    unzip -qq -o "$archive" "ninja$EXE_SUFFIX" -d "$extract_dir"
    test -f "$expect_exe" || fail "Unzip did not generate expected executable [$expect_exe]"

    # Recurisve invocation will find the extracted executable and copy it
    _download_ninja
}

_build_ninja() {
    declare build_out_dir="$_ninja_cache_dir/built"
    mkdir -p "$build_out_dir"
    declare expect_exe="$build_out_dir/ninja$EXE_SUFFIX"
    if test -f "$expect_exe"; then
        debug "Using built Ninja executable [$expect_exe]"
        mkdir -p -- "$(dirname "$NINJA_EXE")"
        cp -- "$expect_exe" "$NINJA_EXE"
        return 0
    fi

    declare extract_dir="$_ninja_cache_dir/ninja-src"
    declare src_tgz="$_ninja_cache_dir/ninja-src.tgz"
    declare url="https://github.com/ninja-build/ninja/archive/refs/tags/v$NINJA_VERSION.tar.gz"
    if test -d "$extract_dir"; then rm -r -- "$extract_dir"; fi
    mkdir -p -- "$extract_dir"

    log "Downloading Ninja source [$url]"
    mkdir -p -- "$_ninja_cache_dir"
    curl --retry 5 -LsS --max-time 120 --fail --output "$src_tgz" "$url"
    tar -x -f "$src_tgz" -C "$extract_dir" --strip-components=1

    log "Building Ninja from source"
    run_chdir "$build_out_dir" run_python "$extract_dir/configure.py" --bootstrap
    test -f "$expect_exe" || fail "Bootstrap did not generate the expected executable [$expect_exe]"

    # Recursive invocation will find our build and copy it
    _build_ninja
}

_ensure_ninja() {
    declare arch
    arch="$(uname -m)"
    if test -f /etc/alpine-release; then
        arch="$arch-musl"
    fi

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
