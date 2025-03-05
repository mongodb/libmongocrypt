#!/bin/bash -ex

# This script should be run on macOS and Cygwin on Windows.
# On macOS it will create the following distributions
# pymongocrypt-<version>.tar.gz
# pymongocrypt-<version>-py3-none-macosx_11_0_universal2.whl
# pymongocrypt-<version>-py3-none-macosx_10_14_intel.whl
#
# On Windows it will create the following distribution:
# pymongocrypt-<version>-py3-none-win_amd64.whl
#
# If docker is available on Linux or MacOS, it will also produce the following:
# pymongocrypt-<Version>-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

SCRIPT_DIR=$(dirname ${BASH_SOURCE:-$0})

# The libmongocrypt git revision release to embed in our wheels.
LIBMONGOCRYPT_VERSION=$(cat $SCRIPT_DIR/libmongocrypt-version.txt)
REVISION=$(git rev-list -n 1 $LIBMONGOCRYPT_VERSION)
# The libmongocrypt release branch.
MINOR_VERSION=$(echo $LIBMONGOCRYPT_VERSION | cut -d. -f1,2)
BRANCH="r${MINOR_VERSION}"
# The python executable to use.
PYTHON=${PYTHON:-python}

pushd $SCRIPT_DIR/..

# Clean slate.
rm -rf dist .venv build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib

function get_libmongocrypt() {
    TARGET=$1
    MONGOCRYPT_SO=$2
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
    curl -O https://s3.amazonaws.com/mciuploads/libmongocrypt-release/$TARGET/${BRANCH}/${REVISION}/libmongocrypt.tar.gz
    mkdir libmongocrypt
    tar xzf libmongocrypt.tar.gz -C ./libmongocrypt
    chmod +x ${MONGOCRYPT_SO}
    cp ${MONGOCRYPT_SO} pymongocrypt/
    rm -rf ./libmongocrypt libmongocrypt.tar.gz
}

function build_wheel() {
    python -m pip install unasync
    python -m pip install --upgrade pip build
    python -m build --wheel
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
}

function build_manylinux_wheel() {
    python -m pip install unasync
    docker pull $1
    docker run --rm -v `pwd`:/python $1 /python/scripts/build-manylinux-wheel.sh
    # Sudo is needed to remove the files created by docker.
    sudo rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
}

function test_dist() {
    python -m pip uninstall -y pymongocrypt
    python -m pip install $1
    pushd ..
    python -c "from pymongocrypt.binding import libmongocrypt_version, lib"
    popd
}

# Handle Windows dist.
if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    $PYTHON -m venv .venv
    # Workaround https://bugs.python.org/issue32451:
    # .venv/Scripts/activate: line 3: $'\r': command not found
    dos2unix .venv/Scripts/activate || true
    . ./.venv/Scripts/activate

    # Use crypto-enabled libmongocrypt.
    get_libmongocrypt windows-test libmongocrypt/bin/mongocrypt.dll
    build_wheel
    test_dist dist/*.whl
fi

# Handle MacOS dists.
if [ "Darwin" = "$(uname -s)" ]; then
    $PYTHON -m venv .venv
    . .venv/bin/activate

    # Build universal2 wheel.
    get_libmongocrypt macos libmongocrypt/lib/libmongocrypt.dylib
    export MACOSX_DEPLOYMENT_TARGET=11.0
    export _PYTHON_HOST_PLATFORM=macosx-11.0-universal2
    build_wheel
    if [ "$(uname -m)" == "arm64" ]; then
        test_dist dist/*universal2.whl
    fi

    # Build and test sdist.
    python -m build --sdist
    test_dist dist/*.tar.gz
fi

# Handle manylinux dists.
if [ $(command -v docker) ]; then
    if [ "Windows_NT" = "$OS" ]; then
        # docker: Error response from daemon: Windows does not support privileged mode
        # would be raised by the qemu command below.
        echo "Not supported on Windows"
        exit 0
    fi

    # Set up qemu support using the method used in docker/setup-qemu-action
    # https://github.com/docker/setup-qemu-action/blob/2b82ce82d56a2a04d2637cd93a637ae1b359c0a7/README.md?plain=1#L46
    docker run --rm --privileged tonistiigi/binfmt:latest --install all

    # Build the manylinux2014 x86_64 wheel.
    # https://github.com/pypa/manylinux
    # Supports CentOS 7 rh-python38, CentOS 8 python38, Fedora 32+, Ubuntu 20.04+.
    # When the rhel7 images go EOL we'll have to switch to the manylinux_x_y variants
    # and use rhel8.
    get_libmongocrypt rhel-70-64-bit libmongocrypt/nocrypto/lib64/libmongocrypt.so
    build_manylinux_wheel quay.io/pypa/manylinux2014_x86_64:2023-12-05-e9f0345
    if [ "Linux" = "$(uname -s)" ]; then
        $PYTHON -m venv .venv
        . .venv/bin/activate
        test_dist dist/*linux*.whl
    fi

    # Build the manylinux_2_28 aarch64 wheel.
    get_libmongocrypt rhel-82-arm64 libmongocrypt/nocrypto/lib64/libmongocrypt.so
    build_manylinux_wheel quay.io/pypa/manylinux_2_28_aarch64:2024-01-01-0e91b08
fi

ls -ltr dist
popd
