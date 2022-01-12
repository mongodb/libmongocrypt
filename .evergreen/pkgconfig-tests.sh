#!/bin/bash
set -o xtrace
set -o errexit

system_path () {
    if [ "$OS" == "Windows_NT" ]; then
        cygpath -a "$1" -w
    else
        echo $1
    fi
}

if [ ! -e ./.evergreen ]; then
    echo "Error: run from libmongocrypt root"
    exit 1;
fi

if [ ! $(command -v pkg-config) ]; then
    echo "pkg-config not present on this platform; skipping test ..."
    exit 0
fi

libmongocrypt_root=$(pwd)
pkgconfig_tests_root=${libmongocrypt_root}/pkgconfig_tests

rm -rf pkgconfig_tests
mkdir -p pkgconfig_tests/{install,libmongocrypt-cmake-build}
cd pkgconfig_tests

$libmongocrypt_root/.evergreen/prep_c_driver_source.sh
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    chmod u+x ./.evergreen/find-cmake.sh
    # Amazon Linux 2 (arm64) has a very old system CMake we want to ignore
    IGNORE_SYSTEM_CMAKE=1 . ./.evergreen/find-cmake.sh
fi

if [ "$OS" != "Windows_NT" ]; then
    # Check if on macOS with arm64.
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    echo "OS_NAME: $OS_NAME"
    MARCH=$(uname -m | tr '[:upper:]' '[:lower:]')

    if [ "darwin" = "$OS_NAME" -a "arm64" = "$MARCH" ]; then
        ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DCMAKE_OSX_ARCHITECTURES=arm64"
    fi
fi

mkdir cmake-build
cd cmake-build
INSTALL_PATH="$(system_path $pkgconfig_tests_root/install)"
SRC_PATH="$(system_path ../)"
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

# Build libmongocrypt, static linking against libbson and configured for the PPA
cd $pkgconfig_tests_root/libmongocrypt-cmake-build
PREFIX_PATH="$(system_path $pkgconfig_tests_root/install)"
INSTALL_PATH="$(system_path $pkgconfig_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $libmongocrypt_root)"
$CMAKE -DENABLE_SHARED_BSON=OFF -DENABLE_BUILD_FOR_PPA=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="$PREFIX_PATH" -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo
find ${PREFIX_PATH} -name libbson-static-1.0.a -execdir cp {} $(dirname $(find ${INSTALL_PATH} -name libmongocrypt-static.a )) \;

# To validate the pkg-config scripts, we don't want the libbson script to be visible
export PKG_CONFIG_PATH="$(system_path $(/usr/bin/dirname $(/usr/bin/find $pkgconfig_tests_root/install/libmongocrypt -name libmongocrypt.pc)))"

echo "Validating pkg-config scripts"
pkg-config --debug --print-errors --exists libmongocrypt-static
pkg-config --debug --print-errors --exists libmongocrypt

export PKG_CONFIG_PATH="$(system_path $(/usr/bin/dirname $(/usr/bin/find $pkgconfig_tests_root/install -name libbson-1.0.pc))):$(system_path $(/usr/bin/dirname $(/usr/bin/find $pkgconfig_tests_root/install/libmongocrypt -name libmongocrypt.pc)))"

# Build example-state-machine, static linking against libmongocrypt
cd $libmongocrypt_root
gcc $(pkg-config --cflags libmongocrypt-static libbson-static-1.0) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt-static)
./example-state-machine
# Build example-no-bson, static linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt-static) -o example-no-bson test/example-no-bson.c $(pkg-config --libs libmongocrypt-static)
./example-no-bson

rm -f example-state-machine example-no-bson

# Build example-state-machine, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt libbson-static-1.0) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt)
# Build example-no-bson, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt) -o example-no-bson test/example-no-bson.c $(pkg-config --libs libmongocrypt)
export LD_LIBRARY_PATH="$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib):$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib64)"
./example-state-machine
./example-no-bson
unset LD_LIBRARY_PATH

rm -f example-state-machine example-no-bson

# Clean up prior to next execution
cd $pkgconfig_tests_root
rm -rf libmongocrypt-cmake-build install/libmongocrypt
mkdir -p libmongocrypt-cmake-build

# Build libmongocrypt, dynamic linking against libbson
cd $pkgconfig_tests_root/libmongocrypt-cmake-build
PREFIX_PATH="$(system_path $pkgconfig_tests_root/install)"
INSTALL_PATH="$(system_path $pkgconfig_tests_root/install/libmongocrypt)"
SRC_PATH="$(system_path $libmongocrypt_root)"
$CMAKE -DENABLE_SHARED_BSON=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_PREFIX_PATH="$PREFIX_PATH" -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" "$SRC_PATH"
$CMAKE --build . --target install --config RelWithDebInfo

# Build example-state-machine, static linking against libmongocrypt
cd $libmongocrypt_root
gcc $(pkg-config --cflags libmongocrypt-static libbson-static-1.0) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt-static)
# Build example-no-bson, static linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt-static) -o example-no-bson test/example-no-bson.c $(pkg-config --libs libmongocrypt-static)
export LD_LIBRARY_PATH="$(system_path $pkgconfig_tests_root/install/lib):$(system_path $pkgconfig_tests_root/install/lib64)"
./example-state-machine
./example-no-bson
unset LD_LIBRARY_PATH

rm -f example-state-machine example-no-bson

# Build example-state-machine, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt libbson-static-1.0) -o example-state-machine test/example-state-machine.c $(pkg-config --libs libmongocrypt)
# Build example-no-bson, dynamic linking against libmongocrypt
gcc $(pkg-config --cflags libmongocrypt) -o example-no-bson test/example-no-bson.c $(pkg-config --libs libmongocrypt)
export LD_LIBRARY_PATH="$(system_path $pkgconfig_tests_root/install/lib):$(system_path $pkgconfig_tests_root/install/lib64):$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib):$(system_path $pkgconfig_tests_root/install/libmongocrypt/lib64)"
./example-state-machine
./example-no-bson
unset LD_LIBRARY_PATH

rm -f example-state-machine example-no-bson

