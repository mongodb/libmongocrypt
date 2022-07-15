#!/bin/bash -ex

# This script should be run on macOS and Cygwin on Windows.
# On macOS it will create the following distributions:
# pymongocrypt-<version>.tar.gz
# pymongocrypt-<version>-py2.py3-none-manylinux2010_x86_64.whl
# pymongocrypt-<version>-py2.py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.whl
# pymongocrypt-<version>-py2.py3-none-macosx_10_9_x86_64.whl
#
# On Windows it will create the following distribution:
# pymongocrypt-<version>-py2.py3-none-win_amd64.whl

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail


# Remove any binary files
rm -rf build pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    rm -rf venv37
    virtualenv -p C:\\python\\Python37\\python.exe venv37 && . ./venv37/Scripts/activate

    LIBMONGOCRYPT_TARGET=windows ./handle_libmongocrypt.sh

elif [ "Darwin" = "$(uname -s)" ]; then
    if [[ $(uname -m) == 'arm64' ]]; then
      PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
    else
      PYTHON="python3.7"
    fi
    pip install build

    # Build the source dist first
    python -m build --sdist

    # Build the manylinux2010 wheels.
    # Fetch libmongocrypt for linux.
    LIBMONGOCRYPT_TARGET=linux  ./handle_libmongocrypt.sh

    # 2021-05-05-1ac6ef3 was the last release to generate pip < 20.3 compatible
    # wheels. After that auditwheel was upgraded to v4 which produces PEP 600
    # manylinux_x_y wheels which requires pip >= 20.3. We use the older docker
    # image to support older pip versions.
    images=(quay.io/pypa/manylinux2010_x86_64:2021-05-05-1ac6ef3 \
            quay.io/pypa/manylinux2010_x86_64)
    for image in "${images[@]}"; do
        docker pull $image
        docker run --rm -v `pwd`:/python $image /python/build-manylinux-wheel.sh
    done

    # Build the mac wheel.
    LIBMONGOCRYPT_TARGET=macos ./handle_libmongocrypt.sh
    python -m build wheel

    # Clear all temp files
    rm -rf build libmongocrypt pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib

    ls dist
else
   echo "ERROR: Run this script on macOS or Windows"
   exit 1
fi
