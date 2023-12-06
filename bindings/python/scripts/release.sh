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

# Get the libmongocrypt files.
. ./get-libmongocrypt.sh

if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    rm -rf venv37
    virtualenv -p C:\\python\\Python37\\python.exe venv37 && . ./venv37/Scripts/activate
    PYTHON=$(which python)
elif [ "Darwin" = "$(uname -s)" ]; then
    PYTHON=${PYTHON:="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"}
fi 

if [[ ("Windows_NT" = "$OS") ||  ("Darwin" = "$(uname -s)") ]]; then
    # Ensure updated deps.
    $PYTHON -m pip install --upgrade pip build
    $PYTHON -m build .

    # Remove the binary files.
    rm -rf build pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
fi 

if [ $(command -v docker) ]; then
    # Build the manylinux2010 wheels.

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

    # Sudo is needed to remove the files created by docker.
    sudo rm -rf build pymongocrypt/*.so pymongocrypt/*.dll pymongocrypt/*.dylib
fi

ls dist
