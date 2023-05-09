#!/bin/bash -ex

# Usage:
# createvirtualenv /path/to/python /output/path/for/venv
# * param1: Python binary to use for the virtualenv
# * param2: Path to the virtualenv to create
createvirtualenv () {
    PYTHON=$1
    VENVPATH=$2
    if $PYTHON -m virtualenv --version; then
        VIRTUALENV="$PYTHON -m virtualenv --system-site-packages --never-download"
    elif $PYTHON -m venv -h>/dev/null; then
        VIRTUALENV="$PYTHON -m venv --system-site-packages"
    elif command -v virtualenv; then
        VIRTUALENV="$(command -v virtualenv) -p $PYTHON --system-site-packages --never-download"
    else
        echo "Cannot test without virtualenv"
        exit 1
    fi
    $VIRTUALENV $VENVPATH
    if [ "Windows_NT" = "$OS" ]; then
        . $VENVPATH/Scripts/activate
    else
        . $VENVPATH/bin/activate
    fi
    # Upgrade to the latest versions of pip setuptools wheel so that
    # pip can always download the latest cryptography+cffi wheels.
    python -m pip install --upgrade pip
    python -m pip install --upgrade pip setuptools wheel
}
