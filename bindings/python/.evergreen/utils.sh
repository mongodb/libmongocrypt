#!/bin/bash -ex

# Usage:
# createvirtualenv /path/to/python /output/path/for/venv
# * param1: Python binary to use for the virtualenv
# * param2: Path to the virtualenv to create
createvirtualenv () {
    PYTHON=$1
    VENVPATH=$2
    if $PYTHON -m virtualenv --version; then
        VIRTUALENV="$PYTHON -m virtualenv"
    elif command -v virtualenv; then
        VIRTUALENV="$(command -v virtualenv) -p $PYTHON"
    else
        echo "Cannot test without virtualenv"
        exit 1
    fi
    $VIRTUALENV --system-site-packages --never-download $VENVPATH
    if [ "Windows_NT" = "$OS" ]; then
        . $VENVPATH/Scripts/activate
    else
        . $VENVPATH/bin/activate
    fi
    # Bootstrap pip to deal with old versions that may install an unsupported
    # version when told to upgrade. First upgrade to 19.1, which should be
    # smart enough to know the latest compatible version of pip, setuptools,
    # and wheel.
    python -m pip install --upgrade 'pip<19.2'  # 19.2 dropped support for Python 3.4
    python -m pip install --upgrade pip, setuptools, wheel
}
