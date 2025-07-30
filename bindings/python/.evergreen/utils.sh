#!/bin/bash -ex

# Usage:
# createvirtualenv /path/to/python /output/path/for/venv
# * param1: Python binary to use for the virtualenv
# * param2: Path to the virtualenv to create
createvirtualenv () {
    PYTHON=$1
    VENVPATH=$2
    # Prefer venv
    VENV="$PYTHON -m venv"
    if [ "$(uname -s)" = "Darwin" ]; then
        VIRTUALENV="$PYTHON -m virtualenv"
    else
        VIRTUALENV=$(command -v virtualenv 2>/dev/null || echo "$PYTHON -m virtualenv")
        VIRTUALENV="$VIRTUALENV -p $PYTHON"
    fi
    if ! $VENV $VENVPATH 2>/dev/null; then
        # Workaround for bug in older versions of virtualenv.
        $VIRTUALENV $VENVPATH 2>/dev/null || $VIRTUALENV $VENVPATH
    fi
    if [ "Windows_NT" = "${OS:-}" ]; then
        # Workaround https://bugs.python.org/issue32451:
        # mongovenv/Scripts/activate: line 3: $'\r': command not found
        dos2unix $VENVPATH/Scripts/activate || true
        . $VENVPATH/Scripts/activate
    else
        . $VENVPATH/bin/activate
    fi

    export PIP_QUIET=1
    python -m pip install --upgrade pip
}

# Usage:
# PYTHON = find_python3
find_python3() {
    PYTHON=""
    # Add a fallback system python3 if it is available and Python 3.9+.
    if is_python_39 "$(command -v python3)"; then
        PYTHON="$(command -v python3)"
    fi
    # Find a suitable toolchain version, if available.
    if [ "$(uname -s)" = "Darwin" ]; then
        PYTHON="/Library/Frameworks/Python.Framework/Versions/3.9/bin/python3"
    elif [ "Windows_NT" = "${OS:-}" ]; then # Magic variable in cygwin
        PYTHON="C:/python/Python39/python.exe"
    else
        # Prefer our own toolchain, fall back to mongodb toolchain if it has Python 3.9+.
        if [ -f "/opt/python/3.9/bin/python3" ]; then
            PYTHON="/opt/python/3.9/bin/python3"
        elif is_python_39 "$(command -v /opt/mongodbtoolchain/v4/bin/python3)"; then
            PYTHON="/opt/mongodbtoolchain/v4/bin/python3"
        elif is_python_39 "$(command -v /opt/mongodbtoolchain/v3/bin/python3)"; then
            PYTHON="/opt/mongodbtoolchain/v3/bin/python3"
        fi
    fi
    if [ -z "$PYTHON" ]; then
        echo "Cannot run pre-commit without python3.9+ installed!"
        exit 1
    fi
    echo "$PYTHON"
}

# Function that returns success if the provided Python binary is version 3.9 or later
# Usage:
# is_python_39 /path/to/python
# * param1: Python binary
is_python_39() {
    if [ -z "$1" ]; then
        return 1
    elif $1 -c "import sys; exit(sys.version_info[:2] < (3, 9))"; then
        # runs when sys.version_info[:2] >= (3, 9)
        return 0
    else
        return 1
    fi
}
