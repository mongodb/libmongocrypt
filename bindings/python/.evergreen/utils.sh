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

# Sorts paths by the number in their final path component (after stripping
# the regex in param1 from it), ascending, dropping numbers below param2.
# Portable: does not rely on GNU sort -V.
_sort_paths_by_number() {
    awk -F/ '{ key = $NF; sub(/^'"$1"'/, "", key); key += 0; if (key >= '"$2"') printf "%010d\t%s\n", key, $0 }' |
        sort |
        cut -f2-
}

# Prints the Python interpreters in the standard numbered toolchain locations,
# one per line, ascending by version, Python 3.9+ only (per the version number
# in the directory name). On Linux, falls back to the latest MongoDB toolchain
# interpreter when the Python toolchain is absent.
find_pythons() {
    local dirs=""
    if [ "Windows_NT" = "${OS:-}" ]; then # Magic variable in cygwin
        dirs=$(find C:/python -maxdepth 1 -type d -name "Python3[0-9]*" 2>/dev/null | _sort_paths_by_number "^Python" 39)
    elif [ "$(uname -s)" = "Darwin" ]; then
        dirs=$(find /Library/Frameworks/Python.framework/Versions -maxdepth 1 -type d -name "3.[0-9]*" 2>/dev/null | _sort_paths_by_number "^3\." 9)
    else
        dirs=$(find /opt/python -maxdepth 1 -type d -name "3.[0-9]*" 2>/dev/null | _sort_paths_by_number "^3\." 9)
        if [ -z "$dirs" ]; then
            dirs=$(find /opt/mongodbtoolchain -maxdepth 1 -type d -name "v[0-9]*" 2>/dev/null | _sort_paths_by_number "^v" 0 | tail -1)
        fi
    fi
    for dir in $dirs; do
        if [ "Windows_NT" = "${OS:-}" ]; then
            echo "$dir/python.exe"
        else
            echo "$dir/bin/python3"
        fi
    done
}
