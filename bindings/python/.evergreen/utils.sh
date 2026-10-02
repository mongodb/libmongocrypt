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

# Prints each usable interpreter from the space-separated candidate list,
# one per line, ascending by version. An interpreter is usable if it is
# version 3.9 or later, a final release, and not free-threaded.
_probe_pythons() {
    for bin in $1; do
        [ -x "$bin" ] || continue
        "$bin" -c 'import sys
ok = sys.version_info >= (3, 9) and sys.version_info.releaselevel == "final" and "free-threading" not in sys.version
exit(0 if ok else 1)' 2>/dev/null || continue
        printf '%s\t%s\n' "$("$bin" -c 'import sys; print("%04d" % (sys.version_info[0] * 1000 + sys.version_info[1]))')" "$bin"
    done | sort | cut -f2-
}

# Prints the Python interpreters in the standard numbered toolchain locations,
# one per line, ascending by version, Python 3.9+ only. Only plain version
# directories are matched (e.g. 3.14, not 3.14-asan-ubsan or 3.14t). On Linux,
# falls back to the latest MongoDB toolchain interpreter when the Python
# toolchain is absent, then to a system interpreter from PATH.
find_pythons() {
    local dirs="" dir
    if [ "Windows_NT" = "${OS:-}" ]; then # Magic variable in cygwin
        for dir in C:/python/Python3[0-9]*; do
            [ -d "$dir" ] && dirs="$dirs $dir/python.exe"
        done
    elif [ "$(uname -s)" = "Darwin" ]; then
        for dir in /Library/Frameworks/Python.framework/Versions/3.[0-9]*; do
            case "${dir##*/}" in *[!\.0-9]*) continue ;; esac
            [ -d "$dir" ] && dirs="$dirs $dir/bin/python3"
        done
    else
        for dir in /opt/python/3.[0-9]*; do
            case "${dir##*/}" in *[!\.0-9]*) continue ;; esac
            [ -d "$dir" ] && dirs="$dirs $dir/bin/python3"
        done
    fi
    local results
    results=$(_probe_pythons "$dirs")
    if [ -n "$results" ]; then
        printf '%s\n' "$results"
        return 0
    fi
    if [ "$(uname -s)" != "Darwin" ] && [ "Windows_NT" != "${OS:-}" ]; then
        # No Python toolchain: fall back to the latest MongoDB toolchain
        # interpreter.
        dirs=""
        for dir in /opt/mongodbtoolchain/v[0-9]*; do
            [ -d "$dir" ] && dirs="$dirs $dir/bin/python3"
        done
        results=$(_probe_pythons "$dirs")
        if [ -n "$results" ]; then
            printf '%s\n' "$results" | tail -1
            return 0
        fi
    fi
    # Fall back to a system interpreter from PATH.
    dirs=""
    for dir in python3 python; do
        dir=$(command -v "$dir" 2>/dev/null) || continue
        dirs="$dirs $dir"
    done
    _probe_pythons "$dirs"
}
