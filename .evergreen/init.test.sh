#!/bin/bash

# Test shell utilities.

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

function assert_eq() {
    if [ "$1" != "$2" ]; then
        echo "${BASH_SOURCE[0]}:${BASH_LINENO[0]} assertion failed: '$1' != '$2'"
        return 1
    fi
}

function test_abspath () {
    mkdir -p /tmp/a/b/c
    cd /tmp/a/b/c
    got=$(abspath .)
    expect=/tmp/a/b/c
    assert_eq "$got" "$expect"

    got=$(abspath ..)
    expect=/tmp/a/b
    assert_eq "$got" "$expect"

    got=$(abspath .././foo.txt)
    expect=/tmp/a/b/foo.txt
    assert_eq "$got" "$expect"

    got=$(abspath /foo.txt)
    expect=/foo.txt
    assert_eq "$got" "$expect"

    got=$(abspath /tmp/a/../a/foo.txt)
    expect=/tmp/a/foo.txt
    assert_eq "$got" "$expect"

    got=$(abspath /tmp//a//b//c//foo.txt)
    expect=/tmp/a/b/c/foo.txt
    assert_eq "$got" "$expect"

    pushd /tmp > /dev/null
    got=$(abspath ./a/b/c/foo.txt)
    expect=/tmp/a/b/c/foo.txt
    assert_eq "$got" "$expect"
    popd > /dev/null

    got=$(abspath /a/b/c/foo.txt)
    expect=/a/b/c/foo.txt
    assert_eq "$got" "$expect"
}

test_abspath
