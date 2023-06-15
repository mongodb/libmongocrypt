#!/bin/bash
# calc_release_version_selftest.sh is used to test output of calc_release_version.py.
# run with:
# cd etc
# ./calc_release_version_selftest.sh

set -o errexit
set -o pipefail

function assert_eq () {
    a="$1"
    b="$2"
    if [[ "$a" != "$b" ]]; then
        echo "Assertion failed: $a != $b"
        # Print caller
        caller
        exit 1
    fi
}

SAVED_REF=$(git rev-parse HEAD)

function cleanup () {
    rm calc_release_version_test.py
    git checkout $SAVED_REF --quiet
}

trap cleanup EXIT

# copy calc_release_version.py to a separate file not tracked by git so it does not change on `git checkout`
cp calc_release_version.py calc_release_version_test.py

echo "Test a tagged commit ... begin"
{
    git checkout 1.8.1 --quiet
    got=$(python calc_release_version_test.py)
    assert_eq "$got" "1.8.1"
    git checkout - --quiet
}
echo "Test a tagged commit ... end"

DATE=$(date +%Y%m%d)
echo "Test an untagged commit ... begin"
{
    # b7f8a1f1502d28a5ef440e642fddda8da8f873a1 is commit before 1.8.1
    git checkout b7f8a1f1502d28a5ef440e642fddda8da8f873a1 --quiet
    got=$(python calc_release_version_test.py)
    assert_eq "$got" "1.8.1-$DATE+gitb7f8a1f150"
    git checkout - --quiet
}
echo "Test an untagged commit ... end"

echo "Test next minor version ... begin"
{
    CURRENT_SHORTREF=$(git rev-parse --revs-only --short=10 HEAD)
    got=$(python calc_release_version_test.py --next-minor)
    # The expected output may need to be updated after a release.
    assert_eq "$got" "1.9.0-$DATE+git$CURRENT_SHORTREF"
}
echo "Test next minor version ... end"

echo "All tests passed"
