#!/bin/bash

set -euxo pipefail

: "${WORKDIR:="$PWD"}"

# Generate an error if these are unset:
: "$PACKAGER_DISTRO" "$PACKAGER_ARCH"

. "$WORKDIR/libmongocrypt/.evergreen/setup-env.sh"


if [ "$OS" = "Windows_NT" ]; then
  CMAKE="/cygdrive/c/cmake/bin/cmake"
else
  IGNORE_SYSTEM_CMAKE=1 . "$WORKDIR/libmongocrypt/.evergreen/find-cmake.sh"
fi

if ! "${HAS_PACKAGES:-false}"; then
  echo "'HAS_PACKAGES' is not 'true': Skipping package build"
  exit 0
fi

if test -d "$WORKDIR/venv"; then
  if test "$OS" = "Windows_NT"; then
    # Need to quote the path on Windows to preserve the separator.
    . "$WORKDIR/venv/Scripts/activate" 2> /tmp/activate_error.log
  else
    . "$WORKDIR/venv/bin/activate" 2> /tmp/activate_error.log
  fi
  if test $? -ne 0; then
    echo "Failed to activate virtualenv: $(cat /tmp/activate_error.log)"
  fi
  python=python
else
  python="${PYTHON:-/opt/mongodbtoolchain/v3/bin/python3}"
fi

export PYTHONPATH
: "${PYTHONPATH:=}"
if test "$OS" = "Windows_NT"; then
  PYTHONPATH="$PYTHONPATH;$(cygpath -w "$WORKDIR/src")"
else
  PYTHONPATH="$PYTHONPATH:$WORKDIR/src"
fi

# Get current version of libmongocrypt.
pushd "$WORKDIR/libmongocrypt"
  mongocrypt_version="$("$python" etc/calc_release_version.py 2>&1)"
popd

PPA_BUILD_ONLY=1 ./libmongocrypt/.evergreen/build_all.sh
pkg_version=$mongocrypt_version
tar -zcv -C install \
  --transform="s|^libmongocrypt/|libmongocrypt-$pkg_version/|" \
  --exclude=nocrypto \
  --exclude=sharedbson \
  -f "libmongocrypt-$pkg_version.tar.gz" \
  libmongocrypt
pushd libmongocrypt/etc/
  # The files from libmongocrypt/debian/ are the official maintainer scripts,
  # but libmongocrypt/etc/debian/ contains a few custom scripts that are
  # meant to support the packager.py workflow.  This step "fills in" around
  # those custom scripts.
  cp -nr ../debian/* debian/
  command "$python" ./packager.py \
    --prefix "$WORKDIR/libmongocrypt" \
    --distros "$PACKAGER_DISTRO" \
    --tarball "$WORKDIR/libmongocrypt-$pkg_version.tar.gz" \
    --library-version "$pkg_version" \
    --metadata-gitspec HEAD \
    --arches "$PACKAGER_ARCH"
popd
