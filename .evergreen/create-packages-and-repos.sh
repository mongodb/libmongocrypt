#!/bin/bash

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

# Generate an error if these are unset:
: "$PACKAGER_DISTRO" "$PACKAGER_ARCH"

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
  # Require PYTHON be set:
  : "${PYTHON:?}"
  python="${PYTHON}"
fi

export PYTHONPATH
: "${PYTHONPATH:=}"
if test "$OS" = "Windows_NT"; then
  PYTHONPATH="$PYTHONPATH;$(cygpath -w "$WORKDIR/src")"
else
  PYTHONPATH="$PYTHONPATH:$WORKDIR/src"
fi

# Get current version of libmongocrypt.
pushd "$LIBMONGOCRYPT_DIR"
  mongocrypt_version="$("$python" etc/calc_release_version.py)"
popd

PPA_BUILD_ONLY=1 "$LIBMONGOCRYPT_DIR/.evergreen/build_all.sh"
pkg_version=$mongocrypt_version
tar -zcv -C install \
  --transform="s|^libmongocrypt/|libmongocrypt-$pkg_version/|" \
  --exclude=nocrypto \
  --exclude=sharedbson \
  -f "libmongocrypt-$pkg_version.tar.gz" \
  libmongocrypt
pushd "$LIBMONGOCRYPT_DIR/"
  (git remote | grep -q upstream) || git remote add upstream https://github.com/mongodb/libmongocrypt
  git fetch upstream
  git checkout $(git rev-parse upstream/debian/unstable) -- debian
  # The 1.16.0-1 Debian package bumped the debhelper compatibility level to 13, but this level
  # isn't supported on some of the older (now unsupported) versions we still build for; so,
  # patch back to a lower level for the versions that don't support the current level
  if [[ ! -x /usr/bin/dh_assistant ]]; then

    patch -p1 <<EOF
diff --git b/debian/compat a/debian/compat
new file mode 100644
index 00000000..f599e28b
--- /dev/null
+++ a/debian/compat
@@ -0,0 +1 @@
+10
diff --git b/debian/control a/debian/control
index 12eb7557..602fadbb 100644
--- b/debian/control
+++ a/debian/control
@@ -3,7 +3,7 @@ Priority: optional
 Maintainer: Mongo C Driver Team <mongo-c-driver-debian@googlegroups.com>
 Uploaders: Kevin Albertson <kevin.albertson@mongodb.com>,
            Roberto C. Sanchez <roberto@connexer.com>
-Build-Depends: debhelper-compat (= 13),
+Build-Depends: debhelper (>= 10),
                cmake,
                libssl-dev,
                pkgconf,
EOF

  else
     # even on the newer versions, we need to specify via debian/compat, owing to the
     # barebones debian/control file we use for PPA packaging
     echo 13 > debian/compat
  fi
popd
pushd "$LIBMONGOCRYPT_DIR/etc/"
  # The files from libmongocrypt/debian/ are the official maintainer scripts,
  # but libmongocrypt/etc/debian/ contains a few custom scripts that are
  # meant to support the packager.py workflow.  This step "fills in" around
  # those custom scripts.
  cp -nr ../debian/* debian/
  command "$python" ./packager.py \
    --prefix "$LIBMONGOCRYPT_DIR" \
    --distros "$PACKAGER_DISTRO" \
    --tarball "$LIBMONGOCRYPT_DIR-$pkg_version.tar.gz" \
    --library-version "$pkg_version" \
    --metadata-gitspec HEAD \
    --arches "$PACKAGER_ARCH"
popd
