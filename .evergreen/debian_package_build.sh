#!/bin/env bash

#
# Test libmongocrypt's Debian packaging scripts.
#
# Supported options:
#   --is-patch={true,false}
#       If "true", this is an Evergreen patch build. (Default 'false')
#   --arch=<arch>
#       If specified, sets the "--arch" option for debootstrap.

set -euxo pipefail

IS_PATCH=false
_dbs_args=()

for arg in "$@"; do
  case $arg in
    --arch=*)
      a="${arg#*=}"
      _dbs_args+=(--arch "$a")
      ;;
    --is-patch=*)
      IS_PATCH="${arg#*=}"
      ;;
    *)
      echo "Unknown argument '$arg'"
      exit 1
      ;;
  esac
done

on_exit () {
  if [ -e ./unstable-chroot/debootstrap/debootstrap.log ]; then
    echo "Dumping debootstrap.log"
    cat ./unstable-chroot/debootstrap/debootstrap.log
  fi
}
trap on_exit EXIT

if [ "${IS_PATCH}" = "true" ]; then
  git diff HEAD -- . ':!debian' > ../upstream.patch
  git diff HEAD -- debian > ../debian.patch
  git clean -fdx
  git reset --hard HEAD
  if [ -s ../upstream.patch ]; then
    [ -d debian/patches ] || mkdir debian/patches
    mv ../upstream.patch debian/patches/
    echo upstream.patch >> debian/patches/series
    git add debian/patches/*
    git commit -m 'Evergreen patch build - upstream changes'
    git log -n1 -p
  fi
  if [ -s ../debian.patch ]; then
    git apply --index ../debian.patch
    git commit -m 'Evergreen patch build - Debian packaging changes'
    git log -n1 -p
  fi
fi

cd ..

_dbs_args+=(unstable)

git clone https://salsa.debian.org/installer-team/debootstrap.git debootstrap.git
export DEBOOTSTRAP_DIR=`pwd`/debootstrap.git
sudo -E ./debootstrap.git/debootstrap "${_dbs_args[@]}" ./unstable-chroot/ http://cdn-aws.deb.debian.org/debian
cp -a libmongocrypt ./unstable-chroot/tmp/
sudo chroot ./unstable-chroot /bin/bash -c "(set -o xtrace && \
  apt-get install -y build-essential git-buildpackage fakeroot debhelper cmake curl ca-certificates libssl-dev pkg-config libbson-dev libintelrdfpmath-dev && \
  chown -R root:root /tmp/libmongocrypt && \
  cd /tmp/libmongocrypt && \
  git clean -fdx && \
  git reset --hard HEAD && \
  python3 etc/calc_release_version.py > VERSION_CURRENT && \
  git add --force VERSION_CURRENT && \
  git commit VERSION_CURRENT -m 'Set current version' && \
  LANG=C /bin/bash ./debian/build_snapshot.sh && \
  debc ../*.changes && \
  dpkg -i ../*.deb && \
  /usr/bin/gcc -I/usr/include/mongocrypt -I/usr/include/libbson-1.0 -o example-state-machine test/example-state-machine.c -lmongocrypt -lbson-1.0 )"

[ -e ./unstable-chroot/tmp/libmongocrypt/example-state-machine ] || (echo "Example 'example-state-machine' was not built!" ; exit 1)
(cd ./unstable-chroot/tmp/ ; tar zcvf ../../deb.tar.gz *.dsc *.orig.tar.gz *.debian.tar.xz *.build *.deb)

# Build a second time, to ensure a "double build" works
sudo chroot ./unstable-chroot /bin/bash -c "(\
  cd /tmp/libmongocrypt && \
  rm -f example-state-machine && \
  git status --ignored && \
  dpkg-buildpackage -b && dpkg-buildpackage -S )"
