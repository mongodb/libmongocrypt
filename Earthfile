# Earthly Intro: https://docs.earthly.dev/
# Earthfile Reference: https://docs.earthly.dev/docs/earthfile

# Quick notes:
    #   • The shell script at ".evergreen/earthly.sh" can be used to automatically
    #     download and use a fixed version of Earthly that is compatible with
    #     this file version. Execute the shell script as if it were the Earthly
    #     executable itself.
    #   • In this file, the convention is to copy the source tree into /s/libmongocrypt
    #   • Earthly copies the "build context" (working directory) into the local buildkit
    #     daemon before each build execution. (Similar to the Docker build context).
    #     If you have a large amount of data in the working directory, this could be
    #     slow. The ".earthlyignore" file specifies patterns of files and directories
    #     to exclude from the context upload. Modify it to suite your needs, if necessary.
    #   • Only a subset of the source tree is COPY'd into the build environment. Files
    #     outside of this set will not be available in the build. See the COPY_SOURCE
    #     command for the list.
    #   • Modification at any layer will invalidate caching on all subsequent build
    #     layers. This is important and by-design in Earthly. Push infrequently-modified
    #     operations to earlier in the process the pipeline to make better use of
    #     the cache.
    #
    # This file has a few major sections:
    #   - Setup COMMANDs
    #   - Utility COMMANDs
    #   - Environment targets
    #   - Build/test/CI targets
    #
    # All environment targets begin with "env.". All build targets (should) accept an "env"
    # parameter that specifies the name of the environment to use for the task. The name
    # of an environment is specified following the "env." prefix. For example, the
    # Ubuntu 22.04 environment is named "u22", so its environment target is "env.u22",
    # and can be used i.e. "earthly +build --env=u22"
    #
    # The following environment are defined in this file:
    #   • u22 - Ubuntu 22.04
    #   • u20 - Ubuntu 20.04
    #   • u18 - Ubuntu 18.04
    #   • u16 - Ubuntu 16.04
    #   • u14 - Ubuntu 14.04
    #   • rl8 - RockyLinux 8 - Stand-in for RHEL 8
    #   • c7 - CentOS 7 - Stand-in for RHEL 7
    #   • c6 - CentOS 6 - Stand-in for RHEL 6
    #   • amzn1 - AmazonLinux (2018.03)
    #   • amzn2 - AmazonLinux 2
    #   • deb9 - Debian 9.2
    #   • deb10 - Debian 10.0
    #   • deb11 - Debian 11.0
    #   • sles15 - OpenSUSE Leap 15.0
    #   • alpine - Alpine Linux 3.18
    #
    # When adding new environments, always pull from a fully-qualified image ID:
    #   • DO NOT: "ubuntu"
    #   • DO NOT: "ubuntu:latest"
    #   • DO NOT: "ubuntu:22.10"
    #   • DO: "docker.io/library/ubuntu:22.10"
# ###

VERSION --use-cache-command 0.6
FROM docker.io/library/alpine:3.16
WORKDIR /s

init:
    # Special initializing target that sets up the base image and adds the "__install"
    # script. This scripts abstracts around the underlying package manager interface
    # to "do the right thing" when you want to install packages. Package names will
    # still need to be spelled correctly for the respective system.
    #
    # Invoke +init with a "--base" parameter that specifies the base image to pull
    ARG --required base
    FROM $base
    COPY etc/install-package.sh /usr/local/bin/__install
    RUN chmod +x /usr/local/bin/__install
    ENV USER_CACHES_DIR=/Cache

# Environment setup commands below. Each provides the basic environment for a
# libmongocrypt build. Additional packages and setup may be required for
# individual tasks.

DEBIAN_SETUP:
    # Setup for a debian-like build environment. Used for both Debian and Ubuntu
    COMMAND
    RUN __install build-essential g++ libssl-dev curl unzip python3 pkg-config \
                  git ccache findutils ca-certificates

REDHAT_SETUP:
    # Setup for a redhat-like build environment. Used for CentOS and RockyLinux.
    COMMAND
    RUN __install epel-release && \
        __install gcc-c++ make openssl-devel curl unzip git ccache findutils \
                  patch

CENTOS6_SETUP:
    # Special setup for CentOS6: The packages have been moved to the vault, so
    # we need to enable the vault repos before we perform any __installs
    COMMAND
    RUN rm /etc/yum.repos.d/*.repo
    COPY etc/c6-vault.repo /etc/yum.repos.d/CentOS-Base.repo
    DO +REDHAT_SETUP

AMZ_SETUP:
    # Setup for Amazon Linux.
    COMMAND
    # amzn1 has "python38", but amzn2 has "python3." Try both
    RUN __install python3 || __install python38
    RUN __install gcc-c++ make openssl-devel curl unzip tar gzip \
                  openssh-clients patch git

SLES_SETUP:
    # Setup for a SLES/SUSE build environment
    COMMAND
    RUN __install gcc-c++ make libopenssl-devel curl unzip tar gzip python3 \
                  patch git xz which

ALPINE_SETUP:
    # Setup for an Alpine Linux build environment
    COMMAND
    RUN __install make bash gcc g++ unzip curl tar gzip git musl-dev \
                  linux-headers openssl-dev python3

# Environment targets are defined below. These do not have build outputs, but
# are rather themselves the "outputs" to be used as the environment for subsequent
# tasks

env.c6:
    # A CentOS 6 environment.
    FROM +init --base=docker.io/library/centos:6
    DO +CENTOS6_SETUP

env.c7:
    # A CentOS 7 environment.
    FROM +init --base=docker.io/library/centos:7
    DO +REDHAT_SETUP

env.rl8:
    # CentOS 8 is cancelled. Use RockyLinux 8 for our RHEL 8 environment.
    FROM +init --base=docker.io/library/rockylinux:8
    DO +REDHAT_SETUP

# Utility command for Ubuntu environments
ENV_UBUNTU:
    COMMAND
    ARG --required version
    FROM +init --base=docker.io/library/ubuntu:$version
    DO +DEBIAN_SETUP

env.u14:
    # An Ubuntu 14.04 environment
    DO +ENV_UBUNTU --version 14.04

env.u16:
    # An Ubuntu 16.04 environment
    DO +ENV_UBUNTU --version 16.04

env.u18:
    # An Ubuntu 18.04 environment
    DO +ENV_UBUNTU --version 18.04

env.u20:
    # An Ubuntu 20.04 environment
    DO +ENV_UBUNTU --version 20.04

env.u22:
    # An Ubuntu 22.04 environment
    DO +ENV_UBUNTU --version 22.04

env.amzn1:
    # An Amazon "1" environment. (AmazonLinux 2018)
    FROM +init --base=docker.io/library/amazonlinux:2018.03
    DO +AMZ_SETUP

env.amzn2:
    # An AmazonLinux 2 environment
    FROM +init --base=docker.io/library/amazonlinux:2
    DO +AMZ_SETUP

# Utility command for Debian setup
ENV_DEBIAN:
    COMMAND
    ARG --required version
    FROM +init --base=docker.io/library/debian:$version
    DO +DEBIAN_SETUP

env.deb9:
    # A Debian 9.2 environment
    DO +ENV_DEBIAN --version 9.2

env.deb10:
    # A Debian 10.0 environment
    DO +ENV_DEBIAN --version 10.0

env.deb-unstable:
    DO +ENV_DEBIAN --version=unstable

env.deb11:
    # A Debian 11.0 environment
    DO +ENV_DEBIAN --version 11.0

env.sles15:
    # An OpenSUSE Leap 15.0 environment.
    FROM +init --base=docker.io/opensuse/leap:15.0
    DO +SLES_SETUP

env.alpine:
    FROM +init --base=docker.io/library/alpine:3.17
    DO +ALPINE_SETUP

# Utility: Warm-up obtaining CMake and Ninja for the build. This is usually
# very quick, but on some platforms we need to compile them from source.
CACHE_WARMUP:
    COMMAND
    # Copy only the scripts that are strictly necessary for the operation, to
    # avoid cache invalidation later on.
    COPY .evergreen/setup-env.sh \
         .evergreen/init.sh \
         .evergreen/ensure-cmake.sh \
         .evergreen/ensure-ninja.sh \
         /T/
    RUN bash /T/ensure-cmake.sh
    RUN env NINJA_EXE=/usr/local/bin/ninja \
        bash /T/ensure-ninja.sh

COPY_SOURCE:
    COMMAND
    COPY --dir \
        .git/ \
        cmake/ \
        kms-message/ \
        test/ \
        debian/ \
        src/ \
        doc/ \
        etc/ \
        LICENSE \
        .evergreen/ \
        third-party/ \
        CMakeLists.txt \
        "/s/libmongocrypt"
    COPY --dir bindings/cs/ "/s/libmongocrypt/bindings/"

BUILD_EXAMPLE_STATE_MACHINE:
    COMMAND
    COPY test/example-state-machine.c /s/
    RUN pkg-config --exists libmongocrypt --print-errors && \
        gcc /s/example-state-machine.c \
            -o /s/example-state-machine \
            $(pkg-config --cflags --libs libmongocrypt)
    COPY --dir test/example /s/test/example
    RUN cd /s && /s/example-state-machine

rpm-build:
    FROM +init --base fedora:rawhide
    GIT CLONE https://src.fedoraproject.org/rpms/libmongocrypt.git /R
    # Install the packages listed by "BuildRequires" and rpm-build:
    RUN __install $(awk '/^BuildRequires:/ { print $2 }' /R/libmongocrypt.spec) \
                  rpm-build
    DO +COPY_SOURCE
    RUN cp -r /s/libmongocrypt/. /R
    RUN awk -f /R/etc/rpm/tweak.awk < /R/libmongocrypt.spec > /R/libmongocrypt.2.spec
    RUN rpmbuild -ba /R/libmongocrypt.2.spec \
        -D "_topdir /X" \
        -D "_sourcedir /R"
    SAVE ARTIFACT /X/RPMS /
    SAVE ARTIFACT /X/SRPMS /

rpm-install-runtime:
    # Install the runtime RPM
    FROM +init --base fedora:rawhide
    COPY +rpm-build/RPMS /tmp/libmongocrypt-rpm/
    RUN dnf makecache
    RUN __install $(find /tmp/libmongocrypt-rpm/ -name 'libmongocrypt-1.*.rpm')

rpm-install-dev:
    # Install the development RPM
    FROM +rpm-install-runtime
    COPY +rpm-build/RPMS /tmp/libmongocrypt-rpm/
    RUN dnf makecache
    RUN __install $(find /tmp/libmongocrypt-rpm/ -name 'libmongocrypt-devel-*.rpm')

rpm-devel-test:
    # Attempt to build a small app using pkg-config and the dev RPM
    FROM +rpm-install-dev
    RUN __install gcc
    DO +BUILD_EXAMPLE_STATE_MACHINE
    SAVE ARTIFACT /s/example-state-machine /

rpm-runtime-test:
    # Attempt to run a libmongocrypt-using app with the runtime RPM installed
    FROM +rpm-install-runtime
    COPY +rpm-devel-test/example-state-machine /s/
    COPY --dir test/example /s/test/example
    RUN cd /s/ && /s/example-state-machine

# A target to build the debian package. Options:
#   • --env=[...] (default: deb-unstable)
#     · Set the environment for the build. Affects which packages are available
#       for build dependencies.
# NOTE: Uncommited local changes will be ignored and not affect the result!
deb-build:
    ARG env=deb-unstable
    FROM +env.$env
    RUN __install git-buildpackage fakeroot debhelper cmake libbson-dev \
                  libintelrdfpmath-dev
    DO +COPY_SOURCE
    WORKDIR /s/libmongocrypt
    RUN git clean -fdx && git reset --hard
    RUN python3 etc/calc_release_version.py > VERSION_CURRENT
    RUN git add -f VERSION_CURRENT && \
        git -c user.name=anon -c user.email=anon@localhost \
            commit VERSION_CURRENT -m 'Set version' && \
        env LANG=C bash debian/build_snapshot.sh && \
        debc ../*.changes && \
        dpkg -i ../*.deb
    SAVE ARTIFACT /s/*.deb /debs/

deb-install-runtime:
    # Install the runtime deb package
    FROM +init --base=docker.io/library/debian:unstable
    COPY +deb-build/debs/libmongocrypt0*.deb /tmp/lmc.deb
    RUN __install /tmp/lmc.deb

deb-install-dev:
    # Install the development deb package
    FROM +deb-install-runtime
    COPY +deb-build/debs/libmongocrypt-dev*.deb /tmp/lmc-dev.deb
    RUN __install /tmp/lmc-dev.deb

deb-dev-test:
    # Attempt to build a small app using pkg-config and the dev deb package
    FROM +deb-install-dev
    RUN __install pkg-config gcc
    DO +BUILD_EXAMPLE_STATE_MACHINE
    SAVE ARTIFACT /s/example-state-machine /

deb-runtime-test:
    # Attempt to run a libmongocrypt-using app with the runtime DEB installed
    FROM +deb-install-runtime
    COPY +deb-dev-test/example-state-machine /s/
    COPY --dir test/example /s/test/example
    RUN cd /s/ && /s/example-state-machine

packaging-full-test:
    BUILD +deb-runtime-test
    BUILD +rpm-runtime-test

check-format:
    FROM python:3.11.2-slim-buster
    RUN pip install pipx
    COPY etc/format* /X/etc/
    COPY .evergreen/init.sh /X/.evergreen/
    RUN /X/etc/format.sh  # Does nothing, but warms the cache
    COPY --dir .clang-format src test /X/
    RUN /X/etc/format-all.sh --dry-run -Werror --verbose

# The main "build" target. Options:
#   • --env=[...] (default "u22")
#     · Set the environment for the build. Any name of and "env.<name>" targets
#       can be used.
#   • --persist_build={true,false} (default "true")
#     · Persist the build directory between executions. Enables incremental
#       compilation and reusing of configuration between builds. The build
#       directory is NOT shared between different "--env" environments, only
#       within a single environment.
build:
    ARG env=u22
    FROM +env.$env
    DO +CACHE_WARMUP
    DO +COPY_SOURCE
    WORKDIR /s
    ARG persist_build=true
    IF $persist_build
        CACHE /s/libmongocrypt/cmake-build
    END
    RUN env USE_NINJA=1 bash libmongocrypt/.evergreen/build_all.sh
