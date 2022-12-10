#!/usr/bin/env python3
"""Packager module.

This program makes Debian and RPM repositories for libmongocrypt,
by downloading our tarballs and forming them into Linux packages.
It must be run on a Debianoid, since Debian provides tools to make
RPMs, but RPM-based systems don't provide debian packaging crud.
This program is also based on the program of the same name in the
MongoDB server repository.

This program was adapted from the program of the same name in the
MongoDB server repository:

https://github.com/mongodb/mongo/blob/v4.2/buildscripts/packager.py

Notes
-----
* Almost anything that you want to be able to influence about how a
package construction must be embedded in some file that the
packaging tool uses for input (e.g., debian/rules, debian/control,
debian/changelog; or the RPM specfile), and the precise details are
arbitrary and silly.  So this program generates all the relevant
inputs to the packaging tools.

* Once a .deb or .rpm package is made, there's a separate layer of
tools that makes a "repository" for use by the apt/yum layers of
package tools.  The layouts of these repositories are arbitrary and
silly, too.

* Before you run the program on a new host, these are the
prerequisites:

apt-get install dpkg-dev rpm debhelper fakeroot ia32-libs createrepo git-core
echo "Now put the dist gnupg signing keys in ~root/.gnupg"

"""

import argparse
from datetime import datetime
import errno
from glob import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# The MongoDB names for the architectures we support.
ARCH_CHOICES = ["x86_64", "arm64", "s390x", "ppc64le"]

# Made up names for the flavors of distribution we package for.
DISTROS = ["suse", "debian", "redhat", "ubuntu", "amazon", "amazon2"]


class Spec(object):
    """Spec class."""

    def __init__(self, ver, gitspec=None, rel=None):
        """Initialize Spec."""
        self.ver = ver
        self.gitspec = gitspec
        self.rel = rel

    # Commit-triggerd (nightly) version numbers can be in the form: 3.0.7-pre-, or 3.0.7-5-g3b67ac
    # Patch builds version numbers are in the form: 3.5.5-64-g03945fa-patch-58debcdb3ff1223c9d00005b
    #
    def is_nightly(self):
        """Return True if nightly."""
        return bool(re.search("-$", self.version())) or bool(
            re.search(r"\d-\d+-g[0-9a-f]+$", self.version()))

    def is_patch(self):
        """Return True if patch."""
        return bool(re.search(r"\d-\d+-g[0-9a-f]+-patch-[0-9a-f]+$", self.version()))

    def is_rc(self):
        """Return True if rc."""
        return bool(re.search(r"-rc\d+(\+[0-9]{8}git[0-9a-f]+)?$", self.version()))

    def is_beta(self):
        """Return True if beta."""
        return bool(re.search(r"-beta\d+(\+[0-9]{8}git[0-9a-f]+)?$", self.version()))

    def is_pre_release(self):
        """Return True if pre-release."""
        return self.is_rc() or self.is_beta() or self.is_nightly()

    def version(self):
        """Return version."""
        return self.ver

    def patch_id(self):
        """Return patch id."""
        if self.is_patch():
            return re.sub(r'.*-([0-9a-f]+$)', r'\1', self.version())
        return "none"

    def metadata_gitspec(self):
        """Git revision to use for spec+control+init+manpage files.

        The default is the release tag for the version being packaged.
        """
        if self.gitspec:
            return self.gitspec
        return 'r' + self.version()

    def prelease(self):
        """Return pre-release verison suffix."""
        # NOTE: This is only called for RPM packages, and only after
        # pversion() below has been called. If you want to change this format
        # and want DEB packages to match, make sure to update pversion()
        # below
        #
        # "N" is either passed in on the command line, or "1"
        if self.rel:
            corenum = self.rel
        else:
            corenum = 1

        # Version suffix for RPM packages:
        # 1) RC's - "0.N.rcX"
        # 2) Nightly (snapshot) - "0.N.latest"
        # 3) Patch builds - "0.N.patch.<patch_id>"
        # 4) Standard release - "N"
        if self.is_rc():
            return "0.%s.%s" % (corenum, re.sub('.*-', '', self.version()))
        elif self.is_beta():
            return "0.%s.beta.%s" % (corenum, re.sub('.*-beta', '', self.version()))
        elif self.is_nightly():
            return "0.%s.latest" % (corenum)
        elif self.is_patch():
            return "0.%s.patch.%s" % (corenum, self.patch_id())
        return str(corenum)

    def pversion(self, distro):
        """Return the pversion."""
        # Note: Debian packages have funny rules about dashes in
        # version numbers, and RPM simply forbids dashes.  pversion
        # will be the package's version number (but we need to know
        # our upstream version too).

        # For RPM packages this just returns X.Y.X because of the
        # aforementioned rules, and prelease (above) adds a suffix later,
        # so detect this case early
        if re.search("(suse|redhat|fedora|centos|amazon)", distro.name()):
            return re.sub("-.*", "", self.version())

        # For DEB packages, this code sets the full version. If you change
        # this format and want RPM packages to match make sure you change
        # prelease above as well
        if re.search("^(debian|ubuntu)", distro.name()):
            if self.is_nightly():
                ver = re.sub("-.*", "-latest", self.ver)
            elif self.is_patch():
                ver = re.sub("-.*", "", self.ver) + "-patch-" + self.patch_id()
            else:
                ver = self.ver

            return re.sub("-", "~", ver)

        raise Exception("BUG: unsupported platform?")

    def branch(self):
        """Return the major and minor portions of the specified version.

        For example, if the version is "2.5.5" the branch would be "2.5"
        """
        return ".".join(self.ver.split(".")[0:2])


class Distro(object):
    """Distro class."""

    def __init__(self, string):
        """Initialize Distro."""
        self.dname = string

    def name(self):
        """Return name."""
        return self.dname

    @staticmethod
    def pkgbase():
        """Return pkgbase."""
        return "libmongocrypt"

    def archname(self, arch):
        """Return the packaging system's architecture name.

        Power and x86 have different names for apt/yum (ppc64le/ppc64el
        and x86_64/amd64).
        """
        # pylint: disable=too-many-return-statements
        if re.search("^(debian|ubuntu)", self.dname):
            if arch == "ppc64le":
                return "ppc64el"
            elif arch == "s390x":
                return "s390x"
            elif arch == "arm64":
                return "arm64"
            elif arch.endswith("86"):
                return "i386"
            return "amd64"
        elif re.search("^(suse|centos|redhat|fedora|amazon)", self.dname):
            if arch == "ppc64le":
                return "ppc64le"
            elif arch == "s390x":
                return "s390x"
            elif arch == "arm64":
                return "aarch64"
            elif arch.endswith("86"):
                return "i686"
            return "x86_64"
        else:
            raise Exception("BUG: unsupported platform?")
        # pylint: enable=too-many-return-statements

    def repodir(self, arch, build_os, spec):  # noqa: D406,D407,D412,D413
        """Return the directory where we'll place the package files for (distro, distro_version).

        This is in that distro's preferred repository
        layout (as distinct from where that distro's packaging building
        tools place the package files).

        Examples:

        repo/apt/ubuntu/dists/precise/libmongocrypt/2.5/universe/binary-amd64
        repo/apt/ubuntu/dists/precise/libmongocrypt/2.5/universe/binary-i386

        repo/apt/ubuntu/dists/trusty/libmongocrypt/2.5/universe/binary-amd64
        repo/apt/ubuntu/dists/trusty/libmongocrypt/2.5/universe/binary-i386

        repo/apt/debian/dists/wheezy/libmongocrypt/2.5/main/binary-amd64
        repo/apt/debian/dists/wheezy/libmongocrypt/2.5/main/binary-i386

        repo/yum/redhat/6/libmongocrypt/2.5/x86_64
        yum/redhat/6/libmongocrypt/2.5/i386

        repo/zypper/suse/11/libmongocrypt/2.5/x86_64
        zypper/suse/11/libmongocrypt/2.5/i386
        """

        repo_directory = ""

        if spec.is_pre_release():
            repo_directory = "testing"
        else:
            repo_directory = spec.branch()

        if re.search("^(debian|ubuntu)", self.dname):
            return "repo/apt/%s/dists/%s/libmongocrypt/%s/%s/binary-%s/" % (
                self.dname, self.repo_os_version(build_os), repo_directory, self.repo_component(),
                self.archname(arch))
        elif re.search("(redhat|fedora|centos|amazon)", self.dname):
            return "repo/yum/%s/%s/libmongocrypt/%s/%s/RPMS/" % (
                self.dname, self.repo_os_version(build_os), repo_directory, self.archname(arch))
        elif re.search("(suse)", self.dname):
            return "repo/zypper/%s/%s/libmongocrypt/%s/%s/RPMS/" % (
                self.dname, self.repo_os_version(build_os), repo_directory, self.archname(arch))
        else:
            raise Exception("BUG: unsupported platform?")

    def repo_component(self):
        """Return the name of the section/component/pool we are publishing into.

        Example, "universe" for Ubuntu, "main" for debian.
        """
        if self.dname == 'ubuntu':
            return "universe"
        elif self.dname == 'debian':
            return "main"
        else:
            raise Exception("unsupported distro: %s" % self.dname)

    def repo_os_version(self, build_os):  # pylint: disable=too-many-branches
        """Return an OS version suitable for package repo directory naming.

        Example, 5, 6 or 7 for redhat/centos, "precise," "wheezy," etc.
        for Ubuntu/Debian, 11 for suse, "2013.03" for amazon.
        """
        # pylint: disable=too-many-return-statements
        if self.dname == 'suse':
            return re.sub(r'^suse(\d+)$', r'\1', build_os)
        if self.dname == 'redhat':
            return re.sub(r'^rhel(\d).*$', r'\1', build_os)
        if self.dname == 'amazon':
            return "2013.03"
        elif self.dname == 'amazon2':
            return "2017.12"
        elif self.dname == 'ubuntu':
            if build_os == 'ubuntu1204':
                return "precise"
            elif build_os == 'ubuntu1404':
                return "trusty"
            elif build_os == 'ubuntu1604':
                return "xenial"
            elif build_os == 'ubuntu1804':
                return "bionic"
            elif build_os == 'ubuntu2004':
                return "focal"
            elif build_os == 'ubuntu2204':
                return "jammy"
            else:
                raise Exception("unsupported build_os: %s" % build_os)
        elif self.dname == 'debian':
            if build_os == 'debian81':
                return 'jessie'
            elif build_os == 'debian92':
                return 'stretch'
            elif build_os == 'debian10':
                return 'buster'
            elif build_os == 'debian11':
                return 'bullseye'
            else:
                raise Exception("unsupported build_os: %s" % build_os)
        else:
            raise Exception("unsupported distro: %s" % self.dname)
        # pylint: enable=too-many-return-statements

    def make_pkg(self, build_os, arch, spec, srcdir):
        """Return the package."""
        if re.search("^(debian|ubuntu)", self.dname):
            return make_deb(self, build_os, arch, spec, srcdir)
        elif re.search("^(suse|centos|redhat|fedora|amazon)", self.dname):
            return make_rpm(self, build_os, arch, spec, srcdir)
        else:
            raise Exception("BUG: unsupported platform?")

    def build_os(self, arch):
        """Return the build os label in the binary package to download.

        Example, "rhel55" for redhat, "ubuntu1204" for ubuntu, "debian81" for debian,
        "suse11" for suse, etc.
        """
        # Community builds only support amd64
        if arch not in ['x86_64', 'ppc64le', 's390x', 'arm64']:
            raise Exception("BUG: unsupported architecture (%s)" % arch)

        if re.search("(suse)", self.dname):
            return ["suse11", "suse12", "suse15"]
        elif re.search("(redhat|fedora|centos)", self.dname):
            return ["rhel80", "rhel70", "rhel71", "rhel72", "rhel62", "rhel55", "rhel67"]
        elif self.dname in ['amazon', 'amazon2']:
            return [self.dname]
        elif self.dname == 'ubuntu':
            return [
                "ubuntu1204",
                "ubuntu1404",
                "ubuntu1604",
                "ubuntu1804",
                "ubuntu2004",
                "ubuntu2204",
            ]
        elif self.dname == 'debian':
            return ["debian81", "debian92", "debian10", "debian11"]
        else:
            raise Exception("BUG: unsupported platform?")

    def release_dist(self, build_os):
        """Return the release distribution to use in the rpm.

        "el5" for rhel 5.x,
        "el6" for rhel 6.x,
        return anything else unchanged.
        """

        if self.dname == 'amazon':
            return 'amzn1'
        elif self.dname == 'amazon2':
            return 'amzn2'
        return re.sub(r'^rh(el\d).*$', r'\1', build_os)


def get_args(distros, arch_choices):
    """Return the program arguments."""

    distro_choices = []
    for distro in distros:
        for arch in arch_choices:
            distro_choices.extend(distro.build_os(arch))

    parser = argparse.ArgumentParser(description='Build libmongocrypt Packages')
    parser.add_argument("-v", "--library-version", help="Library version to build (e.g. 1.0.0-beta2)",
                        required=True)
    parser.add_argument("-m", "--metadata-gitspec",
                        help="Gitspec to use for package metadata files", required=False)
    parser.add_argument("-r", "--release-number", help="RPM release number base", type=int,
                        required=False)
    parser.add_argument("-d", "--distros", help="Distros to build for", choices=distro_choices,
                        required=False, default=[], action='append')
    parser.add_argument("-p", "--prefix", help="Directory to build into", required=False)
    parser.add_argument("-a", "--arches", help="Architecture to build", choices=arch_choices,
                        default=[], required=False, action='append')
    parser.add_argument("-t", "--tarball", help="Local tarball to package", required=True,
                        type=lambda x: is_valid_file(parser, x))

    args = parser.parse_args()

    if len(args.distros) * len(args.arches) > 1 and args.tarball:
        parser.error("Can only specify local tarball with one distro/arch combination")

    return args


def main():
    """Execute Main program."""

    distros = [Distro(distro) for distro in DISTROS]

    args = get_args(distros, ARCH_CHOICES)

    spec = Spec(args.library_version, args.metadata_gitspec, args.release_number)

    oldcwd = os.getcwd()
    srcdir = oldcwd + "/../"

    # Where to do all of our work. Use a randomly-created directory if one
    # is not passed in.
    prefix = args.prefix
    if prefix is None:
        prefix = tempfile.mkdtemp()
    print("Working in directory %s" % prefix)

    os.chdir(prefix)
    try:
        # Build a package for each distro/spec/arch tuple, and
        # accumulate the repository-layout directories.
        for (distro, arch) in crossproduct(distros, args.arches):

            for build_os in distro.build_os(arch):
                if build_os in args.distros or not args.distros:

                    filename = tarfile(build_os, arch, spec)
                    ensure_dir(filename)
                    shutil.copyfile(args.tarball, filename)

                    repo = make_package(distro, build_os, arch, spec, srcdir)
                    make_repo(repo, distro, build_os)

    finally:
        os.chdir(oldcwd)


def crossproduct(*seqs):
    """Provide a generator for iterating all the tuples consisting of elements of seqs."""
    num_seqs = len(seqs)
    if num_seqs == 0:
        pass
    elif num_seqs == 1:
        for idx in seqs[0]:
            yield [idx]
    else:
        for lst in crossproduct(*seqs[:-1]):
            for idx in seqs[-1]:
                lst2 = list(lst)
                lst2.append(idx)
                yield lst2


def sysassert(argv):
    """Run argv and assert that it exited with status 0."""
    print("In %s, running %s" % (os.getcwd(), " ".join(argv)))
    sys.stdout.flush()
    sys.stderr.flush()
    assert subprocess.Popen(argv).wait() == 0


def backtick(argv):
    """Run argv and return its output string."""
    print("In %s, running %s" % (os.getcwd(), " ".join(argv)))
    sys.stdout.flush()
    sys.stderr.flush()
    return subprocess.Popen(argv, stdout=subprocess.PIPE).communicate()[0]


def tarfile(build_os, arch, spec):
    """Return the location where we store the downloaded tarball for this package."""
    return "dl/libmongocrypt-%s-%s-%s.tar.gz" % (spec.version(), build_os, arch)


def setupdir(distro, build_os, arch, spec):
    """Return the setup directory name."""
    # The setupdir will be a directory containing all inputs to the
    # distro's packaging tools (e.g., package metadata files, init
    # scripts, etc), along with the already-built binaries).  In case
    # the following format string is unclear, an example setupdir
    # would be dst/x86_64/debian-sysvinit/wheezy/libmongocrypt/
    # or dst/x86_64/redhat/rhel55/libmongocrypt/
    return "dst/%s/%s/%s/%s-%s/" % (arch, distro.name(), build_os, distro.pkgbase(),
                                      spec.pversion(distro))


def unpack_binaries_into(build_os, arch, spec, where):
    """Unpack the tarfile for (build_os, arch, spec) into directory where."""
    rootdir = os.getcwd()
    ensure_dir(where)
    # Note: POSIX tar doesn't require support for gtar's "-C" option,
    # and Python's tarfile module prior to Python 2.7 doesn't have the
    # features to make this detail easy.  So we'll just do the dumb
    # thing and chdir into where and run tar there.
    os.chdir(where)
    try:
        sysassert(["tar", "xvzf", rootdir + "/" + tarfile(build_os, arch, spec)])
        release_dir = glob('libmongocrypt-*')[0]
        for releasefile in "lib", "lib64", "include":
            if os.path.exists("%s/%s" % (release_dir, releasefile)):
                print("moving file: %s/%s" % (release_dir, releasefile))
                os.rename("%s/%s" % (release_dir, releasefile), releasefile)
        os.rmdir(release_dir)
    except Exception:
        exc = sys.exc_info()[1]
        os.chdir(rootdir)
        raise exc
    os.chdir(rootdir)


def make_package(distro, build_os, arch, spec, srcdir):
    """Construct the package for (arch, distro, spec).

    Get the packaging files from srcdir and any user-specified suffix from suffixes.
    """

    sdir = setupdir(distro, build_os, arch, spec)
    ensure_dir(sdir)
    for pkgdir in ["etc/debian", "etc/rpm"]:
        print("Copying packaging files from %s to %s" % ("%s/%s" % (srcdir, pkgdir), sdir))
        sysassert([
            "sh", "-c",
            "(cd \"%s\" && tar cf - %s ) | (cd \"%s\" && tar --strip-components=1 -xvf -)" % (srcdir, pkgdir, sdir)
        ])
    # Splat the binaries under sdir.  The "build" stages of the
    # packaging infrastructure will move the files to wherever they
    # need to go.
    unpack_binaries_into(build_os, arch, spec, sdir)
    return distro.make_pkg(build_os, arch, spec, srcdir)


def make_repo(repodir, distro, build_os):
    """Make the repo."""
    if re.search("(debian|ubuntu)", repodir):
        make_deb_repo(repodir, distro, build_os)
    elif re.search("(suse|centos|redhat|fedora|amazon)", repodir):
        make_rpm_repo(repodir)
    else:
        raise Exception("BUG: unsupported platform?")


def make_deb(distro, build_os, arch, spec, srcdir):
    """Make the Debian script."""
    sdir = setupdir(distro, build_os, arch, spec)
    # Rewrite the control and rules files
    write_debian_changelog(sdir + "debian/changelog", spec, srcdir, distro)
    distro_arch = distro.archname(arch)
    sysassert([
        "cp", "-v", srcdir + "etc/debian/control", sdir + "debian/control"
    ])
    sysassert([
        "cp", "-v", srcdir + "etc/debian/rules", sdir + "debian/rules"
    ])

    # Do the packaging.
    oldcwd = os.getcwd()
    try:
        os.chdir(sdir)
        sysassert(["dpkg-buildpackage", "-uc", "-us", "-a" + distro_arch])
    finally:
        os.chdir(oldcwd)
    repo_dir = distro.repodir(arch, build_os, spec)
    ensure_dir(repo_dir)
    # FIXME: see if shutil.copyfile or something can do this without
    # much pain.
    sysassert(["sh", "-c", "cp -v \"%s/../\"*.deb \"%s\"" % (sdir, repo_dir)])
    return repo_dir


def make_deb_repo(repo, distro, build_os):
    """Make the Debian repo."""
    # Note: the Debian repository Packages files must be generated
    # very carefully in order to be usable.
    oldpwd = os.getcwd()
    os.chdir(repo + "../../../../../../")
    try:
        dirs = {
            os.path.dirname(deb)[2:]
            for deb in backtick(["find", ".", "-name", "*.deb"]).decode('utf-8').split()
        }
        for directory in dirs:
            st = backtick(["dpkg-scanpackages", directory, "/dev/null"])
            with open(directory + "/Packages", "wb") as fh:
                fh.write(st)
            bt = backtick(["gzip", "-9c", directory + "/Packages"])
            with open(directory + "/Packages.gz", "wb") as fh:
                fh.write(bt)
    finally:
        os.chdir(oldpwd)
    # Notes: the Release{,.gpg} files must live in a special place,
    # and must be created after all the Packages.gz files have been
    # done.
    s1 = """Origin: libmongocrypt
Label: libmongocrypt
Suite: %s
Codename: %s/libmongocrypt
Architectures: amd64 arm64 ppc64el s390x
Components: %s
Description: libmongocrypt packages
""" % (distro.repo_os_version(build_os), distro.repo_os_version(build_os), distro.repo_component())
    if os.path.exists(repo + "../../Release"):
        os.unlink(repo + "../../Release")
    if os.path.exists(repo + "../../Release.gpg"):
        os.unlink(repo + "../../Release.gpg")
    oldpwd = os.getcwd()
    os.chdir(repo + "../../")
    s2 = backtick(["apt-ftparchive", "release", "."])
    try:
        with open("Release", 'wb') as fh:
            fh.write(s1.encode('utf-8'))
            fh.write(s2)
    finally:
        os.chdir(oldpwd)


def move_repos_into_place(src, dst):  # pylint: disable=too-many-branches
    """Move the repos into place."""
    # Find all the stuff in src/*, move it to a freshly-created
    # directory beside dst, then play some games with symlinks so that
    # dst is a name the new stuff and dst+".old" names the previous
    # one.  This feels like a lot of hooey for something so trivial.

    # First, make a crispy fresh new directory to put the stuff in.
    i = 0
    while True:
        date_suffix = time.strftime("%Y-%m-%d")
        dname = dst + ".%s.%d" % (date_suffix, i)
        try:
            os.mkdir(dname)
            break
        except OSError:
            exc = sys.exc_info()[1]
            if exc.errno == errno.EEXIST:
                pass
            else:
                raise exc
        i = i + 1

    # Put the stuff in our new directory.
    for src_file in os.listdir(src):
        sysassert(["cp", "-rv", src + "/" + src_file, dname])

    # Make a symlink to the new directory; the symlink will be renamed
    # to dst shortly.
    i = 0
    while True:
        tmpnam = dst + ".TMP.%d" % i
        try:
            os.symlink(dname, tmpnam)
            break
        except OSError:  # as exc: # Python >2.5
            exc = sys.exc_info()[1]
            if exc.errno == errno.EEXIST:
                pass
            else:
                raise exc
        i = i + 1

    # Make a symlink to the old directory; this symlink will be
    # renamed shortly, too.
    oldnam = None
    if os.path.exists(dst):
        i = 0
        while True:
            oldnam = dst + ".old.%d" % i
            try:
                os.symlink(os.readlink(dst), oldnam)
                break
            except OSError:  # as exc: # Python >2.5
                exc = sys.exc_info()[1]
                if exc.errno == errno.EEXIST:
                    pass
                else:
                    raise exc

    os.rename(tmpnam, dst)
    if oldnam:
        os.rename(oldnam, dst + ".old")


def write_debian_changelog(path, spec, srcdir, distro):
    """Write the debian changelog."""
    oldcwd = os.getcwd()
    os.chdir(srcdir)
    preamble = "libmongocrypt (%s-0) unstable; urgency=medium\n\n" % spec.pversion(distro)
    preamble += "  * Built from Evergreen.\n\n"
    preamble += " -- Roberto C. Sanchez <roberto@connexer.com>  "
    preamble += "%s\n\n" % datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")
    try:
        sb = preamble + backtick([
            "sh", "-c",
            "cat etc/debian/changelog"
        ]).decode('utf-8')
    finally:
        os.chdir(oldcwd)
    with open(path, 'w') as fh:
        fh.write(sb)


def make_rpm(distro, build_os, arch, spec, srcdir):  # pylint: disable=too-many-locals
    """Create the RPM specfile."""
    sdir = setupdir(distro, build_os, arch, spec)

    specfile = srcdir + "etc/rpm/libmongocrypt.spec"

    topdir = ensure_dir('%s/rpmbuild/%s/' % (os.getcwd(), build_os))
    for subdir in ["BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"]:
        ensure_dir("%s/%s/" % (topdir, subdir))
    distro_arch = distro.archname(arch)
    # RPM tools take these macro files that define variables in
    # RPMland.  Unfortunately, there's no way to tell RPM tools to use
    # a given file *in addition* to the files that it would already
    # load, so we have to figure out what it would normally load,
    # augment that list, and tell RPM to use the augmented list.  To
    # figure out what macrofiles ordinarily get loaded, older RPM
    # versions had a parameter called "macrofiles" that could be
    # extracted from "rpm --showrc".  But newer RPM versions don't
    # have this.  To tell RPM what macros to use, older versions of
    # RPM have a --macros option that doesn't work; on these versions,
    # you can put a "macrofiles" parameter into an rpmrc file.  But
    # that "macrofiles" setting doesn't do anything for newer RPM
    # versions, where you have to use the --macros flag instead.  And
    # all of this is to let us do our work with some guarantee that
    # we're not clobbering anything that doesn't belong to us.
    #
    # On RHEL systems, --rcfile will generally be used and
    # --macros will be used in Ubuntu.
    #
    macrofiles = [
        l for l in backtick(["rpm", "--showrc"]).decode('utf-8').split("\n")
        if l.startswith("macrofiles")
    ]
    flags = []
    macropath = os.getcwd() + "/macros"

    write_rpm_macros_file(macropath, topdir, distro.release_dist(build_os))
    if macrofiles:
        macrofiles = macrofiles[0] + ":" + macropath
        rcfile = os.getcwd() + "/rpmrc"
        write_rpmrc_file(rcfile, macrofiles)
        flags = ["--rcfile", rcfile]
    else:
        # This hard-coded hooey came from some box running RPM
        # 4.4.2.3.  It may not work over time, but RPM isn't sanely
        # configurable.
        flags = [
            "--macros",
            "/usr/lib/rpm/macros:/usr/lib/rpm/%s-linux/macros:/usr/lib/rpm/suse/macros:/etc/rpm/macros.*:/etc/rpm/macros:/etc/rpm/%s-linux/macros:~/.rpmmacros:%s"
            % (distro_arch, distro_arch, macropath)
        ]
    # Put the specfile and the tar'd up binaries and stuff in
    # place.
    #
    # The version of rpm and rpm tools in RHEL 5.5 can't interpolate the
    # %{dynamic_version} macro, so do it manually
    with open(specfile, "r") as spec_source:
        with open(topdir + "SPECS/" + os.path.basename(specfile), "w") as spec_dest:
            for line in spec_source:
                line = line.replace('%{dynamic_version}', spec.pversion(distro))
                line = line.replace('%{dynamic_release}', spec.prelease())
                spec_dest.write(line)

    oldcwd = os.getcwd()
    os.chdir(sdir + "/../")
    try:
        sysassert([
            "tar", "-cpzf",
            topdir + "SOURCES/libmongocrypt-%s.tar.gz" % spec.pversion(distro),
            os.path.basename(os.path.dirname(sdir))
        ])
    finally:
        os.chdir(oldcwd)
    # Do the build.

    flags.extend([
        "-D", "dynamic_version " + spec.pversion(distro), "-D",
        "dynamic_release " + spec.prelease(), "-D", "_topdir " + topdir
    ])

    # Versions of RPM after 4.4 ignore our BuildRoot tag so we need to
    # specify it on the command line args to rpmbuild
    if ((distro.name() == "suse" and distro.repo_os_version(build_os) == "15")
            or (distro.name() == "redhat" and distro.repo_os_version(build_os) == "8")):
        flags.extend([
            "--buildroot",
            os.path.join(topdir, "BUILDROOT"),
        ])

    sysassert(["rpmbuild", "-ba", "--target", distro_arch] + flags +
              ["%s/SPECS/libmongocrypt.spec" % topdir])
    repo_dir = distro.repodir(arch, build_os, spec)
    ensure_dir(repo_dir)
    # FIXME: see if some combination of shutil.copy<hoohah> and glob
    # can do this without shelling out.
    sysassert(["sh", "-c", "cp -v \"%s/RPMS/%s/\"*.rpm \"%s\"" % (topdir, distro_arch, repo_dir)])
    return repo_dir


def make_rpm_repo(repo):
    """Make the RPM repo."""
    oldpwd = os.getcwd()
    os.chdir(repo + "../")
    try:
        sysassert(["createrepo", "."])
    finally:
        os.chdir(oldpwd)


def write_rpmrc_file(path, string):
    """Write the RPM rc file."""
    with open(path, 'w') as fh:
        fh.write(string)


def write_rpm_macros_file(path, topdir, release_dist):
    """Write the RPM macros file."""
    with open(path, 'w') as fh:
        fh.write("%%_topdir	%s\n" % topdir)
        fh.write("%%dist	.%s\n" % release_dist)
        fh.write("%_use_internal_dependency_generator 0\n")


def ensure_dir(filename):
    """Ensure that the dirname directory of filename exists, and return filename."""
    dirpart = os.path.dirname(filename)
    try:
        os.makedirs(dirpart)
    except OSError:  # as exc: # Python >2.5
        exc = sys.exc_info()[1]
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise exc
    return filename


def is_valid_file(parser, filename):
    """Check if file exists, and return the filename."""
    if not os.path.exists(filename):
        parser.error("The file %s does not exist!" % filename)
        return None
    return filename


if __name__ == "__main__":
    main()
