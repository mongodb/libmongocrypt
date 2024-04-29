=====================
PyMongoCrypt Releases
=====================

Versioning
----------

PyMongoCrypt's version numbers follow `semantic versioning`_: each version
number is structured "major.minor.patch". Patch releases fix bugs, minor
releases add features (and may fix bugs), and major releases include API
changes that break backwards compatibility (and may add features and fix
bugs).

In between releases we add .devN to the version number to denote the version
under development. So if we just released 1.0.0, then the current dev
version might be 1.0.1.dev0 or 1.1.0.dev0.

PyMongoCrypt's version numbers do not necessarily correspond to the embedded
libmongocrypt library's version number. For example, assume the current
PyMongoCrypt version is 1.0 and libmongocrypt is 1.0. Let's say that
libmongocrypt 2.0.0 is released which has breaking changes to its API. If
those 2.0.0 changes do not require any breaking changes to PyMongoCrypt, then
the next version can be 1.1.

.. _semantic versioning: http://semver.org/

Release Process
---------------

PyMongoCrypt ships wheels for macOS, Windows, and manylinux2010 that include
an embedded libmongocrypt build. Releasing a new version requires macOS with
Docker and a Windows machine.

#. Create a ticket for the release and create a PR.  The PR needs to include
   the next steps including the version change because the branch is protected
   from directly pushing commits.
#. Edit the release.sh script to embed the most recent libmongocrypt tag into
   our wheels, for example::

     # The libmongocrypt git revision release to embed in our wheels.
     -REVISION=$(git rev-list -n 1 1.0.0)
     +REVISION=$(git rev-list -n 1 1.0.1)

#. Add a changelog entry for this release in CHANGELOG.rst.
#. Bump "__version__" in ``pymongocrypt/version.py``.
#. After merging the PR, clone the repository and check out the commit
   with the version change.

#. Create and push tag::

   $ git tag -a "pymongocrypt-<version>" -m "pymongocrypt-<version"
   $ git push --tags

#. Pushing a tag will trigger the release process on GitHub Actions that will require a member
   of the team to authorize the deployment. Navigate to https://github.com/mongodb/libmongocrypt/actions/workflows/release-python.yml
   and wait for the publish to complete.

#. Create a new PR against the same ticket to update version to a ``.dev0``
   version.


Manually Creating Wheels
------------------------

#. Build the release packages for macOS and manylinux by running the release.sh
   script on macOS. Note that Docker must be running::

     $ git clone git@github.com:mongodb/libmongocrypt.git
     $ cd libmongocrypt/bindings/python
     $ git checkout "pymongocrypt <release version number>"
     $ MACOS_TARGET=macos_x86_64 PYTHON=<python38> ./release.sh
     $ PYTHON=<python310> ./release.sh

  Make sure to run using the official binaries for Python 3.8 and 3.10.  You
  should end up with the same files created by Evergreen (except for the Windows wheel).

#. To build the release package for Windows, launch a windows-64-vsMulti-small
   Evergreen spawn host, clone the repro, checkout the release tag, and run
   the release script::

     $ git clone git@github.com:mongodb/libmongocrypt.git
     $ cd libmongocrypt/bindings/python
     $ git checkout "pymongocrypt <release version number>"
     $ ./release.sh

   This will create the following distributions::

     $ ls dist
     pymongocrypt-<version>-py2.py3-none-win_amd64.whl
