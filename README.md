# libmongocrypt #
The companion C library for client side encryption in drivers.

# Bugs / Feature Requests #

If you have encountered a bug, or would like to see a new feature in libmongocrypt, please open a case in our issue management tool, JIRA:

- [Create an account and login](https://jira.mongodb.org).
- Navigate to [the MONGOCRYPT project](https://jira.mongodb.org/projects/MONGOCRYPT).
- Click **Create Issue** - Please provide as much information as possible about the issue type and how to reproduce it.

## Documentation ##
See [The Integration Guide](integrating.md) to integrate with your driver.

See [mongocrypt.h](src/mongocrypt.h) for the public API reference.
The documentation can be rendered into HTML with doxygen. Run `doxygen ./doc/Doxygen`, then open `./doc/html/index.html`.

## Building libmongocrypt ##

On Windows and macOS, libmongocrypt can use the platform's default encryption
APIs as its encryption backend. On other systems, one will want to install the
OpenSSL development libraries, which libmongocrypt will use as the default
encryption backend.

Then build libmongocrypt:

```
git clone https://github.com/mongodb/libmongocrypt
cd libmongocrypt
mkdir cmake-build && cd cmake-build
cmake ../
make
```

This builds libmongocrypt.dylib and test-libmongocrypt, in the cmake-build
directory.

## Installing libmongocrypt on macOS ##
Install the latest release of libmongocrypt with the following.
```
brew install mongodb/brew/libmongocrypt
```

To install the latest unstable development version of libmongocrypt, use `brew install mongodb/brew/libmongocrypt --HEAD`. Do not use the unstable version of libmongocrypt in a production environment.

## Building libmongocrypt from source on macOS ##

First install [Homebrew according to its own instructions](https://brew.sh/).

Install the XCode Command Line Tools:
```
xcode-select --install
```

Then clone and build libmongocrypt:
```
git clone https://github.com/mongodb/libmongocrypt.git
cd libmongocrypt
cmake .
cmake --build . --target install
```

Then, libmongocrypt can be used with pkg-config:
```
pkg-config libmongocrypt --libs --cflags
```

Or use cmake's `find_package`:
```
find_package (mongocrypt)
# Then link against mongo::mongocrypt
```

## Installing libmongocrypt on Windows ##
For Windows, there is a fixed URL to download the DLL and includes directory:
https://s3.amazonaws.com/mciuploads/libmongocrypt/windows/latest_release/libmongocrypt.tar.gz

To download the latest unstable release, download from this URL:
https://s3.amazonaws.com/mciuploads/libmongocrypt/windows/latest_release/libmongocrypt_unstable.tar.gz
Do not use the unstable version of libmongocrypt in a production environment.

### Testing ###
`test-mongocrypt` mocks all I/O with files stored in the `test/data` and `test/example` directories. Run `test-mongocrypt` from the source directory:

```
cd libmongocrypt
./cmake-build/test-mongocrypt
```

libmongocrypt is [continuously built and published on evergreen](https://evergreen.mongodb.com/waterfall/libmongocrypt). Submit patch builds to this evergreen project when making changes to test on supported platforms.
The latest tarball containing libmongocrypt built on all supported variants is [published here](https://s3.amazonaws.com/mciuploads/libmongocrypt/all/master/latest/libmongocrypt-all.tar.gz).

### Troubleshooting ###
If OpenSSL is installed in a non-default directory, pass `-DOPENSSL_ROOT_DIR=/path/to/openssl` to the cmake command for libmongocrypt.

If there are errors with cmake configuration, send the set of steps you performed to the maintainers of this project.

If there are compilation or linker errors, run `make` again, setting `VERBOSE=1` in the environment or on the command line (which shows exact compile and link commands), and send the output to the maintainers of this project.

### Design Principles ###
The design of libmongocrypt adheres to these principles.

#### Easy to integrate ####
The main reason behind creating a C library is to make it easier for drivers to support FLE. Some consequences of this principle: the API is minimal, structs are opaque, and global initialization is lazy.

#### Lightweight ####
We decided against the "have libmongocrypt do everything" approach because it complicated integration, especially with async drivers. Because of this we decided no I/O occurs in libmongocrypt.

### Releasing ###

#### Version number scheme ####
Version numbers of libmongocrypt must follow the format 1.[0-9].[0-9] for releases and 1.[0-9].[0-9]-(alpha|beta|rc)[0-9] for pre-releases.  This ensures that Linux distribution packages built from each commit are published to the correct location.

#### Steps to release ####
Do the following when releasing:
- Update CHANGELOG.md with any new changes and update the `[Unreleased]` text to the version being released.
- If this is a new minor release (e.g. `x.y.0`):
   - Create a branch named `rx.y`.
   - Update the [libmongocrypt-release](https://evergreen.mongodb.com/projects##libmongocrypt-release) Evergreen project to set `Branch Name` to `rx.y`.
   - Update the Linux distribution package installation instructions in the below sections to refer to the new version x.y.
- In the Java binding build.gradle.kts, replace `version = "1.0.0-SNAPSHOT"` with `version = "1.0.0-rc123"`.
- Commit, create a new git tag, like `1.0.0-rc123`, and push.
   - Push both the branch ref and tag ref in the same command: `git push origin master 1.0.0-rc123` or `git push origin r1.0 1.0.0`
   - Pushing the branch ref and the tag ref in the same command eliminates the possibility of a race condition in Evergreen (for building resources based on the presence of a release tag)
   - Note that in the future (e.g., if we move to a PR-based workflow for releases, or if we simply want to take better advantage of advanced Evergreen features), it is possible to use Evergreen's "Trigger Versions With Git Tags" feature by updating both `config.yml` and the project's settings in Evergreen
- In the Java binding build.gradle.kts, replace `version = "1.0.0-rc123"` with `version = "1.0.0-SNAPSHOT"` (i.e. undo the change). For an example of this, see [this commit](https://github.com/mongodb/libmongocrypt/commit/2336123fbc1f4f5894f49df5e6320040987bb0d3) and its parent commit.
- Commit and push.
- Ensure the version on Evergreen with the tagged commit is scheduled. The upload-all task must run to complete the release. ([Example](https://evergreen.mongodb.com/task/libmongocrypt_publish_snapshot_upload_all_77eec777c14171956c69b60aaaa4f85931c957ba_22_03_02_13_51_38)).
- Create the release from the GitHub releases page from the new tag.
- Submit a PR to update the Homebrew package https://github.com/mongodb/homebrew-brew/blob/master/Formula/libmongocrypt.rb. ([Example](https://github.com/mongodb/homebrew-brew/pull/135)).
- File a DOCSP ticket to update the dependent version of bindings in the [CSFLE guide](https://github.com/mongodb-university/csfle-guides). ([Example](https://jira.mongodb.org/browse/DOCSP-19476))
- Update the release on the [Jira releases page](https://jira.mongodb.org/projects/MONGOCRYPT/versions).

## Installing libmongocrypt From Distribution Packages ##
Distribution packages (i.e., .deb/.rpm) are built and published for several Linux distributions.  The installation of these packages for supported platforms is documented here.

### Unstable Development Distribution Packages ###
To install the latest unstable development package, change `1.3` to `development` in the package URLs listed in the subsequent instructions. For example, `https://libmongocrypt.s3.amazonaws.com/apt/ubuntu <release>/libmongocrypt/1.3` in the instructions would become `https://libmongocrypt.s3.amazonaws.com/apt/ubuntu <release>/libmongocrypt/development`. Do not use the unstable version of libmongocrypt in a production environment.

### .deb Packages (Debian and Ubuntu) ###

First, import the public key used to sign the package repositories:

```
sudo sh -c 'curl -s --location https://www.mongodb.org/static/pgp/libmongocrypt.asc | gpg --dearmor >/etc/apt/trusted.gpg.d/libmongocrypt.gpg'
```

Second, create a list entry for the repository.  For Ubuntu systems (be sure to change `<release>` to `xenial` or `bionic`, as appropriate to your system):

```
echo "deb https://libmongocrypt.s3.amazonaws.com/apt/ubuntu <release>/libmongocrypt/1.3 universe" | sudo tee /etc/apt/sources.list.d/libmongocrypt.list
```

For Debian systems (be sure to change `<release>` to `stretch` or `buster`, as appropriate to your system):

```
echo "deb https://libmongocrypt.s3.amazonaws.com/apt/debian <release>/libmongocrypt/1.3 main" | sudo tee /etc/apt/sources.list.d/libmongocrypt.list
```

Third, update the package cache:

```
sudo apt-get update
```

Finally, install the libmongocrypt packages:

```
sudo apt-get install -y libmongocrypt-dev
```

### .rpm Packages (RedHat, Suse, and Amazon) ###


#### RedHat Enterprise Linux ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/redhat/$releasever/libmongocrypt/1.4/x86_64
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```
sudo yum install -y libmongocrypt
```

#### Amazon Linux 2 ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/amazon/2/libmongocrypt/1.4/x86_64
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```
sudo yum install -y libmongocrypt
```

#### Amazon Linux ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/amazon/2013.03/libmongocrypt/1.4/x86_64
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```
sudo yum install -y libmongocrypt
```

#### Suse ####

First, import the public key used to sign the package repositories:

```
sudo rpm --import https://www.mongodb.org/static/pgp/libmongocrypt.asc
```

Second, add the repository (be sure to change `<release>` to `12` or `15`, as appropriate to your system):

```
sudo zypper addrepo --gpgcheck "https://libmongocrypt.s3.amazonaws.com/zypper/suse/<release>/libmongocrypt/1.4/x86_64" libmongocrypt
```

Finally, install the libmongocrypt packages:

```
sudo zypper -n install libmongocrypt
```
