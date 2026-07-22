# libmongocrypt #

The companion C library for driver support of [In-Use Encryption](https://www.mongodb.com/docs/manual/core/security-in-use-encryption/).

This project uses [Semantic Versioning](https://semver.org/).

# Bugs / Feature Requests #

If you have encountered a bug, or would like to see a new feature in libmongocrypt, please open a case in our issue management tool, JIRA:

- [Create an account and login](https://jira.mongodb.org).
- Navigate to [the MONGOCRYPT project](https://jira.mongodb.org/projects/MONGOCRYPT).
- Click **Create Issue** - Please provide as much information as possible about the issue type and how to reproduce it.

## Security Vulnerabilities ##

If you’ve identified a security vulnerability, please report it according to the [instructions here](https://www.mongodb.com/docs/manual/tutorial/create-a-vulnerability-report).

# Installing #

## Installing libmongocrypt from source ##

To build:

```bash
cmake -D CMAKE_BUILD_TYPE=RelWithDebInfo -B cmake-build
cmake --build cmake-build
```

To install:

```bash
cmake --install cmake-build
```

libmongocrypt performs crypto by default with platform crypto APIs on macOS/Windows and OpenSSL on other platforms. Configure with `DISABLE_NATIVE_CRYPTO=ON` to disable the crypto dependency and supply runtime crypto hooks.

## Installing libmongocrypt on macOS ##
Install the latest release of libmongocrypt with the following.
```bash
brew install mongodb/brew/libmongocrypt
```

To install the latest unstable development version of libmongocrypt, use `brew install mongodb/brew/libmongocrypt --HEAD`. Do not use the unstable version of libmongocrypt in a production environment.

## Installing libmongocrypt on Windows ##
A Windows DLL for x86_64 is available on the Github Releases page. See the [latest release](https://github.com/mongodb/libmongocrypt/releases/latest).

Use `gpg` to verify the signature. The public key for `libmongocrypt` is available on https://pgp.mongodb.com/.

## Installing libmongocrypt From Distribution Packages ##
Distribution packages (i.e., .deb/.rpm) are built and published for several Linux distributions.  The installation of these packages for supported platforms is documented here.

### Package Publication Channels ###
The libmongocrypt project publishes packages in three different channels: `release`, `testing`, and `development`. The channel descriptions are:

- `release`: packages representing final releases, having version numbers like `1.17.2`, `1.18.0`, etc.
- `testing`: packages representing pre-releases (e.g., alpha and beta versions); this channel is currently dormant
- `development`: packages created from each build which passes CI, having version numbers like `1.17.3~<date>+git<commit-hash>`; these packages are not considered suitable for production use

In the below sections, replace the placeholder `<channel>` with the value that best matches your particular needs.

### .deb Packages (Debian and Ubuntu) ###

The repository containing the Debian and Ubuntu .deb packages can be configured automatically, using extrepo, or manually. Once the repository is configured then the packages can be installed.

#### Repository configuration with extrepo ####

Extrepo is available on Debian 11 and newer, as well as Ubuntu 22.04 and newer.

First, install the extrepo package:

```bash
sudo apt install extrepo
```

If you would like to see the information about the repository, it can be viewed with the search command:

```bash
extrepo search libmongocrypt
```

In order to enable the repository, execute this command:

```bash
sudo extrepo enable libmongocrypt-release
```

Once the repository is configured, continue with package installation.

#### Manual repository configuration ####

First, import the public key used to sign the package repositories:

```bash
sudo sh -c 'curl -s --location https://pgp.mongodb.com/libmongocrypt.asc | gpg --dearmor >/etc/apt/trusted.gpg.d/libmongocrypt.gpg'
```

Second, create a list entry for the repository.  For Ubuntu systems (be sure to change `<release>` to `jammy` or `noble` as appropriate to your system):

```bash
echo "deb https://libmongocrypt.s3.amazonaws.com/apt/ubuntu <release>/libmongocrypt/<channel> universe" | sudo tee /etc/apt/sources.list.d/libmongocrypt.list
```

For Debian systems (be sure to change `<release>` to `bullseye`, `bookworm`, or `trixie` as appropriate to your system):

```bash
echo "deb https://libmongocrypt.s3.amazonaws.com/apt/debian <release>/libmongocrypt/<channel> main" | sudo tee /etc/apt/sources.list.d/libmongocrypt.list
```

#### Package installation ####

Finally, update the package cache and install the libmongocrypt packages:

```bash
sudo apt-get update
sudo apt-get install -y libmongocrypt-dev
```

### .rpm Packages (RedHat, Suse, and Amazon) ###

RPMs are available for supported systems running on both x86_64 and AArch64 (also called ARM64) processors. The sections below use `x86_64` in the example repository URLs. Substituting `aarch64` in the place of `x86_64` will permit installation of libmongocrypt packages on systems running on AArch64 processors.

#### RedHat Enterprise Linux ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/redhat/$releasever/libmongocrypt/<channel>/x86_64
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```bash
sudo yum install -y libmongocrypt
```

#### Amazon Linux 2023 ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/amazon/2023/libmongocrypt/<channel>/x86_64
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```bash
sudo yum install -y libmongocrypt
```

#### Amazon Linux 2 ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/amazon/2/libmongocrypt/<channel>/x86_64
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```bash
sudo yum install -y libmongocrypt
```

#### Amazon Linux ####

Create the file `/etc/yum.repos.d/libmongocrypt.repo` with contents:

```
[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/amazon/2013.03/libmongocrypt/<channel>/x86_64
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/libmongocrypt.asc
```

Then install the libmongocrypt packages:

```bash
sudo yum install -y libmongocrypt
```

#### Suse ####

First, import the public key used to sign the package repositories:

```bash
sudo rpm --import https://pgp.mongodb.com/libmongocrypt.asc
```

Second, add the repository (be sure to change `<release>` to `12` or `15`, as appropriate to your system):

```bash
sudo zypper addrepo --gpgcheck "https://libmongocrypt.s3.amazonaws.com/zypper/suse/<release>/libmongocrypt/<channel>/x86_64" libmongocrypt
```

Finally, install the libmongocrypt packages:

```bash
sudo zypper -n install libmongocrypt
```

# Development #

## Documentation ##

The [Client-Side Encryption](https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/client-side-encryption.md) driver specification.

See [The Integration Guide](integrating.md) to integrate with your driver.

See [mongocrypt.h](src/mongocrypt.h) for the public API reference.

## Python Releases ##
Python releases and tags are signed using the MongoDB Python driver PGP key. Use `gpg` to verify the signature. The public key is available at https://pgp.mongodb.com/python-driver.pub.

## Testing ##
`test-mongocrypt` mocks all I/O with files stored in the `test/data` and `test/example` directories. Run `test-mongocrypt` from the source directory:

```bash
./cmake-build/test-mongocrypt
```

libmongocrypt is continuously built and published on evergreen. Submit patch builds to this evergreen project when making changes to test on supported platforms.
The latest tarball containing libmongocrypt built on all supported variants is [published here](https://s3.amazonaws.com/mciuploads/libmongocrypt/all/master/latest/libmongocrypt-all.tar.gz).

## Releasing ##

See [releasing](./doc/releasing.md).
