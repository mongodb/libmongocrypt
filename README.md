# libmongocrypt #
The companion C library for field-level encryption in drivers. This is a work-in-progress and subject to sweeping changes.

## Building libmongocrypt-stub ##
While full implementation is underway, the stub library is provided for drivers to test integrating with libmongocrypt. The stub library has no external dependencies. Functions that do blocking I/O in libmongocrypt simply sleep for one second in libmongocrypt-stub.

```
git clone git@github.com:10gen/libmongocrypt.git
cd libmongocrypt
mkdir cmake-build && cd cmake-build
cmake ../
make mongocrypt-stub
```

## Building libmongocrypt ##
These instructions have only been tested on macOS 10.14.1 with OpenSSL 1.1.1a.

First build the following dependencies.

1. [The C driver](https://github.com/mongodb/mongo-c-driver), consisting of libmongoc and libbson.
   You can follow the [installation instructions on mongoc.org](http://mongoc.org/libmongoc/current/installing.html) or if you'd prefer installing in a custom directory, build from source.
   ```
   wget https://github.com/mongodb/mongo-c-driver/releases/download/1.13.1/mongo-c-driver-1.13.1.tar.gz
   tar xzf mongo-c-driver-1.13.1.tar.gz
   cd mongo-c-driver-1.13.1
   mkdir cmake-build && cd cmake-build
   cmake -DCMAKE_INSTALL_PATH="/path/to/c-install" ../
   make -j8 install
   ```
   This installs the library and includes into /path/to/c-install. The prefix can be omitted if you prefer installing in /usr/local.
2. [kms-message](https://github.com/10gen/kms-message), a small library for making encrypt and decrypt requests with AWS KMS.

   ```
   git clone git@github.com:10gen/kms-message.git
   cd kms-message
   mkdir cmake-build && cd cmake-build
   cmake -DCMAKE_INSTALL_PREFIX="/path/to/kms-install" ../
   make install
   ```
   This installs the library and includes into /path/to/kms-install. The prefix can be omitted if you prefer installing in /usr/local.
   
3. Install OpenSSL.

Then build libmongocrypt.

```
git clone git@github.com:10gen/libmongocrypt.git
cd libmongocrypt
mkdir cmake-build && cd cmake-build
cmake -DCMAKE_PREFIX_PATH="/path/to/c-install;/path/to/kms-install" ../
make
```

This builds libmongocrypt.dylib and test-libmongocrypt, in the cmake-build directory. Note, the CMAKE_PREFIX_PATH must include the paths to the kms-message and C driver installation directories if they were not the defaults.

### Troubleshooting ###
If OpenSSL is installed in a non-default directory, pass `-DOPENSSL_ROOT_DIR=/path/to/openssl` to the cmake command for libmongocrypt. 

If there are errors with cmake configuration, send the set of steps you performed and their output to Kevin Albertson.

If there are compilation or linker errors, reconfigure with `-DCMAKE_VERBOSE_MAKEFILE=ON` (which shows exact compile and link commands), run `make` again, and send the output to Kevin Albertson.