# libmongocrypt #
The companion C library for client side encryption in drivers.

To integrate libmongocrypt with your driver, see the [Integrating libmongocrypt Guide](integrating.md).

## Building libmongocrypt ##

First build the following dependencies:

1. [The BSON library (part of the C driver)](https://github.com/mongodb/mongo-c-driver), consisting of libbson. Build it from source.
   ```
   wget https://github.com/mongodb/mongo-c-driver/releases/download/1.14.0/mongo-c-driver-1.14.0.tar.gz
   tar xzf mongo-c-driver-1.14.0.tar.gz
   cd mongo-c-driver-1.14.0
   mkdir cmake-build && cd cmake-build
   cmake -DENABLE_MONGOC=OFF -DCMAKE_INSTALL_PATH="/path/to/bson-install" -DCMAKE_C_FLAGS="-fPIC" ../
   make -j8 install
   ```
   This installs the library and includes into /path/to/bson-install. The prefix can be omitted if you prefer installing in /usr/local.
   
2. OpenSSL (if on Linux).

Then build libmongocrypt:

```
git clone git@github.com:10gen/libmongocrypt.git
cd libmongocrypt
mkdir cmake-build && cd cmake-build
cmake -DCMAKE_PREFIX_PATH="/path/to/bson-install" ../
make
```

This builds libmongocrypt.dylib and test-libmongocrypt, in the cmake-build directory. Note, the `CMAKE_PREFIX_PATH` must include the path to the BSON library installation directory if it was not the defaults.  Also note that if your project will also dynamically link to the BSON library, you will need to add `-DENABLE_SHARED_BSON=ON` to the `cmake` command line.

### Testing ###
`test-mongocrypt` mocks all I/O with files stored in the `test/data` and `test/example` directories. Run `test-mongocrypt` from the source directory:

```
cd libmongocrypt
./cmake-build/test-mongocrypt
```

libmongocrypt is [continuously built on evergreen](https://evergreen.mongodb.com/waterfall/libmongocrypt). Submit patch builds to this evergreen project when making changes to test on supported platforms.

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

#### Narrowly scoped ####
The first version of FLE is to get signal. If FLE becomes popular, further improvements will be made (removing mongocryptd process, support for more queries, better performance). libmongocrypt takes the same approach. Making it blazing fast and completely future-proof is not a high priority.
