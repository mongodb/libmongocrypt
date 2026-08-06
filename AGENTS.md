# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## What this is

libmongocrypt is a C library that assists MongoDB drivers in implementing **In-Use Encryption**. The driver-facing behavior it helps support is defined by the Client-Side Encryption specification: <https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/client-side-encryption.md>.

### Naming (from the spec)

The public feature is **In-Use Encryption**, consisting of **Client-Side Field Level Encryption (CSFLE)** and **Queryable Encryption (QE)**. Internally, In-Use Encryption is sometimes called **Field Level Encryption (FLE)**; CSFLE is sometimes called Client Side Encryption (as in the spec title); and CSFLE and QE are sometimes called **FLE1** and **FLE2** respectively. So the `mc-fle2-*` payload files under `src/` implement **Queryable Encryption**, not CSFLE.

Separately (and confusingly), **`csfle`** is sometimes used within libmongocrypt to mean the **crypt_shared** library — an older name for it, unrelated to the CSFLE feature above. For example, `crypt->csfle` is the crypt_shared vtable.

## Build System

This project uses CMake.

Use `cmake-build/` as the CMake binary directory unless otherwise specified by the user. When the user specifies a custom binary directory, always use that directory - do not fall back to `cmake-build/`.

> [!IMPORTANT]
> Despite `build/` being a common choice for a CMake binary directory name, that is not recommended in this repository because the `build/` directory is not ignored by Git.

The typical configure and build steps (for release and installation):

```bash
cmake -D CMAKE_BUILD_TYPE=RelWithDebInfo -B cmake-build
cmake --build cmake-build
```

The optional install step:

```bash
cmake --install cmake-build
```

> [!IMPORTANT]
> For multi-configuration generators (e.g. "Visual Studio *", "Ninja Multi-Config", etc.), use `--config <config>` during the build, install, and test steps instead of `CMAKE_BUILD_TYPE=<config>`.
> The `CMAKE_BUILD_TYPE` option will be ignored by the configuration step.
> Only use `CMAKE_BUILD_TYPE` with single-configuration generators (e.g. Makefile Generators, Ninja, etc.).

Key CMake configuration options (given `option=(default|alternatives...)`):

- `-G <generator-name>`: specify a build system generator (e.g. `Ninja`).
- `-D CMAKE_PREFIX_PATH:PATH=<prefix>`: installation prefixes to search with `find_*()` (e.g. an installed libbson with `USE_SHARED_LIBBSON=ON`, or OpenSSL).
- `-D CMAKE_INSTALL_PREFIX:PATH=<install-prefix>`: install directory used by `install()`. Use `cmake-build/install/` when system modification is undesirable or disallowed by the user.
- `-D CMAKE_BUILD_TYPE:STRING=<config>`: build type on single-configuration generators.
- `-D MONGOCRYPT_CRYPTO:STRING=(OpenSSL|CommonCrypto|CNG|none)`: crypto backend. Defaults to the platform native (OpenSSL on Linux, CommonCrypto on macOS, CNG on Windows).
- `-D DISABLE_NATIVE_CRYPTO:BOOL=(OFF|ON)`: shortcut for `MONGOCRYPT_CRYPTO=none` — build with no crypto backend; a driver then supplies crypto at runtime via `mongocrypt_setopt_crypto_hooks`.
- `-D OPENSSL_ROOT_DIR:PATH=<dir>`: OpenSSL location, if not on a default path.
- `-D USE_SHARED_LIBBSON:BOOL=(OFF|ON)`: link an installed libbson instead of the bundled static one.
- `-D ENABLE_STATIC:BOOL=(ON|OFF)`: build and install static libraries.
- `-D BUILD_TESTING:BOOL=(ON|OFF)`: required to enable test targets including `test-mongocrypt` (see [Running Tests](#running-tests)).
- `-D ENABLE_ONLINE_TESTS:BOOL=(ON|OFF)`: required to enable test targets requiring external servers and the `csfle` utility (requires libmongoc).

**Build performance:** Ninja parallelizes builds across all available cores by default; to cap the job count, set `CMAKE_BUILD_PARALLEL_LEVEL=<N>` in the environment before running `cmake --build`.

> [!NOTE]
> `.evergreen/build_all.sh` is the authoritative reference for CI configure-build-install routines. Consult for platform-specific options and flags.

> [!NOTE]
> For local development and testing, use the Debug configure in the [Running Tests](#running-tests) section instead of the release configure above.

## Dependencies

Dependencies are obtained in three different ways — most are fetched or vendored, so a network connection may be needed at configure time:

- **libbson** (BSON support): *fetched* at configure time by `cmake/FetchMongoC.cmake`, which downloads the mongo-c-driver source archive at a pinned tag and builds libbson, statically linked into libmongocrypt by default. See comments in `cmake/FetchMongoC.cmake` to bump the pinned tag. Set `-D USE_SHARED_LIBBSON=ON` to instead link an installed libbson found via `find_package(bson)` (set `CMAKE_PREFIX_PATH`). 
- **Intel DFP** (Decimal128 math; target `mongocrypt::intel_dfp`): built at configure time from a *vendored tarball* under `third-party/`. Enabled by `MONGOCRYPT_ENABLE_DECIMAL128` (default ON). Set `-D MONGOCRYPT_DFP_DIR=USE-SYSTEM` to instead use a system install.
- **kms-message** (KMS request/response): a separate subproject under `kms-message/`, statically compiled into libmongocrypt. The MongoDB C Driver also vendors kms-message.
- **Crypto backend**: OpenSSL / CommonCrypto / CNG, selected by `MONGOCRYPT_CRYPTO` (see above). On Linux the system OpenSSL is used by default; `DISABLE_NATIVE_CRYPTO=ON` removes the backend entirely.

## Running Tests

The typical configure and build steps (for testing and development):

```bash
cmake -D CMAKE_BUILD_TYPE=Debug -B cmake-build
cmake --build cmake-build
```

> [!TIP]
> For development, prefer the Ninja generator (`-G Ninja`) when available: it builds in parallel across all cores by default, for the fastest edit-build-test loop.

Test targets build by default (`BUILD_TESTING=ON`). The suite is a single executable, `test-mongocrypt`, at the top of the binary directory. Run it **from the source root** (it reads `test/data` and `test/example` via relative paths):

```bash
./cmake-build/test-mongocrypt                              # whole suite
./cmake-build/test-mongocrypt _test_setopt_kms_providers   # a single test, by function name
```

> [!IMPORTANT]
> For multi-configuration generators, the executable appears under a `<config>/` subdirectory (e.g. `cmake-build/Debug/test-mongocrypt`).

A few tests need a real crypt_shared library; download one with the `mongodl.py` script from drivers-evergreen-tools: <https://github.com/mongodb-labs/drivers-evergreen-tools/blob/master/.evergreen/mongodl.py>

```bash
python /path/to/mongodl.py --component crypt_shared <out-dir>
```

CI runs on Evergreen. Submit a patch build to test across supported platforms:

```bash
evergreen patch --project=libmongocrypt --auto-description --yes --finalize \
    --rv ".*" -t "build-and-test-and-upload"
```

### The kms-message subproject

`kms-message` is a self-contained subproject with its own tests, configured and built from its own directory:

```bash
cd kms-message
../cmake-build/kms-message/test_kms_request
```

## Adding a unit test

Tests are C files, not auto-discovered. Two steps are required:

1. Add the file to the `TEST_MONGOCRYPT_SOURCES` list in `CMakeLists.txt`.
2. In `test/test-mongocrypt.c`, add an `_mongocrypt_tester_install_*(&tester)` call in `main`, and register each test function inside that installer via `_mongocrypt_tester_install(tester, "_test_name", fn, CRYPTO_REQUIRED)` (or `CRYPTO_OPTIONAL`).

## Architecture

### Components

- Driver
    - libmongocrypt acts as a **state machine** and does no I/O.
    - libmongocrypt provides a C interface to drivers.
    - Most APIs pass and returns BSON, most structs are opaque, and global init is lazy.
    - See `integrating.md` and the public API in `src/mongocrypt.h`.
- MongoDB server (mongod / mongos)
    - To send the final commands.
    - To fetch remote schemas.
- KMS
    - To encrypt/decrypt Data Encryption Keys (DEK) using a backing Key Encryption Key (KEK).
- mongocryptd / crypt_shared
    - Required for automatic encryption only (not used by explicit encryption, explicit decryption, or automatic decryption)
    - Interchangeable: both do query analysis for automatic encryption.
        - mongocryptd is a process the driver talks to.
        - crypt_shared is a library libmongocrypt loads and calls directly.
    - Only permitted for enterprise or Atlas. This makes automatic encryption an enterprise / Atlas feature.

### Source layout & naming

`src/mongocrypt.h` is the only header consumers are expected to directly include. Any header that is not installed is private.

Public functions follow `mongocrypt_<type>_<method>` (e.g. `mongocrypt_ctx_id`). `mc_*` is a shorthand for internal components.

Other top-level areas: `kms-message/` (vendored KMS request/response library), `bindings/` (language bindings — currently only `python`/PyMongoCrypt, which is released separately from the C library), `etc/` (dev/release scripts), `.evergreen/` (CI), `doc/`.

### C standard

Uses C99. Contributions shall not use features from newer standards.

### Core objects & state machine

- **`mongocrypt_t`** — the top-level handle; **thread-safe**, and expected to be owned by a driver's `MongoClient` / `ClientEncryption` object.
- **`mongocrypt_ctx_t`** — a single operation (encrypt, decrypt, data-key creation, …); **not thread-safe**, and expected to handle one operation. The driver drives it as a state machine, performing the I/O the library requests at each state. See `integrating.md` for the state machine.
- **`mongocrypt_binary_t`** is a non-owning view; `_destroy` frees the view, not the underlying data.

## Before Committing

Format with `./etc/format-all.sh` (requires `uv`; see `CONTRIBUTING.md`). The `kms-message` subproject is not auto-formatted — leave its style as-is.

## Conventions

- SemVer. User-visible changes go in `CHANGELOG.md`.
- Bugs/features are tracked in the Jira **MONGOCRYPT** project; use `MONGOCRYPT-NNN <summary>` in PR titles.
- Develop test-first (red-green-refactor).
