# The guide to integrating libmongocrypt #

libmongocrypt is a C library meant to assist drivers in supporting
client side encryption. libmongocrypt acts as a state machine and the
driver is responsible for I/O between mongod, mongocryptd, and KMS.

There are two major parts to integrating libmongocrypt into your driver:

-   Writing a language-specific binding to libmongocrypt
-   Using the binding in your driver to support client side encryption

## Part 1: Writing a Language-Specific Binding ##

The binding is the glue between your driver\'s native language and
libmongocrypt.

The binding uses the native language\'s foreign function interface to C.
For example, Java can accomplish this with
[JNA](https://github.com/java-native-access/jna), CPython with
[extensions](https://docs.python.org/3/extending/extending.html),
NodeJS with [add-ons](https://nodejs.org/api/addons.html), etc.

The libmongocrypt library files (.so/.dll) are pre-built on its
[Evergreen project](https://evergreen.mongodb.com/waterfall/libmongocrypt). Click
the variant\'s \"built-and-test-and-upload\" tasks to download the
attached files.

libmongocrypt describes all API that needs to be called from your driver
in the main public header
[mongocrypt.h](https://github.com/10gen/libmongocrypt/blob/master/src/mongocrypt.h).

There are many types and functions in mongocrypt.h to bind. Consider as
a first step binding to only `mongocrypt_version` ([JNA example](https://github.com/10gen/libmongocrypt/blob/fbb9f59bf32019373232dc1a1fd85a00d6ab95de/bindings/java/mongocrypt/src/main/java/com/mongodb/crypt/capi/CAPI.java#L106-L113)).
Once you have that working, proceed to write bindings for the remaining
API. Here are a few things to keep in mind:

-   \"ctx\" is short for context, and is a generic term indicating that
    the object stores state.
-   By C convention, functions are named like:
    `mongocrypt_<type>_<method>`. For example `mongocrypt_ctx_id`
    can be thought of as a class method \"id\" on the class \"ctx\".
-   `mongocrypt_binary_t` is a non-owning view of data. Calling
    `mongocrypt_binary_destroy` frees the view, but does nothing to the
    underlying data. When a `mongocrypt_binary_t` is returned (e.g.
    `mongocrypt_ctx_mongo_op`), the lifetime of the data is tied to the
    type that returned it (so the data returned will be freed when the
    `mongocrypt_ctx_t`) is freed.

Once you have full bindings for the API, it\'s time to do a sanity
check. The crux of libmongocrypt\'s API is the state machine represented
by `mongocrypt_ctx_t`. This state machine is exercised in the
[example-state-machine](https://github.com/10gen/libmongocrypt/blob/master/test/example-state-machine.c)
executable included with libmongocrypt. It uses mock responses from
mongod, mongocryptd, and KMS. Reimplement the state machine loop
(`_run_state_machine`) in example-state-machine with your binding.

To debug, configure with the cmake option `-DENABLE_TRACE=ON`, and set the environment variable `MONGOCRYPT_TRACE=ON` to log the arguments to mongocrypt functions. Note, this is insecure and should only be used for debugging.

Seek help in the slack channel \#drivers-fle.

## Part 2: Integrate into Driver ##

After you have a binding, integrate libmongocrypt in your driver to
support client side encryption.

See the [driver spec](https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/client-side-encryption.rst)
for a reference of the user-facing API. libmongocrypt is needed for:

-   Automatic encryption/decryption
-   Explicit encryption/decryption
-   KeyVault (explicit encryption/decryption + createDataKey)

It is recommended to start by integrating libmongocrypt to support
automatic encryption/decryption. Then reuse the implementation to
implement the KeyVault.

A MongoClient enabled with client side encryption MUST have one shared
`mongocrypt_t` handle (important because keys + JSON Schemas are cached
in this handle). Each KeyVault also has its own `mongocrypt_t`.

Any encryption or decryption operation is done by creating a
`mongocrypt_ctx_t` and initializing it for the appropriate operation.
`mongocrypt_ctx_t` is a state machine, and each state requires the
driver to perform some action. This may be performing I/O on one of the
following:

-   the encrypted MongoClient to which the operation is occurring (for
    auto encrypt).
-   the key vault MongoClient (which may be the same as the encrypted
    MongoClient).
-   KMS (via a TLS socket).
-   the MongoClient to the local mongocryptd process.

### Initializing ###

There are five different types of `mongocrypt_ctx_t`\'s, distinguished
by how they are initialized:

-   auto encrypt (`mongocrypt_ctx_encrypt_init`)
-   auto decrypt (`mongocrypt_ctx_decrypt_init`)
-   explicit encrypt (`mongocrypt_ctx_explicit_encrypt_init`)
-   explicit decrypt (`mongocrypt_ctx_explicit_decrypt_init`)
-   create data key (`mongocrypt_ctx_datakey_init`)

### State Machine ###

Below is a list of the various states a mongocrypt ctx can be in. For
each state, there is a description of what the driver is expected to do
to advance the state machine. Not all states will be entered for all
types of contexts. But one state machine runner can be used for all
types of contexts.

#### State: `MONGOCRYPT_CTX_ERROR` ####

**Driver needs to...**

Throw an exception based on the status from `mongocrypt_ctx_status`.

**Applies to...**

All contexts.

#### State: `MONGOCRYPT_CTX_NEED_MONGO_COLLINFO` ####

**libmongocrypt needs**...

A result from a listCollections cursor.

**Driver needs to...**

1.  Run listCollections on the encrypted MongoClient with the filter
    provided by `mongocrypt_ctx_mongo_op`
2.  Return the first result (if any) with `mongocrypt_ctx_mongo_feed` or proceed to the next step if nothing was returned.
3.  Call `mongocrypt_ctx_mongo_done`

**Applies to...**

auto encrypt

#### State: `MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB` ####

**libmongocrypt needs**...

Results from a listCollections cursor from a specified database.

**Driver needs to...**

1.  Run listCollections on the encrypted MongoClient with the filter
    provided by `mongocrypt_ctx_mongo_op` on the database provided by `mongocrypt_ctx_mongo_db`.
2.  Return the first result (if any) with `mongocrypt_ctx_mongo_feed` or proceed to the next step if nothing was returned.
3.  Call `mongocrypt_ctx_mongo_done`

**Applies to...**

A context initialized with `mongocrypt_ctx_encrypt_init` for automatic encryption. This state is only entered when `mongocrypt_setopt_use_need_mongo_collinfo_with_db_state` is called to opt-in.

#### State: `MONGOCRYPT_CTX_NEED_MONGO_MARKINGS` ####

**libmongocrypt needs**...

A reply from mongocryptd indicating which values in a command need to be
encrypted.

**Driver needs to...**

1.  Use db.runCommand to run the command provided by `mongocrypt_ctx_mongo_op`
    on the MongoClient connected to mongocryptd.
2.  Feed the reply back with `mongocrypt_ctx_mongo_feed`.
3.  Call `mongocrypt_ctx_mongo_done`.

**Applies to...**

auto encrypt

#### State: `MONGOCRYPT_CTX_NEED_MONGO_KEYS` ####

**libmongocrypt needs**...

Documents from the key vault collection.

**Driver needs to...**

1.  Use MongoCollection.find on the MongoClient connected to the key
    vault client (which may be the same as the encrypted client). Use
    the filter provided by `mongocrypt_ctx_mongo_op`.
2.  Feed all resulting documents back (if any) with repeated calls to
    `mongocrypt_ctx_mongo_feed`.
3.  Call `mongocrypt_ctx_mongo_done`.

**Applies to...**

All contexts except for create data key.

#### State: `MONGOCRYPT_CTX_NEED_KMS` ####

**libmongocrypt needs**...

The responses from one or more HTTP messages to KMS.

**Driver needs to...**

1.  Iterate all KMS requests using `mongocrypt_ctx_next_kms_ctx`.
    (Note, the driver MAY fan out all HTTP requests at the same time).
2.  For each context:

    a.  Create/reuse a TLS socket connected to the endpoint indicated by
        `mongocrypt_kms_ctx_endpoint`. The endpoint string is a host name with
        a port number separated by a colon. E.g.
        "kms.us-east-1.amazonaws.com:443". A port number will always be
        included. Drivers may assume the host name is not an IP address or IP
        literal.

    b.  Write the message from `mongocrypt_kms_ctx_message` to the
        > socket.

    c.  Feed the reply back with `mongocrypt_kms_ctx_feed`. Repeat
        > until `mongocrypt_kms_ctx_bytes_needed` returns 0.

3.  When done feeding all replies, call `mongocrypt_ctx_kms_done`.

**Applies to...**

All contexts.

#### State: `MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` ####

`MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` was added in libmongocrypt 1.4.0 as part of [MONGOCRYPT-382](https://jira.mongodb.org/browse/MONGOCRYPT-382).

`MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` can only be entered if `mongocrypt_setopt_use_need_kms_credentials_state` is called. This prevents breaking drivers that do not handle the `MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` state.

If a KMS provider is configured with an empty document (e.g. `{ "aws": {} }`), the `MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS` is entered before KMS requests are made.

**libmongocrypt needs**...

Credentials for one or more KMS providers.

**Driver needs to...**

Fetch credentials for supported KMS providers. See the [Client Side Encryption specification](https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/client-side-encryption.rst#automatic-credentials) for details.

Pass credentials to libmongocrypt using `mongocrypt_ctx_provide_kms_providers`.

**Applies to...**

All contexts.

#### State: `MONGOCRYPT_CTX_READY` ####

**Driver needs to...**

Call `mongocrypt_ctx_finalize` to perform the encryption/decryption and
get the final result.

**Applies to...**

All contexts except for create data key.

#### State: `MONGOCRYPT_CTX_DONE` ####

**Driver needs to...**

Exit the state machine loop.

**Applies to...**

All contexts.

Seek help in the slack channel \#drivers-fle.
