# The guide to integrating libmongocrypt #

libmongocrypt is a C library meant to assist drivers in supporting
client side encryption. libmongocrypt acts as a state machine and the
driver is responsible for I/O between mongod, mongocryptd, and AWS KMS.

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
a first step binding to only mongocrypt\_version ([JNA example](https://github.com/10gen/libmongocrypt/blob/fbb9f59bf32019373232dc1a1fd85a00d6ab95de/bindings/java/mongocrypt/src/main/java/com/mongodb/crypt/capi/CAPI.java#L106-L113)).
Once you have that working, proceed to write bindings for the remaining
API. Here are a few things to keep in mind:

-   \"ctx\" is short for context, and is a generic term indicating that
    the object stores state.
-   By C convention, functions are named like:
    mongocrypt\_\<type\>\_\<method\>. For example mongocrypt\_ctx\_id
    can be thought of as a class method \"id\" on the class \"ctx\".
-   mongocrypt\_binary\_t is a non-owning view of data. Calling
    mongocrypt\_binary\_destroy frees the view, but does nothing to the
    underlying data. When a mongocrypt\_binary\_t is returned (e.g.
    mongocrypt\_ctx\_mongo\_op), the lifetime of the data is tied to the
    type that returned it (so the data returned will be freed when the
    mongocrypt\_ctx\_t) is freed.

Once you have full bindings for the API, it\'s time to do a sanity
check. The crux of libmongocrypt\'s API is the state machine represented
by mongocrypt\_ctx\_t. This state machine is exercised in the
[example-state-machine](https://github.com/10gen/libmongocrypt/blob/master/test/example-state-machine.c)
executable included with libmongocrypt. It uses mock responses from
mongod, mongocryptd, and AWS KMS. Reimplement the state machine loop
(\_run\_state\_machine) in example-state-machine with your binding.

Seek help in the slack channel \#drivers-fle.

## Part 2: Integrate into Driver ##

After you have a binding, integrate libmongocrypt in your driver to
support client side encryption.

See the [driver spec](https://docs.google.com/document/d/1yg4m_ptf5YtZdmNDNMcpcpsvrtnLF1xOPLx8D5BpAJw)
for a reference of the user-facing API. libmongocrypt is needed for:

-   Automatic encryption/decryption
-   Explicit encryption/decryption
-   KeyVault (explicit encryption/decryption + createDataKey)

It is recommended to start by integrating libmongocrypt to support
automatic encryption/decryption. Then reuse the implementation to
implement the KeyVault.

A MongoClient enabled with client side encryption MUST have one shared
mongocrypt\_t handle (important because keys + JSON Schemas are cached
in this handle). Each KeyVault also has its own mongocrypt\_t.

Any encryption or decryption operation is done by creating a
mongocrypt\_ctx\_t and initializing it for the appropriate operation.
mongocrypt\_ctx\_t is a state machine, and each state requires the
driver to perform some action. This may be performing I/O on one of the
following:

-   the encrypted MongoClient to which the operation is occurring (for
    auto encrypt).
-   the key vault MongoClient (which may be the same as the encrypted
    MongoClient).
-   AWS KMS (via a TLS socket).
-   the MongoClient to the local mongocryptd process.

### Initializing ###

There are five different types of mongocrypt\_ctx\_t\'s, distinguished
by how they are initialized:

-   auto encrypt (mongocrypt\_ctx\_encrypt\_init)
-   auto decrypt (mongocrypt\_ctx\_decrypt\_init)
-   explicit encrypt (mongocrypt\_ctx\_explicit\_encrypt\_init)
-   explicit decrypt (mongocrypt\_ctx\_explicit\_decrypt\_init)
-   create data key (mongocrypt\_ctx\_datakey\_init)

### State Machine ###

Below is a list of the various states a mongocrypt ctx can be in. For
each state, there is a description of what the driver is expected to do
to advance the state machine. Not all states will be entered for all
types of contexts. But one state machine runner can be used for all
types of contexts.

#### State: MONGOCRYPT\_CTX\_ERROR ####

**Driver needs to...**

Throw an exception based on the status from mongocrypt\_ctx\_status.

**Applies to...**

All contexts.

#### State: MONGOCRYPT\_CTX\_NOTHING\_TO\_DO ####

**Driver needs to...**

Proceed with the original input. I.e. if this is for automatic
encryption, there was nothing to encrypt. If this was for automatic
decryption, there was nothing to decrypt.

**Applies to...**

auto encrypt, auto decrypt

#### State: MONGOCRYPT\_CTX\_NEED\_MONGO\_COLLINFO ####

**libmongocrypt needs**...

A result from a listCollections cursor.

**Driver needs to...**

1.  Run listCollections on the encrypted MongoClient with the filter
    provided by mongocrypt\_ctx\_mongo\_op
2.  eturn the result (if any) with mongocrypt\_ctx\_mongo\_feed
3.  Call mongocrypt\_ctx\_mongo\_done

**Applies to...**

auto encrypt

#### State: MONGOCRYPT\_CTX\_NEED\_MONGO\_MARKINGS ####

**libmongocrypt needs**...

A reply from mongocryptd indicating which values in a command need to be
encrypted.

**Driver needs to...**

1.  Use db.runCommand to run the command provided by mongocrypt\_ctx\_mongo\_op
    on the MongoClient connected to mongocryptd.
2.  Feed the reply back with mongocrypt\_ctx\_mongo\_feed.
3.  Call mongocrypt\_ctx\_mongo\_done.

**Applies to...**

auto encrypt

#### State: MONGOCRYPT\_CTX\_NEED\_MONGO\_KEYS ####

**libmongocrypt needs**...

Documents from the key vault collection.

**Driver needs to...**

1.  Use MongoCollection.find on the MongoClient connected to the key
    vault client (which may be the same as the encrypted client). Use
    the filter provided by mongocrypt\_ctx\_mongo\_op.
2.  Feed all resulting documents back with repeated calls to
    mongocrypt\_ctx\_mongo\_feed.
3.  Call mongocrypt\_ctx\_mongo\_done.

**Applies to...**

All contexts except for create data key.

#### State: MONGOCRYPT\_CTX\_NEED\_KMS ####

**libmongocrypt needs**...

The responses from one or more HTTP messages to AWS KMS.

**Driver needs to...**

1.  Iterate all KMS requests using mongocrypt\_ctx\_next\_kms\_ctx.
    (Note, the driver MAY fan out all HTTP requests at the same time).
2.  For each context:

    a.  Create/reuse a TLS socket connected to the endpoint indicated by
        > mongocrypt\_kms\_ctx\_endpoint

    b.  Write the message from mongocrypt\_kms\_ctx\_message to the
        > socket.

    c.  Feed the reply back with mongocrypt\_kms\_ctx\_feed. Repeat
        > until mongocrypt\_kms\_ctx\_bytes\_needed returns 0.

3.  When done feeding all replies, call mongocrypt\_ctx\_kms\_done.

**Applies to...**

All contexts.

#### State: MONGOCRYPT\_CTX\_READY ####

**Driver needs to...**

Call mongocrypt\_ctx\_finalize to perform the encryption/decryption and
get the final result.

**Applies to...**

All contexts except for create data key.

#### State: MONGOCRYPT\_CTX\_DONE ####

**Driver needs to...**

Exit the state machine loop.

**Applies to...**

All contexts.

Seek help in the slack channel \#drivers-fle.
