MongoDB Client Encryption
=========================

The Node.js wrapper for [`libmongocrypt`](../../README.md)

**Note** This library provides encryption functionality for the MongoDB Node.js driver but is **not intended** to be consumed by itself.  We reserve the 
right to make breaking changes that fall outside of semver for this package.

### Installation

You can install `mongodb-client-encryption` with the following:

```bash
npm install mongodb-client-encryption
```

### Development
#### Setup

Run the following command to build libmongocrypt and setup the node bindings for development:

```shell
bash ./etc/build-static.sh
```

#### Linting

We lint both the c++ bindings and the Typescript.

To lint the Typescript, you can run `npm run check:eslint -- --fix`.  To lint the c++, run `npm run clang-format`.

#### Testing

The unit tests require the binding to be built.  Run `npm run rebuild` to build the addon from the c++ source.  Then the tests can be run with `npm test`.

Note: changes to c++ source are not automatically re-compiled.  you need to rebuild the bindings after each change.
