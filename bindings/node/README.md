# MongoDB Client Encryption

The Node.js wrapper for [`libmongocrypt`](../../README.md)

**Note** This library provides encryption functionality for the MongoDB Node.js driver but is **not intended** to be consumed in isolation. The public API that uses the functionality in this library is available in the `mongodb` package. We reserve the right to make breaking changes to `mongodb-client-encryption` that fall outside of semver.

### MongoDB Node.js Driver Version Compatibility

Only the following version combinations with the [MongoDB Node.js Driver](https://github.com/mongodb/node-mongodb-native) are considered stable.

|               | `kerberos@1.x` | `kerberos@2.x` |
| ------------- | -------------- | -------------- |
| `mongodb@6.x` | N/A            | ✓              |
| `mongodb@5.x` | ✓              | ✓              |
| `mongodb@4.x` | ✓              | ✓              |
| `mongodb@3.x` | ✓              | N/A            |

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

To lint the Typescript, you can run `npm run check:eslint -- --fix`. To lint the c++, run `npm run clang-format`.

#### Testing

The unit tests require the binding to be built. Run `npm run rebuild` to build the addon from the c++ source. Then the tests can be run with `npm test`.

Note: changes to c++ source are not automatically re-compiled. One needs to rebuild the bindings after each change.
