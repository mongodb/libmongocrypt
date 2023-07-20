MongoDB Client Encryption
=========================

The Node.js wrapper for [`libmongocrypt`](../../README.md)

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

Some tests require a standalone server to be running with authentication enabled.  Set up a single
server running with the following conditions:

| param     | value     |
|-----------|-----------|
| host      | localhost |
| port      | 27017     |

This is the standard setup for a standalone server with no authentication.

Run the test suite using:

```bash
npm test
```
