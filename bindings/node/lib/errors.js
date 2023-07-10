'use strict';

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 * @class
 * An error indicating that something went wrong specifically with MongoDB Client Encryption
 */
class MongoCryptError extends Error {
  constructor(message, options = {}) {
    super(message);
    if (options.cause != null) {
      this.cause = options.cause;
    }
  }

  get name() {
    return 'MongoCryptError';
  }
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 * @class
 * An error indicating that `ClientEncryption.createEncryptedCollection()` failed to create data keys
 */
class MongoCryptCreateDataKeyError extends MongoCryptError {
  constructor({ encryptedFields, cause }) {
    super(`Unable to complete creating data keys: ${cause.message}`, { cause });
    this.encryptedFields = encryptedFields;
  }

  get name() {
    return 'MongoCryptCreateDataKeyError';
  }
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 * @class
 * An error indicating that `ClientEncryption.createEncryptedCollection()` failed to create a collection
 */
class MongoCryptCreateEncryptedCollectionError extends MongoCryptError {
  constructor({ encryptedFields, cause }) {
    super(`Unable to create collection: ${cause.message}`, { cause });
    this.encryptedFields = encryptedFields;
  }

  get name() {
    return 'MongoCryptCreateEncryptedCollectionError';
  }
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 * @class
 * An error indicating that mongodb-client-encryption failed to auto-refresh Azure KMS credentials.
 */
class MongoCryptAzureKMSRequestError extends MongoCryptError {
  /**
   * @param {string} message
   * @param {object | undefined} body
   */
  constructor(message, body) {
    super(message);
    this.body = body;
  }
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 */
class MongoCryptKMSRequestNetworkTimeoutError extends MongoCryptError {}

module.exports = {
  MongoCryptError,
  MongoCryptKMSRequestNetworkTimeoutError,
  MongoCryptAzureKMSRequestError,
  MongoCryptCreateDataKeyError,
  MongoCryptCreateEncryptedCollectionError
};
