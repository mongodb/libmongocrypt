'use strict';

/**
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

/** @class */
class MongoCryptInvalidArgumentError extends MongoCryptError {
  constructor(message) {
    super(message);
  }

  get name() {
    return 'MongoCryptInvalidArgumentError';
  }
}

/** @class */
class MongoCryptCreateDataKeyError extends MongoCryptError {
  constructor({ encryptedFields, cause }) {
    super('Unable to complete creating data keys', { cause });
    this.encryptedFields = encryptedFields;
  }

  get name() {
    return 'MongoCryptCreateDataKeyError';
  }
}

/** @class */
class MongoCryptCreateEncryptedCollectionError extends MongoCryptError {
  constructor({ encryptedFields, cause }) {
    super('Unable to create collection', { cause });
    this.encryptedFields = encryptedFields;
  }

  get name() {
    return 'MongoCryptCreateEncryptedCollectionError';
  }
}

module.exports = {
  MongoCryptError,
  MongoCryptInvalidArgumentError,
  MongoCryptCreateDataKeyError,
  MongoCryptCreateEncryptedCollectionError
};
