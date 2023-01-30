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

class MongoCryptCreateDataKeyForEncryptedCollectionError extends MongoCryptError {
  constructor({ encryptedFields, errors }) {
    super('Unable to complete creating data keys');
    this.encryptedFields = encryptedFields;
    this.errors = errors;
  }

  get name() {
    return 'MongoCryptCreateDataKeyForEncryptedCollectionError';
  }
}

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
  MongoCryptCreateDataKeyForEncryptedCollectionError,
  MongoCryptCreateEncryptedCollectionError
};
