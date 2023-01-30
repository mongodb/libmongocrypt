'use strict';

/**
 * @class
 * An error indicating that something went wrong specifically with MongoDB Client Encryption
 */
class MongoCryptError extends Error {
  constructor(message, options = {}) {
    super(message);
    if (options.cause instanceof Error) {
      this.cause = options.cause;
    }
  }

  get name() {
    return 'MongoCryptError';
  }
}

class MongoCryptCreateDataKeyForEncryptedCollectionError extends MongoCryptError {
  constructor(message, { encryptedFields, errors }) {
    super(message);
    this.encryptedFields = encryptedFields;
    this.errors = errors;
  }

  get name() {
    return 'MongoCryptCreateDataKeyForEncryptedCollectionError';
  }
}

class MongoCryptCreateEncryptedCollectionError extends MongoCryptError {
  constructor(message, { encryptedFields, cause }) {
    super(message, { cause });
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
