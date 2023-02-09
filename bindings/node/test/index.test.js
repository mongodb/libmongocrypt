'use strict';

const { expect } = require('chai');
const mongodbClientEncryption = require('../lib/index');

// Update this as you add exports, helps double check we don't accidentally remove something
// since not all tests import from the root public export
const EXPECTED_EXPORTS = [
  'extension',
  'MongoCryptError',
  'MongoCryptCreateEncryptedCollectionError',
  'MongoCryptCreateDataKeyError',
  'AutoEncrypter',
  'ClientEncryption'
];

describe('mongodb-client-encryption entrypoint', () => {
  it('should export all and only the expected keys in expected_exports', () => {
    expect(mongodbClientEncryption).to.have.keys(EXPECTED_EXPORTS);
  });
});
