'use strict';

let defaultModule;
function loadDefaultModule() {
  if (!defaultModule) {
    defaultModule = extension(require('mongodb'));
  }

  return defaultModule;
}

const {
  MongoCryptError,
  MongoCryptCreateEncryptedCollectionError,
  MongoCryptCreateDataKeyError
} = require('./errors');

function extension(mongodb) {
  const modules = { mongodb };

  modules.stateMachine = require('./stateMachine')(modules);
  modules.autoEncrypter = require('./autoEncrypter')(modules);
  modules.clientEncryption = require('./clientEncryption')(modules);

  return {
    AutoEncrypter: modules.autoEncrypter.AutoEncrypter,
    ClientEncryption: modules.clientEncryption.ClientEncryption,
    MongoCryptError,
    MongoCryptCreateEncryptedCollectionError,
    MongoCryptCreateDataKeyError
  };
}

module.exports = {
  extension,
  MongoCryptError,
  MongoCryptCreateEncryptedCollectionError,
  MongoCryptCreateDataKeyError,
  get AutoEncrypter() {
    const m = loadDefaultModule();
    delete module.exports.AutoEncrypter;
    module.exports.AutoEncrypter = m.AutoEncrypter;
    return m.AutoEncrypter;
  },
  get ClientEncryption() {
    const m = loadDefaultModule();
    delete module.exports.ClientEncryption;
    module.exports.ClientEncryption = m.ClientEncryption;
    return m.ClientEncryption;
  }
};
