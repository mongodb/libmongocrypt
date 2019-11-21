'use strict';

let defaultModule;
function loadDefaultModule() {
  if (!defaultModule) {
    defaultModule = extension(require('mongodb'));
  }

  return defaultModule;
}

const MongoCryptError = require('./lib/common').MongoCryptError;
function extension(mongodb) {
  const modules = { mongodb };

  modules.stateMachine = require('./lib/stateMachine')(modules);
  modules.autoEncrypter = require('./lib/autoEncrypter')(modules);
  modules.clientEncryption = require('./lib/clientEncryption')(modules);

  return {
    AutoEncrypter: modules.autoEncrypter.AutoEncrypter,
    ClientEncryption: modules.clientEncryption.ClientEncryption,
    MongoCryptError
  };
}

module.exports = {
  extension,
  MongoCryptError,
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
