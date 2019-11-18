'use strict';

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
let _module;
function loadModule() {
  if (!_module) {
    _module = extension(require('mongodb'));
  }

  return _module;
}

function memo(fn) {
  let value;
  return () => value || (value = fn());
}

exports.extension = extension;
exports.MongoCryptError = MongoCryptError;
Object.defineProperty(exports, 'AutoEncrypter', {
  enumerable: true,
  get: memo(() => loadModule().AutoEncrypter)
});
Object.defineProperty(exports, 'ClientEncryption', {
  enumerable: true,
  get: memo(() => loadModule().ClientEncryption)
});
