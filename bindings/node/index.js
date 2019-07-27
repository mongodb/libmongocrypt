'use strict';

module.exports = function(mongodb) {
  const modules = { mongodb };

  modules.stateMachine = require('./lib/stateMachine')(modules);
  modules.autoEncrypter = require('./lib/autoEncrypter')(modules);
  modules.clientEncryption = require('./lib/clientEncryption')(modules);

  return {
    AutoEncrypter: modules.autoEncrypter.AutoEncrypter,
    ClientEncryption: modules.clientEncryption.ClientEncryption,
    MongoCryptError: require('./lib/common').MongoCryptError
  };
};
