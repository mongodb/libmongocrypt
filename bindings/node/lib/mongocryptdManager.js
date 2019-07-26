'use strict';

/**
 * @typedef AutoEncryptionExtraOptions
 * @prop {string} [mongocryptdURI] overrides the uri used to connect to mongocryptd
 * @prop {boolean} [mongocryptdBypassSpawn=false] if true, autoEncryption will not spawn a mongocryptd
 * @prop {string} [mongocryptdSpawnPath] the path to the mongocryptd executable
 * @prop {string[]} [mongocryptdURI] command line arguments to pass to the mongocryptd executable
 */

module.exports = function() {
  const platform = require('os').platform;

  class MongocryptdManager {
    constructor(extraOptions) {
      extraOptions = extraOptions || {};

      // TODO: this is not actually supported by the spec, so we should clarify
      // with the spec or get rid of this
      if (extraOptions.mongocryptdURI) {
        this.uri = extraOptions.mongocryptdURI;
      } else if (platform() === 'win32') {
        this.uri = 'mongodb://localhost:27020/?serverSelectionTimeoutMS=1000';
      } else {
        this.uri = 'mongodb://%2Ftmp%2Fmongocryptd.sock/?serverSelectionTimeoutMS=1000';
      }

      this.spawPath = extraOptions.mongocryptdSpawnPath || '';
      this.spawnArgs = [];
      if (Array.isArray(extraOptions.mongocryptdSpawnArgs)) {
        this.spawnArgs.concat(extraOptions.mongocryptdSpawnArgs);
      }
      if (this.spawnArgs.indexOf('idleShutdownTimeoutSecs') < 0) {
        this.spawnArgs.concat(['--idleShutdownTimeoutSecs', '60']);
      }
    }
  }

  return { MongocryptdManager };
};
