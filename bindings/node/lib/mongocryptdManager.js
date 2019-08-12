'use strict';

const spawn = require('child_process').spawn;
const readFile = require('fs').readFile;

/**
 * @typedef AutoEncryptionExtraOptions
 * @prop {string} [mongocryptdURI] overrides the uri used to connect to mongocryptd
 * @prop {boolean} [mongocryptdBypassSpawn=false] if true, autoEncryption will not spawn a mongocryptd
 * @prop {string} [mongocryptdSpawnPath] the path to the mongocryptd executable
 * @prop {string[]} [mongocryptdSpawnArgs] command line arguments to pass to the mongocryptd executable
 */

const mongocryptdPidFileName = 'mongocryptd.pid';
const checkIntervalMS = 50;

function checkIsUp(callback) {
  readFile(mongocryptdPidFileName, 'utf8', (err, data) => {
    if (err) {
      return callback(undefined, false);
    }

    if (!data || !data.length) {
      return callback(undefined, false);
    }

    try {
      JSON.parse(data);
    } catch (e) {
      return callback(e, false);
    }

    callback(undefined, true);
  });
}

function waitForUp(tries, callback) {
  if (tries <= 0) {
    return callback();
  }

  checkIsUp((err, isUp) => {
    if (isUp) {
      return callback();
    }

    tries -= 1;
    setTimeout(() => waitForUp(tries, callback), checkIntervalMS);
  });
}

class MongocryptdManager {
  constructor(extraOptions) {
    extraOptions = extraOptions || {};

    // TODO: this is not actually supported by the spec, so we should clarify
    // with the spec or get rid of this
    if (extraOptions.mongocryptdURI) {
      this.uri = extraOptions.mongocryptdURI;
    } else {
      // TODO: eventually support connecting on Linux Socket for non-windows,
      // blocked by SERVER-41029
      this.uri = 'mongodb://localhost:27020/?serverSelectionTimeoutMS=1000';
    }

    this.bypassSpawn = !!extraOptions.mongocryptdBypassSpawn;

    this.spawPath = extraOptions.mongocryptdSpawnPath || '';
    this.spawnArgs = [];
    if (Array.isArray(extraOptions.mongocryptdSpawnArgs)) {
      this.spawnArgs.concat(extraOptions.mongocryptdSpawnArgs);
    }
    if (this.spawnArgs.indexOf('idleShutdownTimeoutSecs') < 0) {
      this.spawnArgs.concat(['--idleShutdownTimeoutSecs', '60']);
    }
  }

  spawn(callback) {
    checkIsUp((err, isUp) => {
      if (!err && isUp) {
        process.nextTick(callback);
        return;
      }

      const cmdName = this.spawnPath || 'mongocryptd';

      // Spawned with stdio: ignore and detatched:true
      // to ensure child can outlive parent.
      this._child = spawn(cmdName, this.spawnArgs, {
        stdio: 'ignore',
        detached: true
      });

      this._child.on('error', () => {});

      // unref child to remove handle from event loop
      this._child.unref();

      waitForUp(20, callback);
    });
  }
}

module.exports = { MongocryptdManager };
