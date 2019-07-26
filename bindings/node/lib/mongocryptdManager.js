'use strict';

const spawn = require('child_process').spawn;
const readFile = require('fs').readFile;

/**
 * @typedef AutoEncryptionExtraOptions
 * @prop {string} [mongocryptdURI] overrides the uri used to connect to mongocryptd
 * @prop {boolean} [mongocryptdBypassSpawn=false] if true, autoEncryption will not spawn a mongocryptd
 * @prop {string} [mongocryptdSpawnPath] the path to the mongocryptd executable
 * @prop {string[]} [mongocryptdURI] command line arguments to pass to the mongocryptd executable
 */

module.exports = function() {
  const platform = require('os').platform;

  const MONGOCRYPTD_PID_FILE = 'mongocryptd.pid';
  const STATE = {
    NO_PID_FILE: Symbol('NO_PID_FILE'),
    EMPTY_PID_FILE: Symbol('EMPTY_PID_FILE'),
    VALID_PID_FILE: Symbol('VALID_PID_FILE')
  };

  const checkIntervalMS = 100;

  function checkPidFile(callback) {
    readFile(MONGOCRYPTD_PID_FILE, 'utf8', (err, data) => {
      if (err) {
        return callback(undefined, STATE.NO_PID_FILE);
      }

      if (!data || !data.length) {
        return callback(undefined, STATE.EMPTY_PID_FILE);
      }

      try {
        JSON.parse(data);
      } catch (e) {
        return callback(e);
      }

      callback(undefined, STATE.VALID_PID_FILE);
    });
  }

  function waitForPidFile(up, tries, callback) {
    if (tries <= 0) {
      return callback();
    }

    checkPidFile((err, state) => {
      console.log(
        `[waitForPidFile](${up ? 'up' : 'down'}, ${tries}): ${state && state.toString()}`
      );
      if ((state === STATE.VALID_PID_FILE) === up) {
        return callback();
      }

      tries -= 1;
      setTimeout(() => waitForPidFile(up, tries, callback), checkIntervalMS);
    });
  }

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

    kill(callback) {
      if (this._child) {
        this._child.kill();
        this._child.removeAllListeners('error');
        this._child.removeAllListeners('exit');
        this._child = undefined;
      }
      if (callback) {
        waitForPidFile(false, 3, callback);
      }
    }

    spawn(callback) {
      this.kill(() => {
        const cmdName = this.spawnPath || 'mongocryptd';

        this._child = spawn(cmdName, this.spawnArgs, {
          stdio: ['ignore', 'ignore', 'ignore']
        })
          .once('error', () => this.kill())
          .once('exit', () => this.kill());

        waitForPidFile(true, 3, callback);
      });
    }
  }

  return { MongocryptdManager };
};
