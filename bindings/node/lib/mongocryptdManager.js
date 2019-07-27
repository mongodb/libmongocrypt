'use strict';

const spawn = require('child_process').spawn;
const readFile = require('fs').readFile;
const platform = require('os').platform;

/**
 * @typedef AutoEncryptionExtraOptions
 * @prop {string} [mongocryptdURI] overrides the uri used to connect to mongocryptd
 * @prop {boolean} [mongocryptdBypassSpawn=false] if true, autoEncryption will not spawn a mongocryptd
 * @prop {string} [mongocryptdSpawnPath] the path to the mongocryptd executable
 * @prop {string[]} [mongocryptdURI] command line arguments to pass to the mongocryptd executable
 */

const mongocryptdPidFileName = 'mongocryptd.pid';
const pidFileStates = {
  noPidFile: Symbol('noPidFile'),
  emptyPidFile: Symbol('emptyPidFile'),
  validPidFile: Symbol('validPidFile')
};

const checkIntervalMS = 50;

function checkPidFile(callback) {
  readFile(mongocryptdPidFileName, 'utf8', (err, data) => {
    if (err) {
      return callback(undefined, pidFileStates.noPidFile);
    }

    if (!data || !data.length) {
      return callback(undefined, pidFileStates.emptyPidFile);
    }

    try {
      JSON.parse(data);
    } catch (e) {
      return callback(e);
    }

    callback(undefined, pidFileStates.validPidFile);
  });
}

function waitForPidFile(up, tries, callback) {
  if (tries <= 0) {
    return callback();
  }

  checkPidFile((err, state) => {
    if ((state === pidFileStates.validPidFile) === up) {
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

  kill(callback) {
    if (this.bypassSpawn) {
      process.nextTick(callback);
      return;
    }
    this._kill(callback);
  }

  _kill(callback) {
    if (this._child) {
      this._child.kill();
      this._child.removeAllListeners('error');
      this._child.removeAllListeners('exit');
      this._child = undefined;
    }
    if (callback) {
      waitForPidFile(false, 20, callback);
    }
  }

  spawn(callback) {
    if (this.bypassSpawn) {
      process.nextTick(callback);
      return;
    }
    this._spawn(callback);
  }

  _spawn(callback) {
    this.kill(() => {
      const cmdName = this.spawnPath || 'mongocryptd';

      this._child = spawn(cmdName, this.spawnArgs, {
        stdio: ['ignore', 'ignore', 'ignore']
      })
        .once('error', () => this.kill())
        .once('exit', () => this.kill());

      waitForPidFile(true, 20, callback);
    });
  }
}

module.exports = { MongocryptdManager };
