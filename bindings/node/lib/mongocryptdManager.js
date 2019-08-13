'use strict';

const spawn = require('child_process').spawn;
const readFile = require('fs').readFile;

const mongocryptdPidFileName = 'mongocryptd.pid';
const checkIntervalMS = 50;

/**
 * @ignore
 * A heuristic check to see if a mongocryptd is running. Checks for a mongocryptd.pid
 * file that contains valid JSON. If the pid file exists, the mongocryptd is likely
 * running.
 * @param {} callback Invoked with true if a valid pid file is found, false otherwise
 */
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

/**
 * @ignore
 * Attempts to wait for a mongocryptd to be up. Will check with checkIsUp
 * in 50ms intervals up to tries times.
 * @param {number} tries The number of times to check for a mongocryptd
 * @param {Function} callback Is called when either the number of tries have been
 * attempted, or when we think a mongocryptd is up
 */
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

/**
 * @ignore
 * An internal class that handles spawning a mongocryptd.
 */
class MongocryptdManager {
  /**
   * @ignore
   * Creates a new Mongocryptd Manager
   * @param {AutoEncrypter~AutoEncryptionExtraOptions} [extraOptions] extra options that determine how/when to spawn a mongocryptd
   */
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

  /**
   * @ignore
   * Will check to see if a mongocryptd is up. If it is not up, it will attempt
   * to spawn a mongocryptd in a detached process, and then wait for it to be up.
   * @param {Function} callback Invoked when we think a mongocryptd is up
   */
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
