'use strict';

const MongocryptdManager = require('../lib/mongocryptdManager').MongocryptdManager;
const expect = require('chai').expect;

describe('MongocryptdManager', function() {
  it('should default to having spawnArgs of --idleShutdownTimeoutSecs=60', function() {
    const mcdm = new MongocryptdManager();

    expect(mcdm.spawnArgs).to.deep.equal(['--idleShutdownTimeoutSecs', 60]);
  });

  it('should concat --idleShutdownTimeoutSecs=60 to provided args', function() {
    const mcdm = new MongocryptdManager({ mongocryptdSpawnArgs: ['foo', 12] });

    expect(mcdm.spawnArgs).to.deep.equal(['foo', 12, '--idleShutdownTimeoutSecs', 60]);
  });

  it('should not override `idleShutdownTimeoutSecs` if the user sets it using `key value` form', function() {
    const mcdm = new MongocryptdManager({
      mongocryptdSpawnArgs: ['--idleShutdownTimeoutSecs', 12]
    });

    expect(mcdm.spawnArgs).to.deep.equal(['--idleShutdownTimeoutSecs', 12]);
  });

  it('should not override `idleShutdownTimeoutSecs` if the user sets it using `key=value` form', function() {
    const mcdm = new MongocryptdManager({
      mongocryptdSpawnArgs: ['--idleShutdownTimeoutSecs=12']
    });

    expect(mcdm.spawnArgs).to.deep.equal(['--idleShutdownTimeoutSecs=12']);
  });
});
