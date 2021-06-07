'use strict';
const expect = require('chai').expect;
const tar = require('tar');
const cp = require('child_process');
const fs = require('fs');
const pkg = require('../package.json');

const packFile = `mongodb-client-encryption-${pkg.version}.tgz`;

const REQUIRED_FILES = [
  'package/LICENSE',
  'package/src/mongocrypt.cc',
  'package/binding.gyp',
  'package/src/mongocrypt.h',
  'package/lib/autoEncrypter.js',
  'package/lib/clientEncryption.js',
  'package/lib/common.js',
  'package/lib/cryptoCallbacks.js',
  'package/index.js',
  'package/lib/mongocryptdManager.js',
  'package/lib/stateMachine.js',
  'package/package.json',
  'package/CHANGELOG.md',
  'package/README.md',
  'package/index.d.ts',
  'package/build/Release/mongocrypt.node'
];

describe(`Release ${packFile}`, () => {
  let tarFileList;
  before(() => {
    cp.execSync('npm pack', { stdio: 'ignore' });
    tarFileList = [];
    tar.list({
      file: packFile,
      sync: true,
      onentry(entry) {
        tarFileList.push(entry.path);
      }
    });
  });

  after(() => {
    fs.unlinkSync(packFile);
    tarFileList = [];
  });

  for (const requiredFile of REQUIRED_FILES) {
    it(`should contain ${requiredFile}`, () => {
      expect(tarFileList).to.includes(requiredFile);
    });
  }

  it('should not have extraneous files', () => {
    expect(tarFileList.sort()).to.deep.equal(REQUIRED_FILES.sort());
  });
});
