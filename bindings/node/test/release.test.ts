import { expect } from 'chai';
import * as tar from 'tar';
import * as cp from 'child_process';
import * as fs from 'fs';

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
const packFile = `mongodb-client-encryption-${pkg.version}.tgz`;

const REQUIRED_FILES = [
  'package/LICENSE',
  'package/addon/mongocrypt.cc',
  'package/binding.gyp',
  'package/addon/mongocrypt.h',
  'package/lib/index.js',
  'package/package.json',
  'package/lib/index.d.ts.map',
  'package/lib/index.js.map',
  'package/CHANGELOG.md',
  'package/README.md',
  'package/lib/index.d.ts',
  'package/src/index.ts'
];

describe(`Release ${packFile}`, function () {
  this.timeout(10000);

  let tarFileList;
  before(() => {
    expect(fs.existsSync(packFile)).to.equal(false);
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
  });

  for (const requiredFile of REQUIRED_FILES) {
    it(`should contain ${requiredFile}`, () => {
      expect(tarFileList).to.includes(requiredFile);
    });
  }

  it('should not have extraneous files', () => {
    const unexpectedFileList = tarFileList.filter(f => !REQUIRED_FILES.some(r => r === f));
    expect(unexpectedFileList).to.have.lengthOf(0, `Extra files: ${unexpectedFileList.join(', ')}`);
  });
});
