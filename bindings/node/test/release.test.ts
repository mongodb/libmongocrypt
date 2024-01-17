import { expect } from 'chai';
import * as tar from 'tar';
import * as cp from 'child_process';
import * as fs from 'fs';
const path = require('path');

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
const packFile = `mongodb-client-encryption-${pkg.version}.tgz`;

const REQUIRED_FILES = [
  'package/LICENSE',
  'package/addon/mongocrypt.cc',
  'package/addon/mongocrypt.h',
  'package/etc/build.js',
  'package/etc/build-static.sh',
  'package/etc/prepare.js',
  'package/CMakeLists.txt',
  'package/lib/index.js',
  'package/package.json',
  'package/lib/index.d.ts.map',
  'package/lib/index.js.map',
  'package/CHANGELOG.md',
  'package/README.md',
  'package/lib/index.d.ts',
  'package/src/index.ts'
];

function readdirRecursiveSync(dir) {
  let res = [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(item => {
    const f = path.join(dir, item.name);
    if (item.isDirectory()) {
      res = [...res, ...readdirRecursiveSync(f).map(i => path.join(item.name, i))];
    } else if (item.isSymbolicLink()) {
      if (fs.statSync(f).isDirectory()) {
        res = [...res, ...readdirRecursiveSync(f).map(i => path.join(item.name, i))];
      } else {
        res.push(item.name);
      }
    } else {
      res.push(item.name);
    }
  });
  return res;
}

describe(`Release ${packFile}`, function () {
  this.timeout(10000);

  // This list is separate from `REQUIRED_FILES` due to its length, which is in the hundreds.
  const vendoredSourceFileList = readdirRecursiveSync(path.join(__dirname, '../addon/mongocrypt'))
    .filter(f => !(f.includes('/test/') || f.includes('/aws-sig-v4-test-suite/')))
    .map(f => path.join('package/addon/mongocrypt', f))
    .sort();
  expect(vendoredSourceFileList).to.not.have.lengthOf(0, "Empty vendored sources");

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

  for (const vendored of vendoredSourceFileList) {
    it(`should contain ${vendored}`, () => {
      expect(tarFileList).to.includes(vendored);
    });
  }

  it('should not have extraneous files', () => {
    const requiredFileList = REQUIRED_FILES.concat(vendoredSourceFileList);
    const unexpectedFileList = tarFileList.filter(f => !requiredFileList.some(r => r === f));
    expect(unexpectedFileList).to.have.lengthOf(0, `Extra files: ${unexpectedFileList.join(', ')}`);
  });
});
