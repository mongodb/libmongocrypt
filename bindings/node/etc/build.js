'use strict';

const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const pkg = require(__dirname + '/../package.json');

function copyRecursiveSync(src, dst) {
  var exists = fs.existsSync(src);
  var stats = exists && fs.statSync(src);
  if (exists && stats.isDirectory()) {
    fs.mkdirSync(dst);
    fs.readdirSync(src).forEach(item => {
      copyRecursiveSync(path.join(src, item), path.join(dst, item));
    });
  } else {
    fs.copyFileSync(src, dst);
  }
}

const vendorSourceDir = path.join(__dirname, '/../addon/mongocrypt');
const links = ['CMakeLists.txt', 'cmake', 'etc', 'kms-message', 'src', 'third-party'];

var argv = process.argv.slice(3); // strips ['node', 'build.js', subcommand]

var command;
switch (process.argv[2]) {
  case 'preinstall':
    if (!fs.existsSync(vendorSourceDir)) {
      fs.mkdirSync(vendorSourceDir);
      links.forEach(item => {
        fs.symlinkSync(path.join('../../../../', item), path.join(vendorSourceDir, item));
      });
    }
    process.exit(0);
    break;
  case 'install':
    command = 'cmake-js';
    argv.unshift('compile');
    break;
  case 'prebuild':
    command = 'prebuild';
    argv.push('--backend', 'cmake-js', '--');
    break;
  case 'prepack':
    var exists = fs.existsSync(vendorSourceDir);
    var stats = exists && fs.statSync(vendorSourceDir);
    if (exists && stats.isDirectory()) {
      fs.rmdirSync(vendorSourceDir, { recursive: true });
    }
    fs.mkdirSync(vendorSourceDir);
    links.forEach(item => {
      copyRecursiveSync(path.join('../../', item), path.join(vendorSourceDir, item));
    });
    fs.rmdirSync(path.join(vendorSourceDir, 'kms-message/aws-sig-v4-test-suite'), {
      recursive: true
    });
    fs.rmdirSync(path.join(vendorSourceDir, 'kms-message/test'), { recursive: true });
    process.exit(0);
    break;
  case 'postpack':
    fs.rmdirSync(vendorSourceDir, { recursive: true });
    fs.mkdirSync(vendorSourceDir);
    links.forEach(item => {
      fs.symlinkSync(path.join('../../../../', item), path.join(vendorSourceDir, item));
    });
    process.exit(0);
    break;
  default:
    throw new Error('unknown command ' + process.argv[2]);
}

argv.push(`--CDBUILD_VERSION=${pkg.version}`);
argv.push(`--CDMONGOCRYPT_DEPS=${process.env.npm_config_mongocrypt_deps ?? ''}`);
if (process.env.npm_config_mongocrypt_depdir ?? false) {
  argv.push(`--CDMONGOCRYPT_MONGOC_DIR=${process.env.npm_config_mongocrypt_depdir}`);
}

var gyp = cp.spawn(command, argv, { stdio: 'inherit' });
gyp.on('exit', function (code, signal) {
  if (code !== 0) {
    process.exit(code);
  }
  if (signal) {
    process.exit(signal);
  }
});
