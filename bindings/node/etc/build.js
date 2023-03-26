'use strict';

const cp = require('child_process');
const pkg = require(__dirname + '/../package.json');

var argv = process.argv.slice(3); // strips ['node', 'build.js', subcommand]

var command;
switch (process.argv[2]) {
  case 'install':
    command = 'cmake-js';
    argv.unshift('compile');
    break;
  case 'prebuild':
    command = 'prebuild';
    argv.push('--backend', 'cmake-js', '--');
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
