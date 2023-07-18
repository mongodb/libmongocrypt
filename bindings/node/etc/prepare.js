#! /usr/bin/env node
var cp = require('child_process');
var fs = require('fs');
var os = require('os');

if (fs.existsSync('src')) {
  cp.spawn('npm', ['run', 'build:ts'], { stdio: 'inherit', shell: os.platform() === 'win32' });
} else {
  if (!fs.existsSync('lib')) {
    console.warn('MongoDB: No compiled javascript present, the driver is not installed correctly.');
  }
}
