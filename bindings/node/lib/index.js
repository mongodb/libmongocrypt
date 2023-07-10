'use strict';

const mc = require('bindings')('mongocrypt');
module.exports = {
  MongoCrypt: mc.MongoCrypt
};
