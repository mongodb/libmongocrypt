'use strict';
const crypto = require('crypto');

function aes256CbcEncryptHook(key, iv, input, output) {
  let result;

  try {
    let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    result = cipher.update(input);
  } catch (e) {
    console.dir({ e });
  }

  result.copy(output);
  return result.length;
}

function aes256CbcDecryptHook(key, iv, input, output) {
  let result;
  try {
    let cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    result = cipher.update(input);
  } catch (e) {
    console.dir({ e });
  }

  result.copy(output);
  return result.length;
}

function randomHook(buffer, count) {
  crypto.randomFillSync(buffer, count);
}

function sha256Hook(input, output) {
  let result;
  try {
    result = crypto
      .createHash('sha256')
      .update(input)
      .digest();
  } catch (e) {
    console.dir({ e });
  }

  result.copy(output);
}

function makeHmacHook(algorithm) {
  return (key, input, output) => {
    let result;
    try {
      result = crypto
        .createHmac(algorithm, key)
        .update(input)
        .digest();
    } catch (e) {
      console.dir({ e });
    }

    result.copy(output);
  };
}

module.exports = {
  aes256CbcEncryptHook,
  aes256CbcDecryptHook,
  randomHook,
  hmacSha512Hook: makeHmacHook('sha512'),
  hmacSha256Hook: makeHmacHook('sha256'),
  sha256Hook
};
