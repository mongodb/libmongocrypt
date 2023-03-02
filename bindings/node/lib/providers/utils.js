'use strict';

const { MongoCryptNetworkTimeoutError } = require('../errors');
const http = require('http');

/**
 * @param {URL | string} url
 * @param {http.RequestOptions} options
 *
 * @returns { Promise<{ body: string, status: number }> }
 */
function get(url, options = {}) {
  return new Promise((resolve, reject) => {
    let timeoutId;
    const request = http
      .get(url, options, response => {
        response.setEncoding('utf8');
        let body = '';
        response.on('data', chunk => (body += chunk));
        response.on('end', () => {
          clearTimeout(timeoutId);
          resolve({ status: response.statusCode, body });
        });
      })
      .on('error', error => reject(error))
      .end();
    timeoutId = setTimeout(() => {
      request.destroy(new MongoCryptNetworkTimeoutError(`request timed out after 10 seconds`));
    }, 10000);
  });
}

module.exports = { get };
